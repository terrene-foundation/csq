//! Grok CLI (xAI) translator (native-CLI Wave 3 surface).
//!
//! Maps a `CocSet` to a `GrokSpawnPayload`. The capability layer's spawn
//! step (a follow-on shard — see `csq/src/cli/commands/run.rs`
//! `launch_native`) writes `agents_md` to `$GROK_HOME/AGENTS.md` and the
//! remaining fields into `$GROK_HOME/config.toml` + `$GROK_HOME/
//! settings.json`, and applies `sandbox_profile` / `permission_mode` /
//! `json_schema` as argv flags.
//!
//! Evidence base: `internal-design-docs
//! harness-decomposition.md`. Headline finding: Grok reads `.claude/`
//! natively and near-completely with zero setup — csq's job is to stop
//! routing Grok through the Codex translator (which writes a
//! `~/.codex/config.toml` key Grok never reads at all) and start
//! materializing into the `GROK_HOME` csq already owns and already
//! redirects.

use std::collections::{BTreeMap, BTreeSet};

use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

use super::flatten::{flatten_artifacts, is_real_path_restriction, render_sections};
use super::types::{GrokPermissionMode, GrokSandboxProfile, GrokSpawnPayload, McpFilter};

/// FR-CL-01 system-prompt directive — re-exported from
/// `crate::coc::translate::build_output_schema_directive`. Same byte content
/// as the CC/Codex/Gemini/Kimi variants; retained belt-and-braces alongside
/// `json_schema` (report 14 §6.3).
pub use super::build_output_schema_directive;

const SURFACE_HEADER: &str = "# csq capability layer (grok)\n";

/// FR-CL-01 JSON Schema for the `{rule_id, decision, rationale}` envelope,
/// as the literal document Grok's `--json-schema <SCHEMA>` flag consumes
/// (report 14 §6.3 — "the model is constrained to produce JSON matching
/// this schema", decoder-level enforcement no other Surface offers today).
/// Pure/deterministic: fixed literal, no runtime inputs.
pub fn build_json_schema_string() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "rule_id": { "type": "string" },
            "decision": { "type": "string", "enum": ["refuse", "comply"] },
            "rationale": { "type": "string" }
        },
        "required": ["rule_id", "decision", "rationale"],
        "additionalProperties": false
    })
    .to_string()
}

/// CU1b: shares `super::flatten` with the other four translators and the
/// live capability-layer scaffold stage — one flattener, no per-surface
/// drift. Only the Surface header + the grok-specific payload fields
/// (sandbox, permission mode, json schema, path-scope tracking) differ.
///
/// Path-scoped rules (`FlatArtifact.paths` a real restriction, not the
/// parser's `["**"]` catch-all default — see
/// [`super::flatten::is_real_path_restriction`]) are NOT expressed as
/// directory-scoped `AGENTS.md` files — the
/// harness-decomposition report (§7.2 `scoped_agents_md`) proposed
/// materializing a scoped rule under `$GROK_HOME/<dir-prefix>/AGENTS.md`,
/// but no evidence in the report establishes that Grok scans subdirectories
/// of `$GROK_HOME` for per-directory instruction files (§3.1 documents only
/// the top-level `$GROK_HOME/AGENTS.md` at global scope, and the
/// project-tree directory walk is a SEPARATE mechanism rooted at the repo,
/// not at `$GROK_HOME`). Building on an unverified read path would silently
/// produce dead files. Every genuinely path-scoped rule is therefore
/// broadened to global scope (its body still reaches `agents_md` through
/// the shared flatten pipeline) and its id is recorded in
/// `unscoped_path_rules` so the broadening is visible rather than silent
/// (report 14 §6.1 "Rules (path-scoped)").
pub fn translate(coc_set: &CocSet) -> GrokSpawnPayload {
    let arts = flatten_artifacts(coc_set, Surface::Grok);
    let (agents_md, contributing_ids) = render_sections(SURFACE_HEADER, &arts);

    let unscoped_path_rules: BTreeSet<String> = arts
        .rules
        .iter()
        .filter(|r| is_real_path_restriction(&r.paths))
        .map(|r| r.id.clone())
        .collect();

    GrokSpawnPayload {
        agents_md,
        unscoped_path_rules,
        // Reserved — CocSet carries no permission-rule kind yet. See the
        // payload's doc comment (mirrors `mcp_filter` on every translator).
        permission_deny: BTreeSet::new(),
        permission_allow: BTreeSet::new(),
        // Deterministic per-slot isolation by default (report 14 §7.4 item
        // 6) — every real `[compat.claude]` cell (`skills`, `rules`,
        // `agents`, `mcps`, `hooks`, `sessions` — report 14 §5.3 line 524)
        // is set `false`. Round-13 review HIGH-2: this does NOT close
        // every bleed path. THREE remain un-suppressible by ANY cell
        // (the count and the list must agree — an earlier version of
        // this comment said "Two" while listing three, which is the
        // same under-count HIGH-2 existed to remove; the sibling doc on
        // the field itself in `types.rs` was corrected and this one was
        // not):
        // - `~/.claude/settings.json` permissions (report 14 §5.3 — no
        //   `[compat.claude] permissions` cell exists at all).
        // - Subagent discovery from `.claude/agents/`/`~/.claude/agents/`
        //   (report 14 §8 item 1). The `agents` cell name is a FALSE
        //   FRIEND: it gates only the CLAUDE.md/CLAUDE.local.md
        //   instruction-file scan (`05-configuration.md:382`), NOT
        //   subagent loading — `README.md:2218` documents subagent
        //   compat separately, and report 14's own verdict table (§6.1
        //   row "Subagents", §8 item 1) states plainly: "I found no cell
        //   that does [gate subagent discovery]."
        // - Plugin/marketplace state
        //   (`~/.claude/plugins/installed_plugins.json`,
        //   `known_marketplaces.json`) — report 14 §3.2 row "Plugins"
        //   ("(not cell-gated)").
        //
        // See `csq::cli::commands::run::launch_native`'s "Additional
        // wiring-shard obligations" doc comment for the concrete
        // duplicate-subagent hazard this creates once native
        // materialization is wired (`emit_grok_native` writes
        // `$GROK_HOME/agents/csq-<ID>.md`; Grok independently loads
        // `.claude/agents/<ID>.md` — same body, two names, competing for
        // automatic skill/agent selection).
        compat_cells_disabled: true,
        sandbox_profile: GrokSandboxProfile::ReadOnly,
        permission_mode: GrokPermissionMode::default(),
        // `--permission-mode dontAsk` is accepted but silently ignored
        // (report 14 §5.1) — `defaultMode` in settings.json is the only
        // path that actually enables deny-by-default.
        default_mode: Some("dontAsk".to_string()),
        json_schema: Some(build_json_schema_string()),
        output_schema_directive: Some(build_output_schema_directive()),
        // Reserved — CocSet carries no hook-artifact kind yet. See the
        // payload's doc comment (mirrors `KimiSpawnPayload::hooks`).
        hooks: BTreeMap::new(),
        mcp_filter: McpFilter::default(),
        contributing_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::types::{CocSet, CocSource, RuleDef, RuleId};
    use crate::coc::version::CocVersion;
    use sha2::{Digest, Sha256};
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

    fn scoped_rule(id: &str, paths: &[&str], body: &str) -> RuleDef {
        RuleDef {
            id: RuleId(id.to_string()),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            applies_to: BTreeSet::new(),
            precedence: 0,
            disable: BTreeSet::new(),
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

    fn sha256_of(p: &GrokSpawnPayload) -> [u8; 32] {
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
        assert!(payload.unscoped_path_rules.is_empty());
        assert!(payload.mcp_filter.is_empty());
        // `hooks` is reserved (CocSet has no hook-artifact kind yet) and
        // `translate` hardcodes it empty — this pins that INTENT (so a
        // future change populating it without updating this test/doc is
        // caught), not a behavior the empty `CocSet` itself exercises.
        assert!(payload.hooks.is_empty());
    }

    #[test]
    fn rule_scoped_codex_reaches_grok_via_shared_fallback() {
        let set = build_set(vec![rule(
            "RULE-CDX",
            5,
            &[Surface::Codex],
            "deny shell exec",
        )]);
        let payload = translate(&set);
        assert!(payload.agents_md.contains("### RULE-CDX"));
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

    /// The single most important honesty check in this translator: a rule
    /// carrying real path scope (`paths != ["**"]`, i.e. an actual glob)
    /// MUST be reported as broadened, not silently dropped or silently
    /// treated as still-scoped.
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

    /// An unscoped rule (default `paths: ["**"]` from the parser, or an
    /// explicitly-empty `paths`) is NOT recorded — only rules that actually
    /// declared a narrower scope are.
    #[test]
    fn wildcard_path_rule_is_not_recorded_as_unscoped() {
        let set = build_set(vec![rule("RULE-WILD", 0, &[], "applies everywhere")]);
        let payload = translate(&set);
        assert!(!payload.unscoped_path_rules.contains("RULE-WILD"));
    }

    #[test]
    fn precedence_orders_high_first() {
        let set = build_set(vec![
            rule("RULE-LOW", 0, &[Surface::Grok], "low"),
            rule("RULE-HIGH", 9, &[Surface::Grok], "high"),
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
            rule("RULE-A", 5, &[Surface::Grok], "alpha"),
            scoped_rule("RULE-B", &["src/**"], "beta"),
        ]);
        let first = sha256_of(&translate(&set));
        for _ in 0..30 {
            assert_eq!(first, sha256_of(&translate(&set)));
        }
    }

    #[test]
    fn universal_rule_appears_in_grok_translator() {
        let set = build_set(vec![rule(
            "RULE-UNIVERSAL",
            0,
            &[],
            "applies to all surfaces",
        )]);
        let payload = translate(&set);
        assert!(payload.agents_md.contains("RULE-UNIVERSAL"));
        assert!(payload.contributing_ids.contains("RULE-UNIVERSAL"));
    }

    #[test]
    fn output_schema_directive_present_on_grok_payload() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        let directive = payload
            .output_schema_directive
            .expect("directive must be Some");
        assert!(directive.contains("rule_id"));
    }

    /// Grok's `--json-schema` is decoder-level enforcement (report 14
    /// §6.3) — every payload MUST carry a well-formed JSON Schema
    /// document naming the same three fields as the prompt directive.
    #[test]
    fn json_schema_present_and_well_formed() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        let schema_text = payload.json_schema.expect("json_schema must be Some");
        let parsed: serde_json::Value =
            serde_json::from_str(&schema_text).expect("json_schema must be valid JSON");
        let required = parsed["required"]
            .as_array()
            .expect("schema must declare required fields");
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_strs.contains(&"rule_id"));
        assert!(required_strs.contains(&"decision"));
        assert!(required_strs.contains(&"rationale"));
    }

    #[test]
    fn default_mode_is_dont_ask_not_the_ignored_flag_value() {
        // report 14 §5.1: `--permission-mode dontAsk` is accepted-but-inert;
        // `defaultMode` in settings.json is the only real lever. Pin that
        // the translator uses the settings.json field, not the flag.
        let set = build_set(vec![]);
        let payload = translate(&set);
        assert_eq!(payload.default_mode.as_deref(), Some("dontAsk"));
        assert_eq!(payload.permission_mode, GrokPermissionMode::Default);
    }

    #[test]
    fn compat_cells_disabled_by_default_for_slot_isolation() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        assert!(payload.compat_cells_disabled);
    }

    /// Round-5 F2/F5: every GrokSandboxProfile + GrokPermissionMode
    /// serde wire name equals its `as_str` name — the JSON and TOML/argv
    /// channels cannot drift silently (the enums derive kebab-case, but
    /// only a test pins it against a future rename).
    #[test]
    fn serde_wire_names_match_as_str_for_grok_enums() {
        use crate::coc::translate::types::{GrokPermissionMode, GrokSandboxProfile};
        for v in [
            GrokSandboxProfile::Off,
            GrokSandboxProfile::Workspace,
            GrokSandboxProfile::ReadOnly,
            GrokSandboxProfile::Strict,
            GrokSandboxProfile::Devbox,
        ] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(
                wire,
                serde_json::Value::String(v.as_str().to_string()),
                "sandbox profile wire name must equal as_str for {v:?}"
            );
        }
        for v in [
            GrokPermissionMode::Default,
            GrokPermissionMode::BypassPermissions,
        ] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(
                wire,
                serde_json::Value::String(v.as_str().to_string()),
                "permission mode wire name must equal as_str for {v:?}"
            );
        }
    }
}
