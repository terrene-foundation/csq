//! Per-CLI translators: take a `CocSet` and produce a Surface-shaped
//! spawn-time payload.
//!
//! Authoritative spec: `specs/09-unified-coc-artifact-standard.md` §9.2.4
//! (CocSet) + the FR-DISP-* family in
//! `internal-design-docs`.
//!
//! Five translators exist (one per Surface):
//! - `cc`     — Claude Code: settings.json overlay + system-prompt-append
//! - `codex`  — OpenAI Codex: config.toml overlay + sandbox mode + MCP filter
//! - `gemini` — Google Gemini: settings.json overlay + approval mode + MCP filter
//! - `kimi`   — Moonshot Kimi Code (native CLI): AGENTS.md (advisory) +
//!   config.toml permission rules/hooks (hard-constraint channel)
//! - `grok`   — xAI Grok (native CLI): AGENTS.md + config.toml/settings.json
//!   + native `--json-schema` structured output
//!
//! All translators are PURE FUNCTIONS — same input produces byte-identical
//! output across runs and across processes (FR-DISP-05). The pipeline
//! integration (`PipelineStage` trait) lives at spec 10 §10.3 and lands in
//! M3/PR-CA4 — translators in M2 stand alone as `(&CocSet) → Payload`.

pub mod cc;
pub mod codex;
pub mod codex_merge;
pub mod flatten;
pub mod gemini;
pub mod grok;
pub mod kimi;
pub mod kimi_merge;
pub mod materialize;
mod provenance;
pub mod types;

pub use flatten::{
    flatten_artifacts, render_sections, surface_header, FlatArtifact, SurfaceArtifacts,
};
pub use materialize::{
    emit_cc_plugin, emit_coc_rules, emit_codex_native, emit_gemini_native, emit_grok_native,
    emit_kimi_native, MaterializedKind, MaterializedManifest,
};
pub use types::{
    ApprovalMode, ClaudeSpawnPayload, CodexSpawnPayload, GeminiSpawnPayload, GrokPermissionMode,
    GrokSandboxProfile, GrokSpawnPayload, HostContext, KimiDecision, KimiHook, KimiHookEvent,
    KimiPermissionRule, KimiScope, KimiSpawnPayload, McpFilter, SandboxMode, SpawnPayload,
};

use crate::providers::catalog::Surface;

use super::types::CocSet;

/// Dispatch a `CocSet` through the per-Surface translator. Returns
/// `SpawnPayload` (a sum type over the five Surfaces).
///
/// `host_ctx` carries Surface-specific host context (round-3 R3-M3
/// sum-type promotion). cc + codex translators ignore it (their
/// `translate` fns take only `&CocSet` and stay deterministic over
/// their input). gemini consumes via `host_ctx.as_gemini()` for the
/// spec 08 MED-03 host-isolation warning bit.
///
/// Callers that don't need host context pass `&HostContext::None`
/// (default).
pub fn translate(coc_set: &CocSet, surface: Surface, host_ctx: &HostContext) -> SpawnPayload {
    match surface {
        Surface::ClaudeCode => SpawnPayload::ClaudeCode(cc::translate(coc_set)),
        Surface::Codex => SpawnPayload::Codex(codex::translate(coc_set)),
        Surface::Gemini => SpawnPayload::Gemini(gemini::translate_with_options(
            coc_set,
            host_ctx.as_gemini(),
        )),
        // Native Kimi/Grok each get their own translator (workspace
        // hermes-parity an internal journal entry + 0133 supersession). The prior
        // Codex-aliasing route was inert in both directions: `codex::
        // translate` emits a `CodexSpawnPayload.instructions` field destined
        // for `~/.codex/config.toml::instructions`, a key Kimi's config
        // schema does not have and Grok never reads at all (harness-
        // decomposition reports 13 §5.1 / 14 §6.2). Neither vendor's actual
        // read path — `<KIMI_CODE_HOME>/AGENTS.md` / `$GROK_HOME/AGENTS.md`
        // — was ever written to.
        Surface::Kimi => SpawnPayload::Kimi(kimi::translate(coc_set)),
        Surface::Grok => SpawnPayload::Grok(grok::translate(coc_set)),
    }
}

/// FR-CL-01 system-prompt directive instructing the model to emit a
/// `{"rule_id","decision","rationale"}` JSON envelope for compliance-class
/// prompts. Surface-agnostic: same directive text reaches each Surface through its per-Surface
/// delivery mechanism (CC env var / Codex `instructions` block in
/// config.toml / Gemini `system_instruction` field in settings.json /
/// Kimi `AGENTS.md` prose / Grok `--rules` flag).
///
/// Pure function (no inputs); deterministic across calls. Phase 2a
/// deviation per spec 10 §10.4.6: when csq doesn't own the API call, the
/// directive in the system prompt is the substitute for native
/// `response_format` enforcement.
///
/// The directive is also self-conditional ("for compliance prompts only");
/// the scaffold stage's class gate prevents free-form chat from receiving
/// the directive at all (`csq-core/src/capability_layer/scaffold.rs`).
///
/// Origin: PR-CA7c (CC-only); promoted to module level in PR-CA8 commit 1a
/// for cross-Surface use. Single source of truth for the directive text;
/// all five translators (cc, codex, gemini, kimi, grok) re-export from here.
pub fn build_output_schema_directive() -> String {
    let mut s = String::new();
    s.push_str("\n## Structured citation format (compliance prompts)\n");
    s.push_str(
        "When the prompt is a compliance question — i.e. one where a \
         RULE_ID-cited refusal or compliance answer is the expected \
         shape — emit a JSON object on its own line with these fields:\n",
    );
    s.push_str("- `rule_id` (string): the RULE_ID you are citing (e.g. \"RULE-NO-PII\").\n");
    s.push_str("- `decision` (string): \"refuse\" or \"comply\".\n");
    s.push_str("- `rationale` (string): brief explanation grounded in the rule body.\n");
    s.push_str(
        "\nExample: `{\"rule_id\":\"RULE-NO-PII\",\"decision\":\"refuse\",\"rationale\":\"The rule prohibits echoing PII verbatim.\"}`\n",
    );
    s.push_str(
        "\nFor free-form chat prompts (no compliance dimension), respond in plain prose — \
         the envelope is NOT required and SHOULD NOT be emitted.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::types::{CocSet, CocSource};

    fn empty_set() -> CocSet {
        CocSet {
            source: CocSource::Empty,
            ..CocSet::empty()
        }
    }

    #[test]
    fn dispatch_routes_to_correct_translator() {
        let set = empty_set();
        let no_host = HostContext::None;
        match translate(&set, Surface::ClaudeCode, &no_host) {
            SpawnPayload::ClaudeCode(_) => (),
            other => panic!("expected ClaudeCode payload, got {other:?}"),
        }
        match translate(&set, Surface::Codex, &no_host) {
            SpawnPayload::Codex(_) => (),
            other => panic!("expected Codex payload, got {other:?}"),
        }
        match translate(&set, Surface::Gemini, &no_host) {
            SpawnPayload::Gemini(_) => (),
            other => panic!("expected Gemini payload, got {other:?}"),
        }
        match translate(&set, Surface::Kimi, &no_host) {
            SpawnPayload::Kimi(_) => (),
            other => panic!("expected Kimi payload, got {other:?}"),
        }
        match translate(&set, Surface::Grok, &no_host) {
            SpawnPayload::Grok(_) => (),
            other => panic!("expected Grok payload, got {other:?}"),
        }
    }

    /// Kimi/Grok are no longer aliased to the Codex translator (workspace
    /// hermes-parity an internal journal entry) — each Surface now produces its OWN
    /// payload variant, distinct from `SpawnPayload::Codex`.
    #[test]
    fn kimi_and_grok_no_longer_alias_codex_payload() {
        let set = empty_set();
        let no_host = HostContext::None;
        assert!(!matches!(
            translate(&set, Surface::Kimi, &no_host),
            SpawnPayload::Codex(_)
        ));
        assert!(!matches!(
            translate(&set, Surface::Grok, &no_host),
            SpawnPayload::Codex(_)
        ));
    }

    /// PR-CA8b R3-M3: HostContext default is `None` variant — used
    /// by call sites that don't need host context (cc, codex, or
    /// the test fast-path). `as_gemini()` returns `None`.
    #[test]
    fn host_context_default_is_none_variant() {
        let ctx = HostContext::default();
        assert!(matches!(ctx, HostContext::None));
        assert!(ctx.as_gemini().is_none());
    }

    /// PR-CA8b R3-M3: `as_gemini()` projects the Gemini variant when
    /// present.
    #[test]
    fn host_context_gemini_as_gemini_returns_some() {
        let inner = gemini::HostContext {
            production_secrets_present: true,
            ..Default::default()
        };
        let ctx = HostContext::Gemini(inner);
        let projected = ctx.as_gemini().expect("Gemini variant must project");
        assert!(projected.production_secrets_present);
    }

    /// PR-CA8b R3-M3: dispatcher ignores host_ctx for cc and codex —
    /// their translators take only `&CocSet`. The Gemini-specific
    /// HostContext is consumed only when surface is Gemini.
    #[test]
    fn translate_dispatcher_ignores_host_ctx_for_cc_and_codex() {
        let set = empty_set();
        let inner = gemini::HostContext {
            production_secrets_present: true,
            ..Default::default()
        };
        let ctx = HostContext::Gemini(inner);
        // CC + Codex still produce well-formed payloads — host_ctx
        // is unused for those Surfaces.
        match translate(&set, Surface::ClaudeCode, &ctx) {
            SpawnPayload::ClaudeCode(_) => (),
            other => panic!("expected ClaudeCode payload, got {other:?}"),
        }
        match translate(&set, Surface::Codex, &ctx) {
            SpawnPayload::Codex(_) => (),
            other => panic!("expected Codex payload, got {other:?}"),
        }
    }

    /// PR-CA8b R3-M3 + R2-H4: dispatcher threads host_ctx into the
    /// gemini translator. Result: `host_isolation_warning` bit on the
    /// payload reflects the input context.
    #[test]
    fn translate_dispatcher_threads_host_ctx_to_gemini_translator_only() {
        let set = empty_set();
        let inner = gemini::HostContext {
            production_secrets_present: true,
            ..Default::default()
        };
        let ctx = HostContext::Gemini(inner);
        match translate(&set, Surface::Gemini, &ctx) {
            SpawnPayload::Gemini(p) => {
                assert!(
                    p.host_isolation_warning,
                    "host_isolation_warning bit must propagate from HostContext::Gemini"
                );
            }
            other => panic!("expected Gemini payload, got {other:?}"),
        }
        // None variant → no warning.
        let no_host = HostContext::None;
        match translate(&set, Surface::Gemini, &no_host) {
            SpawnPayload::Gemini(p) => {
                assert!(!p.host_isolation_warning);
            }
            other => panic!("expected Gemini payload, got {other:?}"),
        }
    }

    /// PR-CA8 §11.5: the directive text is Surface-agnostic by construction.
    /// All five translator re-exports point at the same module-level
    /// function; this test pins byte-equivalence so a future
    /// translator-specific override fails fast.
    #[test]
    fn output_schema_directive_text_byte_identical_across_surfaces() {
        let cc = cc::build_output_schema_directive();
        let cdx = codex::build_output_schema_directive();
        let gem = gemini::build_output_schema_directive();
        let kim = kimi::build_output_schema_directive();
        let grk = grok::build_output_schema_directive();
        assert_eq!(cc, cdx, "cc vs codex directive text must be identical");
        assert_eq!(cdx, gem, "codex vs gemini directive text must be identical");
        assert_eq!(gem, kim, "gemini vs kimi directive text must be identical");
        assert_eq!(kim, grk, "kimi vs grok directive text must be identical");
        assert!(
            cc.contains("rule_id"),
            "directive must name the rule_id field"
        );
        assert!(
            cc.contains("decision"),
            "directive must name the decision field"
        );
        assert!(
            cc.contains("rationale"),
            "directive must name the rationale field"
        );
    }
}
