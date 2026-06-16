//! Per-CLI translators: take a `CocSet` and produce a Surface-shaped
//! spawn-time payload.
//!
//! Authoritative spec: `specs/09-unified-coc-artifact-standard.md` §9.2.4
//! (CocSet) + the FR-DISP-* family in
//! `workspaces/csq-as-cli/01-analysis/01-research/01-functional-requirements.md`.
//!
//! Three translators exist (one per Surface):
//! - `cc`     — Claude Code: settings.json overlay + system-prompt-append
//! - `codex`  — OpenAI Codex: config.toml overlay + sandbox mode + MCP filter
//! - `gemini` — Google Gemini: settings.json overlay + approval mode + MCP filter
//!
//! All translators are PURE FUNCTIONS — same input produces byte-identical
//! output across runs and across processes (FR-DISP-05). The pipeline
//! integration (`PipelineStage` trait) lives at spec 10 §10.3 and lands in
//! M3/PR-CA4 — translators in M2 stand alone as `(&CocSet) → Payload`.

pub mod cc;
pub mod codex;
pub mod codex_merge;
pub mod gemini;
pub mod types;

pub use types::{
    ApprovalMode, ClaudeSpawnPayload, CodexSpawnPayload, GeminiSpawnPayload, HostContext,
    McpFilter, SandboxMode, SpawnPayload,
};

use crate::providers::catalog::Surface;

use super::types::CocSet;

/// Dispatch a `CocSet` through the per-Surface translator. Returns
/// `SpawnPayload` (a sum type over the three Surfaces).
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
    }
}

/// FR-CL-01 system-prompt directive instructing the model to emit a
/// `{"rule_id","decision","rationale"}` JSON envelope for compliance-class
/// prompts. Surface-agnostic: same directive text reaches CC, Codex, and
/// Gemini through their respective per-Surface delivery mechanisms (CC env
/// var / Codex `instructions` block in config.toml / Gemini
/// `system_instruction` field in settings.json).
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
/// all three translators (cc, codex, gemini) re-export from here.
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
    /// All three translator re-exports point at the same module-level function;
    /// this test pins byte-equivalence so a future translator-specific override
    /// fails fast.
    #[test]
    fn output_schema_directive_text_byte_identical_across_surfaces() {
        let cc = cc::build_output_schema_directive();
        let cdx = codex::build_output_schema_directive();
        let gem = gemini::build_output_schema_directive();
        assert_eq!(cc, cdx, "cc vs codex directive text must be identical");
        assert_eq!(cdx, gem, "codex vs gemini directive text must be identical");
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
