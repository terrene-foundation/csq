//! Per-Surface payload types per Amendment G (M9; csq-as-cli/todos/M9
//! §"Amendment G — Type contract enumeration") + spec 10 §10.3.4.
//!
//! Each translator emits a Surface-specific payload. Field shapes are
//! constrained to determinism-friendly containers (`BTreeMap`, `BTreeSet`,
//! sorted `Vec`) so identical input produces byte-identical output (FR-DISP-05).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// MCP tool allow/deny filter shared across all three Surfaces. The
/// capability layer's MCP gate (FR-CL-03) consults this on every tool-call
/// invocation. Spec 10 §10.8.2: the `.coc/`-declared policy INTERSECTS
/// with the user's existing MCP policy, never UNIONs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpFilter {
    /// Tool names explicitly allowed. Empty allow-list means "no positive
    /// allowlist declared" — caller falls back to deny-list-only filtering.
    pub allow: BTreeSet<String>,
    /// Tool names explicitly denied. A tool in `deny` is rejected even if
    /// it's also in `allow` (deny-wins, intersection-not-union).
    pub deny: BTreeSet<String>,
}

impl McpFilter {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Codex sandbox modes per spec 07 §7.2.2 + §7.7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxMode {
    /// `--sandbox read-only` — compliance + safety suites. Default.
    #[default]
    ReadOnly,
    /// `--sandbox write` — implementation suite, gated. Currently NOT
    /// emitted by csq's translator (M2); reserved for M3+ when the
    /// pipeline gains implementation-suite awareness.
    Write,
}

impl SandboxMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxMode::ReadOnly => "read-only",
            SandboxMode::Write => "write",
        }
    }
}

/// Gemini approval modes per spec 07 §7.2.3 + §7.3.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    /// `--approval-mode plan` — read-only suites. Default.
    #[default]
    Plan,
    /// `--approval-mode auto` — implementation suite, gated. Reserved.
    Auto,
}

impl ApprovalMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalMode::Plan => "plan",
            ApprovalMode::Auto => "auto",
        }
    }
}

/// Claude Code spawn-time payload (FR-DISP-02).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeSpawnPayload {
    /// Raw text to append to `settings.json::env.CLAUDE_SYSTEM_PROMPT_APPEND`
    /// per FR-DISP-02. Built by concatenating in-scope rule bodies in
    /// deterministic order.
    pub system_prompt_append: String,
    /// Tool allowlist that maps to `settings.json::permissions.allow`.
    /// Sorted by `BTreeSet` for determinism.
    pub permissions_allow: BTreeSet<String>,
    /// MCP filter forwarded to the capability layer's MCP gate.
    pub mcp_filter: McpFilter,
    /// Free-form `settings.json` overlay keys. Use `BTreeMap` so iteration
    /// order is alphabetical (deterministic) when csq writes to settings.json.
    pub settings_overlay: BTreeMap<String, serde_json::Value>,
    /// IDs of artifacts that contributed to this payload. Used by the
    /// audit trail (NFR-AUDIT-01 `rule_ids_cited` field).
    pub contributing_ids: BTreeSet<String>,
    /// Structured-output directive (FR-CL-01) — system-prompt fragment
    /// instructing the model to emit a `{"rule_id", "decision",
    /// "rationale"}` envelope when responding to compliance-class
    /// prompts. `None` when no directive is needed (e.g. translator
    /// invoked outside the capability layer pipeline). The capability
    /// layer's scaffold stage appends this to `system_prompt_append`
    /// when the directive is present and the active prompt class is
    /// `Compliance`.
    ///
    /// Phase 2a deviation from FR-CL-01: spec 10 §10.4.6 records that
    /// CC's `--output-format json` mode wraps responses in metadata
    /// rather than producing schema-shaped content. The system-prompt
    /// directive is the Phase 2a substitute; Phase 2b's csq-owns-the-
    /// API-call shape will use native `response_format` enforcement.
    pub output_schema_directive: Option<String>,
}

/// OpenAI Codex spawn-time payload (FR-DISP-03; Amendment G shape).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexSpawnPayload {
    /// Key-value overlay applied on top of `~/.codex/config.toml`.
    /// `BTreeMap<String, String>` per Amendment G — values are TOML scalars
    /// already rendered to their string form (e.g. `"42"` is the integer 42,
    /// `"true"` is boolean true, `"\"foo\""` is the string `"foo"`).
    /// Consumers parse each value via TOML before merge to preserve scalar
    /// type — pure strings must be pre-quoted. Single TOML scalar expressions
    /// only (no embedded `\n`, no trailing comments, no multi-line tables).
    /// Origin: PR-CA8 round-2 R2-C1 + round-3 R3-L1.
    pub config_toml_overlay: BTreeMap<String, String>,
    /// Long-form `instructions = "..."` block written into config.toml.
    /// Built by concatenating in-scope rule bodies in deterministic order.
    pub instructions: String,
    /// Sandbox mode for `--sandbox <mode>` argv flag.
    pub sandbox_mode: SandboxMode,
    /// MCP filter forwarded to the capability layer's MCP gate.
    pub mcp_filter: McpFilter,
    /// IDs of artifacts that contributed to this payload.
    pub contributing_ids: BTreeSet<String>,
    /// Structured-output directive (FR-CL-01) — system-prompt fragment
    /// instructing the model to emit a `{"rule_id", "decision",
    /// "rationale"}` envelope when responding to compliance-class
    /// prompts. `None` when no directive is needed (e.g. translator
    /// invoked outside the capability layer pipeline).
    ///
    /// Surface-agnostic body: this field carries the same text as
    /// `ClaudeSpawnPayload::output_schema_directive` and
    /// `GeminiSpawnPayload::output_schema_directive` per spec 10
    /// §10.4.6.1. Delivered to codex via the per-spawn handle-dir
    /// `config.toml::instructions` block (PR-CA8 commit 2).
    ///
    /// Phase 2a deviation per spec 10 §10.4.6: Phase 2b's csq-owns-the-
    /// API-call shape will use native `response_format` enforcement.
    pub output_schema_directive: Option<String>,
}

/// Google Gemini spawn-time payload (FR-DISP-04; Amendment G shape).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeminiSpawnPayload {
    /// Key-value overlay applied on top of `~/.gemini/settings.json`.
    /// `BTreeMap<String, Value>` per Amendment G.
    pub settings_json_overlay: BTreeMap<String, serde_json::Value>,
    /// `system_instruction` field written into settings.json. Built by
    /// concatenating in-scope rule bodies in deterministic order.
    pub system_instruction: String,
    /// Approval mode for `--approval-mode <mode>` argv flag.
    pub approval_mode: ApprovalMode,
    /// MCP filter forwarded to the capability layer's MCP gate.
    pub mcp_filter: McpFilter,
    /// IDs of artifacts that contributed to this payload.
    pub contributing_ids: BTreeSet<String>,
    /// Per spec 08 MED-03 host-isolation caveat (FR-DISP-04 acceptance).
    /// Set when the translator detects the host carries production-shaped
    /// secrets that may leak through Gemini's local-process tools. The
    /// translator surfaces the warning; the caller decides whether to
    /// abort or log + proceed.
    pub host_isolation_warning: bool,
    /// Structured-output directive (FR-CL-01) — Surface-agnostic body
    /// shared with `ClaudeSpawnPayload::output_schema_directive` and
    /// `CodexSpawnPayload::output_schema_directive` per spec 10
    /// §10.4.6.1. Delivered to gemini via the handle-dir
    /// `.gemini/settings.json::system_instruction` field by csq-cli's
    /// gemini layer wire-up (PR-CA8b commit 4).
    ///
    /// Phase 2a deviation per spec 10 §10.4.6: Phase 2b's csq-owns-the-
    /// API-call shape will use native `response_format` enforcement.
    pub output_schema_directive: Option<String>,
    /// First detected production-shaped env-var name (round-3 R3-H7
    /// disclosure-minimization). Populated when `host_isolation_warning`
    /// is true; the operator-facing stderr line uses this exemplar
    /// instead of enumerating the full `detected_var_names` set.
    /// `None` when no host context was supplied or no secrets detected.
    pub detected_var_first: Option<String>,
}

/// Per-Surface host context, threaded into the translate dispatcher
/// when a Surface needs to consult host state. Today only Gemini
/// needs it (env-var detection for the spec 08 MED-03 host-isolation
/// warning); future Surfaces extend the enum without re-widening
/// dispatcher signatures.
///
/// Origin: PR-CA8 round-2 R2-H4 (HostContext threading) + round-3
/// R3-M3 (sum-type promotion to avoid cross-Surface type coupling
/// in the central dispatcher).
#[derive(Debug, Clone, Default)]
pub enum HostContext {
    /// No host context supplied — translators that consult host state
    /// (only gemini today) treat this as the clean-env case.
    #[default]
    None,
    /// Gemini-specific host context per spec 08 MED-03.
    Gemini(crate::coc::translate::gemini::HostContext),
}

impl HostContext {
    /// Project to the Gemini variant if present; `None` otherwise.
    /// Translators (gemini) call this to fetch their typed context;
    /// non-consuming translators (cc, codex) ignore the dispatcher's
    /// `&HostContext` parameter entirely.
    pub fn as_gemini(&self) -> Option<&crate::coc::translate::gemini::HostContext> {
        match self {
            HostContext::Gemini(g) => Some(g),
            _ => None,
        }
    }
}

/// Sum type over the three Surface payloads. Returned by the
/// dispatcher in `coc/translate/mod.rs::translate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "surface", rename_all = "kebab-case")]
pub enum SpawnPayload {
    ClaudeCode(ClaudeSpawnPayload),
    Codex(CodexSpawnPayload),
    Gemini(GeminiSpawnPayload),
}

impl SpawnPayload {
    pub fn contributing_ids(&self) -> &BTreeSet<String> {
        match self {
            SpawnPayload::ClaudeCode(p) => &p.contributing_ids,
            SpawnPayload::Codex(p) => &p.contributing_ids,
            SpawnPayload::Gemini(p) => &p.contributing_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_filter_default_is_empty() {
        assert!(McpFilter::default().is_empty());
    }

    #[test]
    fn sandbox_mode_str_is_kebab_case() {
        assert_eq!(SandboxMode::ReadOnly.as_str(), "read-only");
        assert_eq!(SandboxMode::Write.as_str(), "write");
    }

    #[test]
    fn approval_mode_str_is_kebab_case() {
        assert_eq!(ApprovalMode::Plan.as_str(), "plan");
        assert_eq!(ApprovalMode::Auto.as_str(), "auto");
    }

    #[test]
    fn defaults_are_safe() {
        // Defaults must be the most-restrictive options so a translator
        // that forgets to set the field doesn't accidentally elevate.
        assert_eq!(SandboxMode::default(), SandboxMode::ReadOnly);
        assert_eq!(ApprovalMode::default(), ApprovalMode::Plan);
    }
}
