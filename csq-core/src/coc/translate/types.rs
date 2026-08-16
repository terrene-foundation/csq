//! Per-Surface payload types per Amendment G (M9; an internal workspace/todos/M9
//! §"Amendment G — Type contract enumeration") + spec 10 §10.3.4.
//!
//! Each translator emits a Surface-specific payload. Field shapes are
//! constrained to determinism-friendly containers (`BTreeMap`, `BTreeSet`,
//! sorted `Vec`) so identical input produces byte-identical output
//! (FR-DISP-05) — with two documented exceptions (LOW-K):
//! [`KimiSpawnPayload::permission_rules`] and [`KimiSpawnPayload::hooks`]
//! are plain, UNSORTED `Vec`s whose insertion order
//! `kimi_merge::render_hook_value`/`render_permission_rule_value` preserve
//! verbatim into the emitted TOML array. Both are always empty from
//! `kimi::translate` today (`CocSet` carries no permission-rule or hook
//! artifact kind yet — see their field docs), so the exception is currently
//! vacuous in practice; it becomes load-bearing the moment a future
//! `.coc/` artifact kind populates them, at which point ORDERING BECOMES
//! THE CALLER'S OBLIGATION, not a guarantee this type contract provides.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// MCP tool allow/deny filter shared across all five Surfaces. The
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
    /// Rule IDs whose `paths` glob scope could not be honored and were
    /// therefore BROADENED to `instructions`'s global scope — surfaced here
    /// rather than silently widened. Codex has no per-file rule-scoping
    /// mechanism (`flatten::in_scope`'s doc comment): every in-scope rule
    /// body, regardless of `paths`, is concatenated into one flat
    /// `instructions` block — the identical shape as
    /// `KimiSpawnPayload::unscoped_path_rules` /
    /// `GrokSpawnPayload::unscoped_path_rules` (round-13 review MED-2 —
    /// Codex had this same silent loss pre-existing on `main`; all three
    /// now populate from the one shared
    /// `flatten::is_real_path_restriction` predicate so they cannot drift).
    pub unscoped_path_rules: BTreeSet<String>,
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
    /// Rule IDs whose `paths` glob scope could not be honored and were
    /// therefore BROADENED to `system_instruction`'s global scope —
    /// surfaced here rather than silently widened. Same shape as
    /// `CodexSpawnPayload::unscoped_path_rules` — see its doc comment
    /// (round-13 review MED-2).
    pub unscoped_path_rules: BTreeSet<String>,
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

/// Decision for a Kimi `[[permission.rules]]` entry
/// (`PermissionRuleSchema$1`, harness-decomposition report 13 §H7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KimiDecision {
    Allow,
    #[default]
    Deny,
}

impl KimiDecision {
    pub const fn as_str(&self) -> &'static str {
        match self {
            KimiDecision::Allow => "allow",
            KimiDecision::Deny => "deny",
        }
    }
}

/// Scope for a Kimi permission rule. Default mirrors the vendor's own
/// schema default (`"user"`) — report 13 §H7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KimiScope {
    TurnOverride,
    SessionRuntime,
    Project,
    #[default]
    User,
}

impl KimiScope {
    pub const fn as_str(&self) -> &'static str {
        match self {
            KimiScope::TurnOverride => "turn-override",
            KimiScope::SessionRuntime => "session-runtime",
            KimiScope::Project => "project",
            KimiScope::User => "user",
        }
    }
}

/// One Kimi `[[permission.rules]]` entry. `pattern` is `ToolName` or
/// `ToolName(argPattern)` (report 13 §H7) — Kimi's hard-constraint channel,
/// since its `AGENTS.md` instruction channel is explicitly demoted to
/// advisory reference data (report 13 §5, H1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KimiPermissionRule {
    pub decision: KimiDecision,
    pub scope: KimiScope,
    pub pattern: String,
    pub reason: Option<String>,
}

/// Kimi Code 0.28.1 hook lifecycle event — the closed 16-name enum
/// `HOOK_EVENT_TYPES$1` (report 13 §4.2). `serde`/TOML-rendered names MUST
/// match these exact strings — Kimi's `HookDefSchema` is `.strict()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KimiHookEvent {
    // The serde wire names are pinned EXPLICITLY (round-4 NIT): without
    // `rename`, the derived JSON format piggybacks on the Rust variant
    // names, so a future refactor renaming a variant would silently
    // change the SpawnPayload wire format while the TOML path (as_str)
    // stayed correct. The renames make the wire format independent of
    // the Rust identifiers, matching `as_str` exactly.
    #[serde(rename = "PreToolUse")]
    PreToolUse,
    #[serde(rename = "PostToolUse")]
    PostToolUse,
    #[serde(rename = "PostToolUseFailure")]
    PostToolUseFailure,
    #[serde(rename = "PermissionRequest")]
    PermissionRequest,
    #[serde(rename = "PermissionResult")]
    PermissionResult,
    #[serde(rename = "UserPromptSubmit")]
    UserPromptSubmit,
    #[serde(rename = "Stop")]
    Stop,
    #[serde(rename = "StopFailure")]
    StopFailure,
    #[serde(rename = "Interrupt")]
    Interrupt,
    #[serde(rename = "SessionStart")]
    SessionStart,
    #[serde(rename = "SessionEnd")]
    SessionEnd,
    #[serde(rename = "SubagentStart")]
    SubagentStart,
    #[serde(rename = "SubagentStop")]
    SubagentStop,
    #[serde(rename = "PreCompact")]
    PreCompact,
    #[serde(rename = "PostCompact")]
    PostCompact,
    #[serde(rename = "Notification")]
    Notification,
}

impl KimiHookEvent {
    /// The exact string Kimi's `HOOK_EVENT_TYPES$1` enum expects.
    pub const fn as_str(&self) -> &'static str {
        match self {
            KimiHookEvent::PreToolUse => "PreToolUse",
            KimiHookEvent::PostToolUse => "PostToolUse",
            KimiHookEvent::PostToolUseFailure => "PostToolUseFailure",
            KimiHookEvent::PermissionRequest => "PermissionRequest",
            KimiHookEvent::PermissionResult => "PermissionResult",
            KimiHookEvent::UserPromptSubmit => "UserPromptSubmit",
            KimiHookEvent::Stop => "Stop",
            KimiHookEvent::StopFailure => "StopFailure",
            KimiHookEvent::Interrupt => "Interrupt",
            KimiHookEvent::SessionStart => "SessionStart",
            KimiHookEvent::SessionEnd => "SessionEnd",
            KimiHookEvent::SubagentStart => "SubagentStart",
            KimiHookEvent::SubagentStop => "SubagentStop",
            KimiHookEvent::PreCompact => "PreCompact",
            KimiHookEvent::PostCompact => "PostCompact",
            KimiHookEvent::Notification => "Notification",
        }
    }
}

/// One Kimi `[[hooks]]` entry. `HookDefSchema$1` is `.strict()` — exactly
/// `{event, matcher?, command, timeout?}`, no extra keys (report 13 §4.1).
/// `matcher` is compiled with `new RegExp(...)`; a malformed regex is
/// swallowed into "matches nothing" rather than an error (report 13 §4.3) —
/// callers MUST emit an anchored, pre-escaped regex, AND the pattern MUST
/// be restricted to the JS-non-unicode-compatible subset (Unicode property
/// escapes `\p{...}`/`\P{...}` and POSIX bracket expressions `[:alpha:]`
/// compile successfully but mean something DIFFERENT under JS's Annex-B
/// dialect; an empty matcher is REJECTED rather than accepted, because
/// Kimi's own hook engine special-cases it to fire on every tool call,
/// report 13 §4.3) — see `kimi_merge::is_js_regex_compatible`, the
/// enforcement point for this contract today.
///
/// **`command` runs under `shell: true`** (report 13 §4.5's exec
/// invocation: `spawn(command, {shell: true, ...})`) — Kimi passes the
/// full `command` string through a shell, so shell metacharacters
/// (`;`, `|`, `` ` ``, `$(...)`, `&&`) in `command` are interpreted, not
/// literal. `KimiSpawnPayload.hooks` is reserved today (`kimi::translate`
/// always emits `Vec::new()` — `CocSet` has no hook-artifact kind yet), so
/// no `.coc/`-authored content reaches `command` in production yet. **The
/// shard that populates this field from a `.coc/` hook artifact MUST
/// validate/escape `command` against shell injection before it reaches
/// `render_hook_value`** — `kimi_merge::render_hook_value` writes
/// `command` into `config.toml` verbatim (no shell-escaping is applied at
/// the TOML-merge layer; a shell-injection guard belongs at the artifact
/// ingestion boundary, mirroring how `matcher`'s regex-dialect validation
/// lives at the merge layer while id/body validation lives upstream in
/// `.coc/` parsing).
///
/// `timeout_secs` is `1..=600`; hooks fail OPEN on every failure branch
/// (report 13 §4.5), so this is an advisory control, not an enforcement
/// boundary on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KimiHook {
    pub event: KimiHookEvent,
    pub matcher: Option<String>,
    /// Shell command executed via `spawn(command, {shell: true, ...})` on
    /// Kimi's side — see the struct doc's "`command` runs under
    /// `shell: true`" note for the injection obligation this places on the
    /// (not-yet-implemented) shard that populates hooks from `.coc/`.
    pub command: String,
    pub timeout_secs: Option<u16>,
}

/// Kimi Code spawn-time payload (harness-decomposition report 13 §6.1).
///
/// Unlike Codex/Gemini, Kimi's own system prompt explicitly demotes
/// `AGENTS.md` to "project-supplied reference data … not a privileged
/// instruction channel" that "cannot grant itself authority" (report 13
/// H1) — so `agents_md` below is ADVISORY ONLY. Hard constraints MUST
/// travel via `permission_rules` + `hooks` (report 13 §5 "Hard tool
/// gating" verdict: FULL, and better than any current csq surface).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KimiSpawnPayload {
    /// Body of `<KIMI_CODE_HOME>/AGENTS.md`. Built by the same
    /// `flatten`/`render_sections` pipeline as the other four Surfaces
    /// (no per-surface flattener drift). ADVISORY ONLY — see the struct
    /// doc.
    pub agents_md: String,
    /// `config.toml` overlay, TOML-scalar-string valued (same convention
    /// as `CodexSpawnPayload::config_toml_overlay`). MUST NOT contain
    /// `default_model` — csq pins the model via `--model` at spawn
    /// (`providers::native::KIMI.pinned_model`); a config write would
    /// collide (report 13 §6.3). Enforced by `kimi_merge`.
    pub config_toml_overlay: BTreeMap<String, String>,
    /// `[[permission.rules]]` entries — THE hard-constraint channel.
    /// Reserved: `CocSet` carries no permission-rule artifact kind yet, so
    /// `kimi::translate` always emits an empty `Vec` here (mirrors
    /// `CodexSpawnPayload::mcp_filter`, which is likewise always
    /// `McpFilter::default()` from `codex::translate` and populated by a
    /// later capability-layer pipeline stage). The `kimi_merge` write path
    /// is real and tested directly against hand-built non-empty values.
    ///
    /// **LOW-K: NOT determinism-sorted.** Unlike the module's default
    /// `BTreeMap`/`BTreeSet`/sorted-`Vec` contract (see the module doc
    /// comment), this is a plain `Vec` whose element ORDER
    /// `kimi_merge::render_permission_rule_value` preserves verbatim into
    /// the emitted `[[permission.rules]]` array. The FUTURE shard that
    /// populates this field from `.coc/` artifacts MUST impose its own
    /// deterministic ordering (e.g. the same `(precedence DESC, id ASC)`
    /// sort `flatten::sort_flat` already uses for every other artifact
    /// kind) — this type does not do it for you.
    pub permission_rules: Vec<KimiPermissionRule>,
    /// `[[hooks]]` entries — THE enforcement channel (fail-open; report 13
    /// §4.5). Reserved for the same reason as `permission_rules` above:
    /// `CocSet` has no hook-artifact kind yet.
    ///
    /// **LOW-K: NOT determinism-sorted** — same caveat as
    /// `permission_rules` above; `kimi_merge::render_hook_value` preserves
    /// this `Vec`'s insertion order verbatim, and the future populating
    /// shard owns imposing a deterministic order.
    pub hooks: Vec<KimiHook>,
    /// MCP filter forwarded to the capability layer's MCP gate. Always
    /// `McpFilter::default()` from `kimi::translate`, same as the other
    /// four Surfaces' `mcp_filter` field.
    pub mcp_filter: McpFilter,
    /// IDs of artifacts that contributed to this payload.
    pub contributing_ids: BTreeSet<String>,
    /// Structured-output directive (FR-CL-01), Surface-agnostic body
    /// shared with the other four payloads. Delivered via `AGENTS.md`
    /// prose (belt-and-braces — Kimi has no native `response_format`).
    pub output_schema_directive: Option<String>,
    /// Rule IDs whose `paths` glob scope could not be honored and were
    /// therefore BROADENED to `agents_md`'s global scope — surfaced here
    /// rather than silently widened (round-13 review MED-2). Kimi has no
    /// per-file rule-scoping mechanism (report 13 documents only the
    /// top-level `<KIMI_CODE_HOME>/AGENTS.md`, no per-directory read path):
    /// every in-scope rule body, regardless of `paths`, is concatenated
    /// into one flat `agents_md` block — the identical shape as
    /// `GrokSpawnPayload::unscoped_path_rules`, which this field mirrors.
    /// Before this field existed, Kimi silently dropped the identical
    /// disclosure Grok already made for the same construct — both now
    /// populate from the one shared `flatten::is_real_path_restriction`
    /// predicate so they cannot drift against each other.
    pub unscoped_path_rules: BTreeSet<String>,
}

/// Grok CLI sandbox profile — `--sandbox <profile>` argv value
/// (report 14 §5.2). Default is the safe (non-`Off`) choice, matching
/// `SandboxMode`/`ApprovalMode`'s "defaults are the most restrictive
/// option" convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum GrokSandboxProfile {
    Off,
    Workspace,
    #[default]
    ReadOnly,
    Strict,
    Devbox,
}

impl GrokSandboxProfile {
    pub const fn as_str(&self) -> &'static str {
        match self {
            GrokSandboxProfile::Off => "off",
            GrokSandboxProfile::Workspace => "workspace",
            GrokSandboxProfile::ReadOnly => "read-only",
            GrokSandboxProfile::Strict => "strict",
            GrokSandboxProfile::Devbox => "devbox",
        }
    }
}

/// Grok CLI `--permission-mode` argv value. NOTE (report 14 §5.1): only
/// `bypass-permissions` and `default` are actually honored by the flag —
/// `dontAsk`/`accept-edits`/`plan` are accepted but silently do nothing.
/// Deny-by-default MUST instead be set via `GrokSpawnPayload::default_mode`
/// (`defaultMode` in a `settings.json`). Default here is the safe choice
/// (does NOT bypass permission checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum GrokPermissionMode {
    #[default]
    Default,
    BypassPermissions,
}

impl GrokPermissionMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            GrokPermissionMode::Default => "default",
            GrokPermissionMode::BypassPermissions => "bypass-permissions",
        }
    }
}

/// Grok CLI (xAI) spawn payload (harness-decomposition report 14 §7.2).
///
/// Unlike Kimi, Grok has a real rules-directory primitive AND native
/// schema-constrained output (`--json-schema`) — strictly stronger FR-CL-01
/// enforcement than any other Surface's prompt directive (report 14 §6.3).
/// Materialization target is ALWAYS the csq-owned per-slot home
/// (`native_home_path(base, slot, Surface::Grok)`, pointed at by
/// `GROK_HOME`) — csq MUST NOT write into the user's repo tree; `AGENTS.md`
/// / `CLAUDE.md` / `.claude/` there are shared, user-owned, cross-harness
/// files (report 14 §7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrokSpawnPayload {
    /// Body of `$GROK_HOME/AGENTS.md` — global scope, lowest precedence
    /// (a repo-root `AGENTS.md` outranks it on conflict; report 14 §7.1
    /// residual risk, stated honestly rather than engineered around).
    /// Built by the same `flatten`/`render_sections` pipeline as the other
    /// four Surfaces.
    pub agents_md: String,
    /// Rule IDs whose `paths` glob scope could not be honored and were
    /// therefore BROADENED to `agents_md`'s global scope — surfaced here
    /// rather than silently widened (report 14 §6.1 "Rules (path-scoped)").
    /// `.coc/` `paths:` frontmatter is never emitted into Grok's on-disk
    /// artifacts by this translator (the shared `render_sections` pipeline
    /// never renders `FlatArtifact.paths` into prose), so the literal-text
    /// pollution report 14 G7 documents (verified against a project's OWN
    /// `.claude/rules/*.md`, which Grok reads independently of csq) does
    /// not apply to csq-authored output — but the SCOPE loss is real and is
    /// exactly what this field records.
    pub unscoped_path_rules: BTreeSet<String>,
    /// `[permission]` deny rules, rendered `MCPTool(server__tool)` —
    /// NOT the Claude Code `mcp__server__tool` spelling, which never
    /// matches (report 14 §7.4 item 3). Reserved: `CocSet` carries no
    /// permission-rule kind yet; always empty from `grok::translate`,
    /// mirroring `CodexSpawnPayload::mcp_filter`.
    pub permission_deny: BTreeSet<String>,
    /// `[permission]` allow rules, same rendering + reservation note as
    /// `permission_deny`.
    pub permission_allow: BTreeSet<String>,
    /// `[compat.claude]` / `[compat.cursor]` cells written into
    /// `config.toml`. `true` = every REAL cell (`skills`, `rules`, `agents`,
    /// `mcps`, `hooks`, `sessions` — report 14 §5.3 line 524) disabled, for
    /// deterministic per-slot isolation (report 14 §7.4 item 6).
    ///
    /// Three bleed paths are NOT suppressible by ANY cell (round-13 review
    /// HIGH-2 — corrected from a prior doc claiming only the first):
    /// - `~/.claude/settings.json` permission rules merge into every Grok
    ///   slot regardless (report 14 §5.3 — no `[compat.claude] permissions`
    ///   cell exists at all).
    /// - Subagent discovery from `.claude/agents/`/`~/.claude/agents/`. The
    ///   `agents` cell NAME is a false friend: it gates only the
    ///   CLAUDE.md/CLAUDE.local.md instruction-file scan
    ///   (`05-configuration.md:382`), NOT subagent loading — report 14 §8
    ///   item 1: "I found no cell that does [gate subagent discovery]."
    /// - Plugin/marketplace state (`~/.claude/plugins/installed_plugins.json`,
    ///   `known_marketplaces.json`) — report 14 §3.2 row "Plugins": "(not
    ///   cell-gated)".
    pub compat_cells_disabled: bool,
    /// `--sandbox <profile>` argv value.
    pub sandbox_profile: GrokSandboxProfile,
    /// `--permission-mode` argv value. See `GrokPermissionMode`'s doc for
    /// the flag's honored-vs-ignored split.
    pub permission_mode: GrokPermissionMode,
    /// `defaultMode` written to `$GROK_HOME/settings.json` — the only path
    /// that genuinely enables deny-by-default (report 14 §5.1, §7.2).
    pub default_mode: Option<String>,
    /// `--json-schema <SCHEMA>` argv value — the FR-CL-01 envelope
    /// (`{rule_id, decision, rationale}`) as a JSON Schema document. Grok
    /// constrains DECODING to this schema (report 14 §6.3), strictly
    /// stronger than every other Surface's prompt-only directive.
    pub json_schema: Option<String>,
    /// Belt-and-braces prompt directive (`--rules <directive>`), same
    /// Surface-agnostic body as the other four payloads.
    pub output_schema_directive: Option<String>,
    /// `$GROK_HOME/hooks/*.json` — one file per hook, keyed by name.
    /// Global-scope hooks are ALWAYS TRUSTED, no folder-trust gate needed
    /// (report 14 §3.2 row "Hooks"). Reserved: `CocSet` carries no
    /// hook-artifact kind yet, so `grok::translate` always emits an empty
    /// map here — mirrors `KimiSpawnPayload::hooks`'s identical
    /// reservation shape. Round-13 review MED-4: report 14's own payload
    /// sketch (§7.2) already specified this field; it was silently dropped
    /// when `GrokSpawnPayload` was implemented, even though Kimi's sibling
    /// `hooks`/`permission_rules` fields were both kept reserved-but-typed.
    pub hooks: BTreeMap<String, serde_json::Value>,
    /// MCP filter forwarded to the capability layer's MCP gate. Always
    /// `McpFilter::default()` from `grok::translate`, same as the other
    /// four Surfaces' `mcp_filter` field.
    pub mcp_filter: McpFilter,
    /// IDs of artifacts that contributed to this payload.
    pub contributing_ids: BTreeSet<String>,
}

/// Sum type over the five Surface payloads. Returned by the
/// dispatcher in `coc/translate/mod.rs::translate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "surface", rename_all = "kebab-case")]
pub enum SpawnPayload {
    ClaudeCode(ClaudeSpawnPayload),
    Codex(CodexSpawnPayload),
    Gemini(GeminiSpawnPayload),
    Kimi(KimiSpawnPayload),
    Grok(GrokSpawnPayload),
}

impl SpawnPayload {
    pub fn contributing_ids(&self) -> &BTreeSet<String> {
        match self {
            SpawnPayload::ClaudeCode(p) => &p.contributing_ids,
            SpawnPayload::Codex(p) => &p.contributing_ids,
            SpawnPayload::Gemini(p) => &p.contributing_ids,
            SpawnPayload::Kimi(p) => &p.contributing_ids,
            SpawnPayload::Grok(p) => &p.contributing_ids,
        }
    }

    /// The per-Surface system-prompt text field — the single flattened
    /// `## Rules / ## Agents / ## Skills / ## Commands` prose each Surface
    /// delivers through its native system-prompt mechanism
    /// (`system_prompt_append` / `instructions` / `system_instruction` /
    /// `agents_md`). This is the field the capability-layer scaffold stage
    /// (CU1b) lifts for the live spawn, and the field CU5's byte-parity
    /// golden compares.
    /// Note: the `output_schema_directive` is a SEPARATE field and is NOT
    /// included here — the live spawn appends it (class-gated) downstream;
    /// `csq translate --json` exposes it as its own key.
    pub fn system_text(&self) -> &str {
        match self {
            SpawnPayload::ClaudeCode(p) => &p.system_prompt_append,
            SpawnPayload::Codex(p) => &p.instructions,
            SpawnPayload::Gemini(p) => &p.system_instruction,
            SpawnPayload::Kimi(p) => &p.agents_md,
            SpawnPayload::Grok(p) => &p.agents_md,
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
        assert_eq!(KimiDecision::default(), KimiDecision::Deny);
        assert_eq!(KimiScope::default(), KimiScope::User);
        assert_eq!(GrokSandboxProfile::default(), GrokSandboxProfile::ReadOnly);
        assert_eq!(GrokPermissionMode::default(), GrokPermissionMode::Default);
    }

    #[test]
    fn kimi_hook_event_as_str_matches_vendor_schema_names() {
        // report 13 §4.2 HOOK_EVENT_TYPES$1 — exact casing, exact spelling.
        //
        // GROUND TRUTH, EXHAUSTIVE. The sibling test in `kimi_merge.rs`
        // (`serde_wire_names_match_as_str_for_all_hook_events`) covers all 16
        // variants but only proves serde == as_str — a CONSISTENCY check
        // between two csq-authored representations. Transposing two adjacent
        // variants in BOTH the `#[serde(rename)]` and the `as_str` arm keeps
        // that test green while shipping the wrong wire string to Kimi, whose
        // `HookDefSchema` is `.strict()` and would reject or misfire the hook.
        // Only a literal table catches that, and only an exhaustive one
        // catches it for every variant.
        //
        // The `match` is deliberate: a NEW variant fails to compile here
        // rather than silently shipping unpinned. Do not replace it with a
        // lookup over a list.
        fn expected(v: KimiHookEvent) -> &'static str {
            match v {
                KimiHookEvent::PreToolUse => "PreToolUse",
                KimiHookEvent::PostToolUse => "PostToolUse",
                KimiHookEvent::PostToolUseFailure => "PostToolUseFailure",
                KimiHookEvent::PermissionRequest => "PermissionRequest",
                KimiHookEvent::PermissionResult => "PermissionResult",
                KimiHookEvent::UserPromptSubmit => "UserPromptSubmit",
                KimiHookEvent::Stop => "Stop",
                KimiHookEvent::StopFailure => "StopFailure",
                KimiHookEvent::Interrupt => "Interrupt",
                KimiHookEvent::SessionStart => "SessionStart",
                KimiHookEvent::SessionEnd => "SessionEnd",
                KimiHookEvent::SubagentStart => "SubagentStart",
                KimiHookEvent::SubagentStop => "SubagentStop",
                KimiHookEvent::PreCompact => "PreCompact",
                KimiHookEvent::PostCompact => "PostCompact",
                KimiHookEvent::Notification => "Notification",
            }
        }

        let all = [
            KimiHookEvent::PreToolUse,
            KimiHookEvent::PostToolUse,
            KimiHookEvent::PostToolUseFailure,
            KimiHookEvent::PermissionRequest,
            KimiHookEvent::PermissionResult,
            KimiHookEvent::UserPromptSubmit,
            KimiHookEvent::Stop,
            KimiHookEvent::StopFailure,
            KimiHookEvent::Interrupt,
            KimiHookEvent::SessionStart,
            KimiHookEvent::SessionEnd,
            KimiHookEvent::SubagentStart,
            KimiHookEvent::SubagentStop,
            KimiHookEvent::PreCompact,
            KimiHookEvent::PostCompact,
            KimiHookEvent::Notification,
        ];
        assert_eq!(all.len(), 16, "vendor schema has 16 hook events");

        for v in all {
            // TOML channel (`as_str`) against the literal.
            assert_eq!(v.as_str(), expected(v), "as_str ground truth for {v:?}");
            // JSON channel (`#[serde(rename)]`) against the SAME literal —
            // pinning both to ground truth is what a transposition cannot
            // survive.
            assert_eq!(
                serde_json::to_value(v).unwrap(),
                serde_json::Value::String(expected(v).to_string()),
                "serde wire ground truth for {v:?}"
            );
        }

        // Distinctness: a transposition that somehow satisfied both channels
        // would still have to collide, and a copy-paste that duplicates a
        // literal across two arms is caught here.
        let mut seen = std::collections::BTreeSet::new();
        for v in all {
            assert!(
                seen.insert(v.as_str()),
                "duplicate wire string {:?} — two variants map to one event",
                v.as_str()
            );
        }
    }

    /// Ground truth for the two remaining Kimi wire enums. Same reasoning as
    /// the hook-event test: `KimiDecision::Deny` and `KimiScope::Project`
    /// were the only values incidentally pinned by merge tests (which assert
    /// success/failure, not the rendered literal), so `Allow`,
    /// `TurnOverride`, `SessionRuntime`, and `User` shipped unpinned.
    #[test]
    fn kimi_decision_and_scope_as_str_match_vendor_schema_names() {
        // report 13 §H7 PermissionRuleSchema$1.
        fn expected_decision(d: KimiDecision) -> &'static str {
            match d {
                KimiDecision::Allow => "allow",
                KimiDecision::Deny => "deny",
            }
        }
        fn expected_scope(s: KimiScope) -> &'static str {
            match s {
                KimiScope::TurnOverride => "turn-override",
                KimiScope::SessionRuntime => "session-runtime",
                KimiScope::Project => "project",
                KimiScope::User => "user",
            }
        }

        for d in [KimiDecision::Allow, KimiDecision::Deny] {
            assert_eq!(d.as_str(), expected_decision(d), "decision {d:?}");
            assert_eq!(
                serde_json::to_value(d).unwrap(),
                serde_json::Value::String(expected_decision(d).to_string()),
                "decision serde wire {d:?}"
            );
        }

        for s in [
            KimiScope::TurnOverride,
            KimiScope::SessionRuntime,
            KimiScope::Project,
            KimiScope::User,
        ] {
            assert_eq!(s.as_str(), expected_scope(s), "scope {s:?}");
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::Value::String(expected_scope(s).to_string()),
                "scope serde wire {s:?}"
            );
        }

        // Vendor schema defaults (report 13 §H7): deny-by-default decision,
        // user-scoped by default.
        assert_eq!(KimiDecision::default(), KimiDecision::Deny);
        assert_eq!(KimiScope::default(), KimiScope::User);
    }

    #[test]
    fn grok_sandbox_profile_str_is_kebab_case() {
        assert_eq!(GrokSandboxProfile::Off.as_str(), "off");
        assert_eq!(GrokSandboxProfile::ReadOnly.as_str(), "read-only");
        assert_eq!(GrokSandboxProfile::Strict.as_str(), "strict");
    }

    #[test]
    fn grok_permission_mode_str_matches_argv_values() {
        assert_eq!(GrokPermissionMode::Default.as_str(), "default");
        assert_eq!(
            GrokPermissionMode::BypassPermissions.as_str(),
            "bypass-permissions"
        );
    }

    /// `contributing_ids` and `system_text` dispatch — the two accessors
    /// every downstream consumer (audit trail, CU5 byte-parity golden)
    /// relies on — MUST reach the Kimi/Grok variants.
    #[test]
    fn spawn_payload_dispatch_reaches_kimi_and_grok() {
        let mut kimi_ids = BTreeSet::new();
        kimi_ids.insert("RULE-X".to_string());
        let kimi_payload = SpawnPayload::Kimi(KimiSpawnPayload {
            agents_md: "kimi text".to_string(),
            contributing_ids: kimi_ids.clone(),
            ..Default::default()
        });
        assert_eq!(kimi_payload.contributing_ids(), &kimi_ids);
        assert_eq!(kimi_payload.system_text(), "kimi text");

        let mut grok_ids = BTreeSet::new();
        grok_ids.insert("RULE-Y".to_string());
        let grok_payload = SpawnPayload::Grok(GrokSpawnPayload {
            agents_md: "grok text".to_string(),
            contributing_ids: grok_ids.clone(),
            ..Default::default()
        });
        assert_eq!(grok_payload.contributing_ids(), &grok_ids);
        assert_eq!(grok_payload.system_text(), "grok text");
    }
}
