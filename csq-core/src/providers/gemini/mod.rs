//! Gemini surface module — third surface alongside `ClaudeCode` and
//! `Codex`. csq spawns the official `gemini` CLI as a subprocess;
//! authentication is whatever the user has configured the gemini CLI
//! for (Code Assist OAuth, AI Studio API key, or Vertex SA).
//!
//! # ToS posture (corrected 2026-05-06 per an internal journal entry)
//!
//! Earlier revisions of this module described a 7-layer "EP1-EP7"
//! defense that pinned `security.auth.selectedType = "gemini-api-key"`
//! and killed gemini-cli processes that hit OAuth markers in stderr.
//! That posture rested on a misreading of `gemini-cli/docs/resources/
//! tos-privacy.md` (the cited prohibition targets reimplementations
//! like OpenClaw that bypass the official CLI; csq spawns the official
//! `gemini` binary as a subprocess, structurally identical to running
//! it under tmux, nohup, or a shell alias) and on cited issue numbers
//! (#20632, #22970) that do not resolve in the upstream repo. The
//! runtime enforcement has been removed. csq treats Gemini the same
//! way it treats Claude and Codex: spawn the official CLI, let it
//! handle auth.
//!
//! # Why a separate module from `codex`
//!
//! Gemini's spawn machinery differs in shape from Anthropic / Codex:
//!
//! - **No daemon prerequisite for spawn** (INV-P02 inverted; see
//!   `specs/07-provider-surface-dispatch.md` §7.5 + an internal journal entry).
//!   API keys are flat and long-lived; OAuth refresh is gemini-cli's
//!   own internal concern.
//! - **Encryption-at-rest for API keys.** When a user binds a slot
//!   to AI Studio API-key mode, the key lives in `platform::secret`,
//!   not on the filesystem.
//! - **Event-driven quota signal.** API-key slots have no public
//!   usage endpoint; quota is reconstructed from spawn-counter +
//!   429 parse + per-response `modelVersion` capture, persisted via
//!   the CLI-durable NDJSON event log (`spec 05 §5.8.1`). Code Assist
//!   OAuth slots may add the `retrieveUserQuota` poll path in
//!   journal-0046 Phase B'.
//!
//! # Modules
//!
//! - [`keyfile`] — Vertex SA JSON path validation + 0o400 enforcement
//! - [`settings`] — handle-dir `.gemini/settings.json` template generation
//! - [`probe`] — settings drift detector (rewrites `model.name` /
//!   `system_instruction` if they drift; writes
//!   `security.auth.selectedType` ONLY for slots bound to an API key)
//! - [`spawn`] — `env_clear` + allowlist + pre-spawn `.env` scan
//!   (now framed as a generic safety guard against cross-account
//!   credential leak, not a ToS defense) + `setrlimit(RLIMIT_CORE, 0)`
//!   on Unix children
//! - [`capture`] — event type definitions (consumer lands in PR-G3)
//! - [`tos`] — informational disclosure marker (one-time per user
//!   acknowledgement of how csq wraps gemini-cli)

pub mod capture;
pub mod code_assist_quota;
pub mod event_id;
pub mod keyfile;
pub mod oauth_flow;
pub mod oauth_login;
pub mod probe;
pub mod provisioning;
pub mod settings;
pub mod spawn;
pub mod tos;

/// Surface tag for [`platform::secret::SlotKey`] and audit-log
/// entries. Resolves to [`Surface::Gemini::as_str()`] now that PR-G1
/// has shipped the enum variant; the placeholder shape is kept so
/// existing PR-G2a call sites (`spawn`, `capture`, `keyfile`) do not
/// need to import the enum directly.
///
/// [`platform::secret::SlotKey`]: crate::platform::secret::SlotKey
/// [`Surface::Gemini::as_str()`]: crate::providers::catalog::Surface::as_str
pub const SURFACE_GEMINI: &str = crate::providers::catalog::Surface::Gemini.as_str();

/// The CLI binary name csq spawns. Centralized so the spawn-banning
/// lint test can grep exactly one place for the string. Any future
/// direct `std::process::Command` invocation of this binary outside
/// of [`spawn`] is a review failure per PR-G2a "lint" gate. See
/// `tests/no_direct_gemini_spawn.rs` for the structural enforcement.
pub const GEMINI_CLI_BINARY: &str = "gemini";

/// `gemini-cli` minor release csq is QA'd against. Bumped when
/// upstream changes the spawn / settings / output contract in a way
/// csq's pre-spawn pipeline cares about. Used by the version-mismatch
/// dialog (PR-G3) to surface a warning if the running binary differs.
pub const PINNED_GEMINI_CLI_VERSION: &str = "0.38";
