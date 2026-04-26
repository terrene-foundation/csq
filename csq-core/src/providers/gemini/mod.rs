//! Gemini surface module — third surface alongside `ClaudeCode` and
//! `Codex`. Lands in PR-G2a as Surface-independent scaffolding using
//! a const placeholder for the surface tag; PR-G2b flips to the
//! `Surface::Gemini` enum variant once PR-G1 ships it.
//!
//! # Why a separate module from `codex`
//!
//! Gemini's auth model differs fundamentally from Codex/Anthropic:
//!
//! - **API-key only.** No OAuth lifecycle, no refresh subsystem, no
//!   daemon prerequisite for spawn (INV-P02 inverted; see
//!   `specs/07-provider-surface-dispatch.md` §7.2.3 + journal 0001).
//! - **Encryption-at-rest.** API keys live in `platform::secret`,
//!   not on the filesystem. New primitive sole-owned by Gemini per
//!   H8 in the implementation plan.
//! - **Event-driven quota.** No `GET /usage` endpoint exists for
//!   Gemini API keys. Quota is reconstructed from spawn-counter +
//!   429 parse + per-response `modelVersion` capture, persisted via
//!   the CLI-durable NDJSON event log (`spec 05 §5.8.1`).
//! - **7-layer ToS-guard.** Google's ToS prohibits routing
//!   subscription OAuth through third-party tools; csq actively
//!   defends against accidental OAuth fall-through with EP1-EP7
//!   (no disable knob, per C-CR1).
//!
//! # PR-G2a scope (this PR)
//!
//! - [`keyfile`] — Vertex SA JSON path validation + 0o400 enforcement
//! - [`settings`] — handle-dir `.gemini/settings.json` template generation
//! - [`probe`] — EP1 drift detector (`reassert_api_key_selected_type`)
//! - [`spawn`] — env_clear + allowlist + pre-spawn .env scan
//!   (EP2/EP3/EP6) + `setrlimit(RLIMIT_CORE, 0)` on Unix children
//! - [`capture`] — event type definitions (consumer lands in PR-G3)
//! - [`tos_guard`] — EP4 versioned whitelist + sentinel detector
//!
//! # Out of scope for PR-G2a (deferred per implementation plan)
//!
//! - PR-G3: NDJSON event log + daemon consumer + IPC types
//! - PR-G4: csq-cli `setkey gemini` / `models switch` / `swap` paths
//! - PR-G5: desktop UI (AddAccountModal, ChangeModelModal)
//!
//! # Resolved by PR-G1 (this build)
//!
//! - `Surface::Gemini` enum variant exists at
//!   [`crate::providers::catalog::Surface::Gemini`]; the
//!   [`SURFACE_GEMINI`] const now resolves to `Surface::Gemini.as_str()`
//!   instead of a string literal.
//! - Per-site dispatch (refresher skip, swap refusal, model-switch
//!   refusal-with-message) is wired across the workspace.

pub mod capture;
pub mod event_id;
pub mod keyfile;
pub mod probe;
pub mod provisioning;
pub mod settings;
pub mod spawn;
pub mod tos;
pub mod tos_guard;

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

/// `gemini-cli` minor release the EP4 ToS-guard whitelist is pinned
/// to. Bump alongside any whitelist changes — the version-mismatch
/// dialog (PR-G3) compares this against the running binary's
/// `--version` output.
pub const PINNED_GEMINI_CLI_VERSION: &str = "0.38";
