//! Gemini slot provisioning — `csq setkey gemini` writes a binding
//! marker file that csq-cli's `run` and the daemon's IPC handler use
//! to authoritatively detect a Gemini-bound slot.
//!
//! # Why a separate marker file
//!
//! Three other surfaces use the same shape:
//!
//! - ClaudeCode → `credentials/<N>.json`
//! - Codex → `credentials/codex-<N>.json`
//! - Gemini → `credentials/gemini-<N>.json` (this file)
//!
//! `canonical_path_for(base_dir, slot, Surface::Gemini)` (PR-G1)
//! already returns this path; PR-G4a finally writes content there.
//!
//! Unlike Anthropic and Codex, the Gemini binding marker carries
//! **no secret material** — the API key lives in the `platform::secret`
//! vault, the Vertex SA JSON lives at the path the operator points
//! us at. The marker is metadata: how to authenticate (API key vs
//! Vertex SA), where to find the Vertex SA file (if applicable), and
//! the model the slot was provisioned with.
//!
//! # Why not the Vault as the dispatch signal
//!
//! [`csq run`] dispatches on a filesystem stat — exactly one
//! `symlink_metadata` syscall per launch. Routing dispatch through
//! the vault would add a Keychain prompt latency budget on every
//! `csq run`, and would force the daemon's IPC slot-existence check
//! (PR-G3 H2 resolution) to read the vault on every event POST.
//! Cheap stat-only dispatch is the right cost shape.
//!
//! # Atomicity
//!
//! The marker is written via `unique_tmp_path → secure_file →
//! atomic_replace` — same pipeline as every other credential write
//! per `rules/security.md` §4 + §5a. Partial failures clean up the
//! tmp file before propagating the error so the umask-default tmp
//! does not linger on disk (PR-G3 redteam B2 pattern).
//!
//! [`csq run`]: https://github.com/terrene-foundation/csq/blob/main/csq-cli/src/commands/run.rs

use crate::credentials::file::canonical_path_for;
use crate::error::PlatformError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::platform::secret::{SecretError, SlotKey, Vault};
use crate::providers::catalog::Surface;
use crate::providers::gemini::SURFACE_GEMINI;
use crate::types::AccountNum;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Schema version for the binding marker file. Bump on any
/// non-backward-compatible field change so the reader can refuse
/// older clients gracefully.
pub const BINDING_SCHEMA_VERSION: u32 = 1;

/// How a Gemini slot authenticates. The three modes are mutually
/// exclusive — a slot is either AI Studio API key (cleartext kept in
/// the vault), Vertex AI service account (JSON file at a path the
/// operator owns), or Code Assist OAuth (gemini-cli owns the OAuth
/// tokens at `~/.gemini/oauth_creds.json`; csq is hands-off).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AuthMode {
    /// AI Studio API key. The key itself is in the platform-native
    /// secret vault under `SlotKey { surface: Gemini, account: N }`;
    /// the marker carries no key material.
    ApiKey,
    /// Vertex AI service account JSON. The marker carries the
    /// absolute path the operator pointed `--vertex-sa-json` at;
    /// `spawn_gemini` sets `GOOGLE_APPLICATION_CREDENTIALS` to this
    /// path on exec.
    VertexSa {
        /// Absolute path to the Vertex SA JSON. Caller validates
        /// `is_file()` + `0o400`-or-stricter at provisioning time.
        path: PathBuf,
    },
    /// Code Assist OAuth (Gemini Code Assist subscription). gemini-cli
    /// owns the OAuth tokens at `~/.gemini/oauth_creds.json`; csq does
    /// NOT manage refresh, does NOT write a `selectedType` pin into
    /// the handle-dir `settings.json`, and lets gemini-cli's auto-
    /// discovery pick up the credentials. The marker carries no
    /// payload — its presence is the signal. Provisioning shells out
    /// to `gemini auth login` (per `feedback_delegate_to_reference_client`
    /// memory: gemini-cli is the reference client; csq does not
    /// reimplement the OAuth flow).
    ///
    /// Stage 2 of an internal journal entry added this variant. v=1 binding markers
    /// remain readable; only NEW slots can be provisioned in this
    /// mode. Old binaries (compiled before this variant) error on
    /// deserialize when reading a CodeAssistOAuth-mode marker —
    /// downgrade-after-OAuth-provision loses access to that slot
    /// until the binary is upgraded again.
    ///
    /// `#[serde(rename = "code_assist_oauth")]` pins the JSON tag so
    /// the default `rename_all = "snake_case"` doesn't split `OAuth`
    /// into `o_auth` (which would produce `code_assist_o_auth`).
    #[serde(rename = "code_assist_oauth")]
    CodeAssistOAuth,
}

/// Persisted contents of `credentials/gemini-<N>.json`. JSON shape:
///
/// ```json
/// {
///   "v": 1,
///   "auth": { "mode": "api_key" },
///   "model_name": "auto",
///   "created_unix_secs": 1714000000
/// }
/// ```
///
/// or, for Vertex SA:
///
/// ```json
/// {
///   "v": 1,
///   "auth": { "mode": "vertex_sa", "path": "/abs/path/sa.json" },
///   "model_name": "auto",
///   "created_unix_secs": 1714000000
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeminiBinding {
    /// Schema version. Reader refuses unknown values.
    pub v: u32,
    /// API-key vs Vertex SA mode + Vertex path when applicable.
    #[serde(rename = "auth")]
    pub auth: AuthMode,
    /// Operator-selected model alias or concrete id (`auto`,
    /// `gemini-2.5-pro`, etc). `csq models switch` rewrites this
    /// field. The seed `settings.json` mirrors the same value so
    /// gemini-cli sees it.
    pub model_name: String,
    /// Provisioning timestamp — unix seconds. Diagnostic only;
    /// nothing in csq compares against it.
    pub created_unix_secs: u64,
}

impl GeminiBinding {
    /// Builds a fresh binding with `created_unix_secs` set to the
    /// current wall clock. Used by both provisioning paths.
    pub fn new(auth: AuthMode, model_name: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            v: BINDING_SCHEMA_VERSION,
            auth,
            model_name: model_name.into(),
            created_unix_secs: now,
        }
    }
}

/// Errors raised by provisioning operations. Distinct from
/// [`SecretError`] so callers can map provisioning-IO failures
/// (e.g. credentials dir missing) separately from vault failures.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Filesystem error writing or reading the marker.
    #[error("provisioning I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Atomic-replace primitive failed.
    #[error("atomic replace at {path}: {reason}")]
    AtomicReplace { path: PathBuf, reason: String },
    /// Vault operation failed during API-key provisioning.
    #[error(transparent)]
    Vault(#[from] SecretError),
    /// Marker JSON is malformed or refers to an unknown schema
    /// version. Caller treats the slot as unbound.
    #[error("malformed marker at {path}: {reason}")]
    Malformed { path: PathBuf, reason: String },
    /// Vertex SA JSON path is missing or not a regular file.
    #[error("vertex SA file invalid at {path}: {reason}")]
    VertexSaInvalid { path: PathBuf, reason: String },
    /// The `by_slot_identity[N]` recovery-channel write failed AFTER the
    /// binding marker was committed. The slot is functional (marker
    /// present, `csq run N` works) but temporarily un-recovery-labelled;
    /// the daemon backfill re-derives it from the live marker on the next
    /// reconcile. Distinct from `AtomicReplace` so the operator can tell a
    /// marker-write failure (slot unusable) from an identity-write failure
    /// (slot usable, recovery channel lags). Carries no path/secret body.
    #[error("by_slot_identity write failed (slot usable; backfill will repair): {reason}")]
    ProfilesIdentity { reason: String },
}

impl ProvisionError {
    /// Fixed-vocabulary tag for structured logging. Mirrors
    /// [`SecretError::error_kind_tag`] discipline.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            ProvisionError::Io { .. } => "gemini_provision_io",
            ProvisionError::AtomicReplace { .. } => "gemini_provision_atomic_replace",
            ProvisionError::Vault(e) => e.error_kind_tag(),
            ProvisionError::Malformed { .. } => "gemini_provision_malformed",
            ProvisionError::VertexSaInvalid { .. } => "gemini_provision_vertex_sa_invalid",
            ProvisionError::ProfilesIdentity { .. } => "gemini_provision_profiles_identity",
        }
    }

    /// User-actionable message with filesystem paths redacted via
    /// [`crate::cli_deps::sanitize::redact_path`]. Canonical mapper
    /// shared by the CLI (`csq setkey gemini ...` — see
    /// `csq/src/cli/commands/setkey.rs::map_provision_error`) and the
    /// desktop Tauri IPC boundary (`gemini_provision_api_key`,
    /// `gemini_provision_vertex_sa`, `gemini_provision_oauth` via
    /// `OauthLoginError::BindingWriteFailed`) so both editions stay in
    /// sync and neither duplicates the redaction logic —
    /// `rules/tauri-commands.md` MUST-3, an internal ticket.
    ///
    /// `Vault` is rendered via its own `Display` (no path fields —
    /// see [`crate::platform::secret::SecretError`]'s doc comment);
    /// callers that want the richer per-variant vault remediation text
    /// (e.g. the CLI's `map_vault_error`) should match on `Vault`
    /// themselves before falling back to this method.
    pub fn redacted_message(&self) -> String {
        use crate::cli_deps::sanitize::redact_path;
        match self {
            ProvisionError::Vault(v) => v.to_string(),
            // Wording mirrors the CLI's `--vertex-sa-json` flag name even
            // though the desktop UI has no such flag (it has a "Vertex SA
            // tab" — see `gemini_provision_api_key`'s doc comment). Kept
            // byte-identical to the CLI's reference implementation
            // (`csq/src/cli/commands/setkey.rs::map_provision_error`) so
            // both editions share one canonical mapper rather than two
            // texts that can silently drift.
            ProvisionError::VertexSaInvalid { path, reason } => {
                format!("--vertex-sa-json {} rejected: {reason}", redact_path(path))
            }
            ProvisionError::Malformed { path, reason } => {
                format!("binding marker {} is corrupt: {reason}", redact_path(path))
            }
            ProvisionError::Io { path, source } => {
                format!("provisioning I/O at {}: {source}", redact_path(path))
            }
            ProvisionError::AtomicReplace { path, reason } => {
                format!("atomic write at {}: {reason}", redact_path(path))
            }
            ProvisionError::ProfilesIdentity { reason } => format!(
                "by_slot_identity write failed (slot usable; backfill will repair): {reason}"
            ),
        }
    }
}

#[cfg(test)]
mod redacted_message_tests {
    use super::*;

    fn with_home<R>(home: &str, f: impl FnOnce() -> R) -> R {
        let _g = crate::platform::test_env::lock();
        let prior = std::env::var_os("HOME");
        std::env::set_var("HOME", home);
        let out = f();
        match prior {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        out
    }

    #[test]
    fn redacted_message_strips_path_on_io_variant() {
        with_home("/Users/jack", || {
            let err = ProvisionError::Io {
                path: std::path::PathBuf::from(
                    "/Users/jack/.claude/accounts/credentials/gemini-2.json",
                ),
                source: std::io::Error::other("disk full"),
            };
            let msg = err.redacted_message();
            assert!(!msg.contains("/Users/jack"), "path leaked: {msg}");
            assert!(msg.contains("~/.claude/accounts/credentials/gemini-2.json"));
            assert!(msg.contains("disk full"));
        });
    }

    #[test]
    fn redacted_message_strips_path_on_vertex_sa_invalid_variant() {
        with_home("/Users/jack", || {
            let err = ProvisionError::VertexSaInvalid {
                path: std::path::PathBuf::from("/Users/jack/secrets/sa.json"),
                reason: "not a regular file".to_string(),
            };
            let msg = err.redacted_message();
            assert!(!msg.contains("/Users/jack"), "path leaked: {msg}");
            assert!(msg.contains("~/secrets/sa.json"));
        });
    }

    #[test]
    fn redacted_message_strips_path_on_malformed_variant() {
        with_home("/Users/jack", || {
            let err = ProvisionError::Malformed {
                path: std::path::PathBuf::from(
                    "/Users/jack/.claude/accounts/credentials/gemini-6.json",
                ),
                reason: "invalid schema version".to_string(),
            };
            let msg = err.redacted_message();
            assert!(!msg.contains("/Users/jack"), "path leaked: {msg}");
            assert!(msg.contains("~/.claude/accounts/credentials/gemini-6.json"));
        });
    }

    #[test]
    fn redacted_message_profiles_identity_has_no_path_and_is_reassuring() {
        let err = ProvisionError::ProfilesIdentity {
            reason: "identity write timed out".to_string(),
        };
        let msg = err.redacted_message();
        assert!(msg.contains("slot usable"));
        assert!(msg.contains("identity write timed out"));
    }
}

/// Identity-class segment for a Gemini auth mode.
///
/// Pure function of the csq-owned binding marker — it NEVER reads the
/// Vertex SA JSON, gemini-cli's `~/.gemini/oauth_creds.json`, or the
/// platform vault. Embedding any of those would be the
/// `an internal workspace` an internal journal entry Finding 1 forbidden class
/// (external/fragile/daemon-refreshed identity source). The `match` is
/// exhaustive on purpose: a future `AuthMode` variant is a compile error
/// here, not a silent mislabel that diverges the backfill from the
/// synchronous write (FM-3a).
pub fn gemini_mode_class(auth: &AuthMode) -> &'static str {
    match auth {
        AuthMode::ApiKey => "apikey",
        AuthMode::VertexSa { .. } => "vertex",
        AuthMode::CodeAssistOAuth => "codeassist",
    }
}

/// The `by_slot_identity[N]` literal for a Gemini-bound slot:
/// `gemini-<N>/<mode-class>` (e.g. `gemini-13/apikey`).
///
/// This is the SINGLE producer consumed by BOTH the synchronous
/// provision write ([`write_gemini_identity`]) AND the daemon backfill
/// pass, so the two paths emit byte-identical literals (FM-3a). It fills
/// the reserved `<id>` position of spec 02 §INV-07's `gemini-<N>/<id>`
/// convention with the only marker-derivable `<id>`-shaped fact csq owns
/// (the auth mode). Identity-CLASS-stable always; identity-VALUE-stable
/// WITHIN a mode; the value changes only on a deliberate operator mode
/// re-provision — the inverse signal-interpretation of Codex's
/// non-stable label (spec 07 §7.2.2 FM-6 vs §7.2.3).
pub fn gemini_identity_label(slot: AccountNum, auth: &AuthMode) -> String {
    format!("gemini-{}/{}", slot.get(), gemini_mode_class(auth))
}

/// Writes `by_slot_identity[N]` for a freshly provisioned Gemini slot
/// under `ProfilesFileLock`.
///
/// Lock ordering (security review F1 / an internal journal entry D3): the caller MUST
/// NOT already hold `ProfilesFileLock` — this helper acquires it. The
/// daemon backfill holds the lock and only *reads* binding markers; it
/// never calls a `provision_*` path, so acquiring here introduces no
/// inversion. Mirrors the M7 `bind_provider_to_slot` shape
/// (`accounts/third_party.rs`): one lock window, identity written through
/// the existing `set_slot_identity` type-witness (no new tmp-write path,
/// no new §5a surface — security review F3).
///
/// Call ordering (FM-8 / security F1 rollback-order): callers invoke this
/// AFTER `write_binding` (marker FIRST, identity LAST). A crash between
/// leaves the slot *bound-but-unidentified* (daemon backfill re-derives
/// the literal from the live marker) — NEVER *identified-but-unbound* (a
/// phantom launchable-looking identity for an unbound slot).
fn write_gemini_identity(
    base_dir: &Path,
    slot: AccountNum,
    auth: &AuthMode,
) -> Result<(), ProvisionError> {
    // Fixed-vocabulary `reason` ONLY — never `{e}`. The lock error and
    // `ConfigError`'s Display both carry the absolute profiles.json path
    // (`/Users/<user>/.claude/accounts/.profiles.json`), which would leak
    // the OS username + home-dir layout into CLI stderr and into the
    // `profiles.json` round-trip. security.md §2 + round-0 security review
    // F4 (the error variant is deliberately path-free; do not defeat it by
    // interpolating a path-bearing inner error here). The structured log
    // discriminant is `error_kind_tag()` = "gemini_provision_profiles_identity".
    let lock =
        crate::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir).map_err(|_e| {
            ProvisionError::ProfilesIdentity {
                reason: "profiles lock unavailable".into(),
            }
        })?;
    let label = gemini_identity_label(slot, auth);
    crate::accounts::profiles::set_slot_identity(&lock, base_dir, slot.get(), &label).map_err(
        |_e| ProvisionError::ProfilesIdentity {
            reason: "profiles.json write failed".into(),
        },
    )
}

impl From<PlatformError> for ProvisionError {
    fn from(value: PlatformError) -> Self {
        ProvisionError::AtomicReplace {
            path: PathBuf::new(),
            reason: value.to_string(),
        }
    }
}

/// Returns the marker path for a given slot. Thin wrapper over
/// [`canonical_path_for`] that pins the `Surface::Gemini` argument
/// so callers do not have to import the enum.
pub fn binding_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    canonical_path_for(base_dir, slot, Surface::Gemini)
}

/// Whether `slot` has a Gemini binding marker. Single
/// `symlink_metadata` syscall — no JSON parse, no vault touch.
/// Treats a dangling symlink at the marker path as "bound" (same
/// posture as `is_codex_bound_slot` per FR-CLI-05 / an internal journal entry).
pub fn is_gemini_bound_slot(base_dir: &Path, slot: AccountNum) -> bool {
    std::fs::symlink_metadata(binding_path(base_dir, slot)).is_ok()
}

/// True iff slot has a spawn-admissible Gemini marker
/// (`is_gemini_bound_slot`) whose binding does NOT parse (corrupt JSON
/// / newer schema / unreadable). Single definition shared by
/// `csq doctor` and `csq probe --all` (an internal ticket / an internal ticket). NOT called from
/// `probe_slot` — that path reads the binding once and matches the
/// Result directly.
pub fn is_gemini_corrupt_bound(base_dir: &Path, slot: AccountNum) -> bool {
    is_gemini_bound_slot(base_dir, slot) && read_binding(base_dir, slot).is_err()
}

/// Reads and parses the binding marker. Returns
/// [`ProvisionError::Io`] with `NotFound` when the marker is absent
/// (caller should match on the source kind to distinguish unbound
/// from corrupted).
pub fn read_binding(base_dir: &Path, slot: AccountNum) -> Result<GeminiBinding, ProvisionError> {
    let path = binding_path(base_dir, slot);
    let raw = std::fs::read_to_string(&path).map_err(|source| ProvisionError::Io {
        path: path.clone(),
        source,
    })?;
    let binding: GeminiBinding =
        serde_json::from_str(&raw).map_err(|e| ProvisionError::Malformed {
            path: path.clone(),
            reason: format!("json parse: {e}"),
        })?;
    if binding.v != BINDING_SCHEMA_VERSION {
        return Err(ProvisionError::Malformed {
            path,
            reason: format!(
                "unknown schema version {} (expected {})",
                binding.v, BINDING_SCHEMA_VERSION
            ),
        });
    }
    Ok(binding)
}

/// Names the POLLING regime an auth mode implies, which is what the
/// quota row's shape depends on — not the auth mode itself.
///
/// `CodeAssistOAuth` slots are polled on a cadence by
/// `daemon::usage_poller::gemini_oauth` (which enumerates slots by
/// reading each binding's auth mode) and get `kind: "utilization"`
/// rows. `ApiKey` / `VertexSa` slots are never polled — their rows are
/// written only when the operator's own gemini-cli traffic produces an
/// event, and carry `kind: "counter"` / `"unknown"`.
///
/// Compared at the DISCRIMINANT level on purpose: re-pointing
/// `VertexSa` at a different SA JSON, or re-running an OAuth login, is
/// not a regime change and must not discard a valid row (the
/// same-provider half of the third-party precedent below).
fn polls_on_a_cadence(auth: &AuthMode) -> bool {
    matches!(auth, AuthMode::CodeAssistOAuth)
}

/// Writes the binding marker atomically with 0o600 permissions.
/// Caller is responsible for vault writes (API-key mode) or path
/// validation (Vertex SA mode); this helper is otherwise purely the
/// marker write — with ONE deliberate side effect, below.
///
/// # Clears the slot's quota row when the polling regime changes
///
/// Rebinding a slot from `CodeAssistOAuth` to `ApiKey`/`VertexSa` (or
/// back) leaves a row written by the OLD regime in `quota.json`.
/// Nothing else ever rewrites it: `enumerate_oauth_mode_slots` stops
/// returning the slot the moment its binding is no longer OAuth, so
/// the cadence poller goes silent, and the event path only writes when
/// the operator's own gemini-cli traffic produces an event — which on
/// an idle-but-healthy slot may be hours or days away.
///
/// The frozen row keeps `kind: "utilization"`, so
/// `quota::status::is_event_driven_row` (`surface == "gemini" &&
/// kind != "utilization"`) reads FALSE and the staleness classifier
/// runs the row's `updated_at` through the poll-cadence path. One hour
/// after the REBIND — not after any real loss of health — a perfectly
/// healthy idle ApiKey slot renders `stale <age>`. That is the same
/// false-positive class the staleness feature was written to
/// eliminate, reached through a rebind instead of a fresh slot.
///
/// Clearing here makes the slot show the honest "not yet polled"
/// state until its new regime writes a real row. This mirrors the
/// third-party precedent in `accounts::third_party::bind_provider_to_slot`
/// (a rebind to a DIFFERENT provider calls the same
/// `logout::remove_quota_entry`; a same-provider re-key preserves the
/// row) and lives HERE rather than in each caller because every
/// production provisioning path funnels through this one function —
/// per-caller enumeration is the drift this repo has been bitten by
/// repeatedly. Those callers are FOUR, not the three an earlier revision
/// of this comment claimed: `provision_api_key_via_vault`,
/// `provision_code_assist_oauth`, `provision_vertex_sa` and
/// `set_model_name`. The fourth only rewrites `model_name` on a binding it
/// has just read, so its regime is unchanged by construction and the clear
/// below is a guaranteed no-op there — which is exactly why routing it
/// through the same chokepoint costs nothing and keeps the invariant in
/// one place.
///
/// Best-effort and non-fatal: an unreadable or absent prior binding
/// means there is no established regime to have changed, so nothing is
/// cleared. The clear runs only AFTER the marker write succeeds, so a
/// failed write leaves both the marker and the quota row untouched.
pub fn write_binding(
    base_dir: &Path,
    slot: AccountNum,
    binding: &GeminiBinding,
) -> Result<(), ProvisionError> {
    let path = binding_path(base_dir, slot);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ProvisionError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    // Per-slot lock held across read-prior -> write -> clear.
    //
    // Without it the prior-regime read is unsynchronised, so two concurrent
    // provisioning calls for the SAME slot (a desktop double-submit, or CLI
    // and desktop racing) can both read the pre-race marker. The loser then
    // computes its regime change against a marker the winner has already
    // replaced, concludes nothing changed, and skips a clear that the REAL
    // transition required — leaving the stale row this function exists to
    // remove.
    //
    // Lock ORDER is binding -> quota, and only ever that way:
    // `remove_quota_entry` acquires the quota lock inside the region guarded
    // here and releases it before returning, and no path takes the quota lock
    // and then a binding lock (the OAuth poller reads this marker without
    // locking it — safe, because the marker is published by atomic rename, so
    // a reader sees the old or the new file, never a torn one). A `.lock`
    // suffix is also invisible to `enumerate_oauth_mode_slots`, which matches
    // only `gemini-<N>.json`.
    let lock_path = path.with_extension("lock");
    let _binding_guard = crate::platform::lock::lock_file(&lock_path).map_err(|e| {
        ProvisionError::AtomicReplace {
            path: lock_path.clone(),
            reason: format!("binding lock: {e}"),
        }
    })?;

    // Read the PRIOR regime before the marker is overwritten — after
    // the write there is no way to tell what it used to be. An absent
    // or unreadable prior binding yields None: no established regime,
    // so nothing to have changed.
    let previous_polls_on_a_cadence = read_binding(base_dir, slot)
        .ok()
        .map(|b| polls_on_a_cadence(&b.auth));

    let json =
        serde_json::to_string_pretty(binding).map_err(|e| ProvisionError::AtomicReplace {
            path: path.clone(),
            reason: format!("serialize: {e}"),
        })?;

    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProvisionError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProvisionError::AtomicReplace {
            path: path.clone(),
            reason: format!("secure_file: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProvisionError::AtomicReplace {
            path,
            reason: format!("atomic replace: {e}"),
        });
    }

    // Only after the marker is durably in place: see the
    // regime-change rationale on this function.
    if previous_polls_on_a_cadence.is_some_and(|prev| prev != polls_on_a_cadence(&binding.auth)) {
        crate::accounts::logout::remove_quota_entry(base_dir, slot);
    }

    Ok(())
}

/// Validates a Vertex SA JSON path before provisioning. Refuses
/// non-existent paths, non-regular files, and files larger than 64
/// KiB (real Vertex SA JSON is ~2 KiB; anything larger is suspect).
/// Does NOT parse the JSON — gemini-cli does that on first call.
pub fn validate_vertex_sa_path(path: &Path) -> Result<PathBuf, ProvisionError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|source| ProvisionError::VertexSaInvalid {
            path: path.to_path_buf(),
            reason: format!("stat: {source}"),
        })?;
    if !meta.file_type().is_file() {
        return Err(ProvisionError::VertexSaInvalid {
            path: path.to_path_buf(),
            reason: "not a regular file (symlinks rejected to prevent confused-deputy)".into(),
        });
    }
    if meta.len() > 64 * 1024 {
        return Err(ProvisionError::VertexSaInvalid {
            path: path.to_path_buf(),
            reason: format!("file too large ({} bytes; expected <= 64 KiB)", meta.len()),
        });
    }
    // Canonicalise to an absolute path so a future relative-path
    // CWD change cannot reroute the resolution.
    let abs = std::fs::canonicalize(path).map_err(|source| ProvisionError::VertexSaInvalid {
        path: path.to_path_buf(),
        reason: format!("canonicalize: {source}"),
    })?;
    Ok(abs)
}

/// Deletes the API-key vault entry for a slot, if and only if the slot is
/// currently bound in `ApiKey` mode.
///
/// - **ApiKey mode**: calls `vault.delete(slot_key)`. The vault contract
///   guarantees `delete` is idempotent — a `NotFound` from the vault is
///   treated as success (the key was already absent; the caller should
///   still remove the binding marker).
/// - **VertexSa mode**: no-op. Vertex SA slots hold no material in the
///   vault — the credential is the SA JSON file at the path stored in the
///   marker, which `logout_account` removes via `config-N/` deletion.
/// - **Absent marker**: no-op. If the marker is missing the slot was
///   never fully provisioned; no vault entry can exist.
///
/// Called by the desktop `remove_account` command BEFORE
/// `logout_account` deletes the binding marker. The marker deletion
/// by `logout_account` removes `credentials/gemini-<N>.json` as part
/// of the `config-N/` recursive removal — the vault delete MUST happen
/// first so the auth mode is still readable.
///
/// # Errors
///
/// Returns an error only when the vault is genuinely unavailable (not
/// merely `NotFound`). Callers should map this to a fixed "vault
/// unavailable" string per `security.md` MUST 2 — do NOT echo the
/// raw `SecretError` body.
pub fn delete_api_key_from_vault(
    base_dir: &Path,
    slot: AccountNum,
    vault: &dyn Vault,
) -> Result<(), SecretError> {
    // Read the binding marker to determine the auth mode. Missing marker →
    // slot was never fully bound → no vault entry to clean up.
    let binding = match read_binding(base_dir, slot) {
        Ok(b) => b,
        Err(ProvisionError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        // Malformed or unreadable marker: we cannot determine the auth
        // mode, so attempt a best-effort vault delete. This is safe —
        // `delete` is idempotent and the slot was going to be removed
        // anyway. Prefer erring on the side of cleaning up over leaving
        // a stale vault entry.
        Err(_) => {
            let slot_key = SlotKey {
                surface: SURFACE_GEMINI,
                account: slot,
            };
            return match vault.delete(slot_key) {
                Ok(()) => Ok(()),
                Err(SecretError::NotFound { .. }) => Ok(()),
                Err(e) => Err(e),
            };
        }
    };

    // Only ApiKey slots have vault material.
    match binding.auth {
        AuthMode::ApiKey => {
            let slot_key = SlotKey {
                surface: SURFACE_GEMINI,
                account: slot,
            };
            match vault.delete(slot_key) {
                Ok(()) => Ok(()),
                // Already absent — idempotent success.
                Err(SecretError::NotFound { .. }) => Ok(()),
                Err(e) => Err(e),
            }
        }
        // Vertex SA: credential is the SA JSON file, not in the vault.
        AuthMode::VertexSa { .. } => Ok(()),
        // Code Assist OAuth: tokens live in `~/.gemini/oauth_creds.json`
        // owned by gemini-cli. csq does not manage them; unbind only
        // removes the binding marker (handled by `unbind`).
        AuthMode::CodeAssistOAuth => Ok(()),
    }
}

/// Removes the binding marker. Does NOT touch the vault entry —
/// callers that want a full unbind invoke `Vault::delete` separately
/// so the audit log emits both events distinctly.
///
/// # Callers (enumerate on every addition — `sentinel-clearing-parity.md` MUST-1)
///
/// - [`crate::accounts::binding_guard::clear_detected_marker_binding`] — an
///   Anthropic or Codex OAuth login onto a Gemini-marked slot REPLACES the
///   binding; this clears the stale Gemini marker (captured pre-mint by
///   [`crate::accounts::binding_guard::detect_stale_marker_binding`], applied
///   only once the login has succeeded) so the slot does not carry two
///   bindings (GH an internal ticket).
/// - `csq logout <N>` sweeps this marker too, but via the surface-neutral
///   `ALL_SURFACES` loop in `accounts::logout::logout_account` (direct
///   `remove_file` on `canonical_path_for`), not through this function.
pub fn unbind(base_dir: &Path, slot: AccountNum) -> Result<(), ProvisionError> {
    let path = binding_path(base_dir, slot);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProvisionError::Io { path, source }),
    }
}

/// The taxonomy of what a slot is bound to. Moved to the surface-neutral
/// [`crate::accounts::binding_guard`] module (an internal journal entry For-Discussion #1)
/// and re-exported here for the callers that historically imported
/// `provisioning::BoundSurface`. The unified detector is
/// [`crate::accounts::binding_guard::detect_bound_surface`]; the Gemini
/// entry points refuse conflicts via
/// [`crate::accounts::binding_guard::refuse_if_slot_conflicts`] with
/// [`Surface::Gemini`] as the target.
pub use crate::accounts::binding_guard::BoundSurface;

/// Orchestrates AI Studio API-key provisioning from a desktop or CLI
/// caller. Sequence:
///
/// 1. `vault.set` writes the encrypted key under the canonical slot.
/// 2. [`write_binding`] writes the `credentials/gemini-<N>.json`
///    marker (api_key mode, `model_name = "auto"`).
/// 3. On marker write failure, the vault entry is rolled back via
///    `vault.delete` so the slot does not enter a half-bound state
///    (vault has key, but no marker → `csq run N` would refuse and
///    operator would see no obvious recovery path).
///
/// The caller is responsible for shape validation on `key` (e.g.
/// `AIza` prefix, length bounds) and for refusing cross-surface
/// conflicts via [`crate::accounts::binding_guard::refuse_if_slot_conflicts`]
/// (with [`Surface::Gemini`]) BEFORE invoking — this fn deliberately does NOT
/// re-check those so it stays unit testable in isolation.
pub fn provision_api_key_via_vault(
    base_dir: &Path,
    slot: AccountNum,
    key: &SecretString,
    vault: &dyn Vault,
) -> Result<(), ProvisionError> {
    let slot_key = SlotKey {
        surface: SURFACE_GEMINI,
        account: slot,
    };
    vault.set(slot_key, key)?;

    let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
    if let Err(e) = write_binding(base_dir, slot, &binding) {
        let _ = vault.delete(slot_key);
        return Err(e);
    }
    // Marker committed → identity LAST (FM-8). A failure here is NOT
    // rolled back: the slot is bound-and-usable; the daemon backfill
    // re-derives by_slot_identity from the live marker. Rolling back the
    // marker/vault on an identity-write failure would destroy a usable
    // binding to fix a lagging recovery label — the wrong trade.
    write_gemini_identity(base_dir, slot, &binding.auth)?;
    Ok(())
}

/// Orchestrates Code Assist OAuth provisioning. Writes the binding
/// marker with `auth = CodeAssistOAuth` and `model_name = "auto"`.
/// Carries no payload — gemini-cli owns the OAuth tokens at
/// `~/.gemini/oauth_creds.json` and csq is hands-off.
///
/// The caller (typically the desktop `gemini_provision_oauth` Tauri
/// command) is responsible for shelling out to `gemini auth login`
/// BEFORE this function — per `feedback_delegate_to_reference_client`,
/// gemini-cli is the reference client and csq does not reimplement the
/// OAuth flow. This function only records the binding once gemini-cli
/// has succeeded; if `gemini auth login` fails, the marker is not
/// written.
///
/// Stage 2 of an internal journal entry
pub fn provision_code_assist_oauth(
    base_dir: &Path,
    slot: AccountNum,
) -> Result<(), ProvisionError> {
    let binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
    write_binding(base_dir, slot, &binding)?;
    // Marker FIRST, identity LAST (FM-8).
    write_gemini_identity(base_dir, slot, &binding.auth)
}

/// Orchestrates Vertex SA provisioning. Validates the path
/// (regular file, ≤ 64 KiB, not a symlink, canonicalised), then
/// writes the binding marker with `model_name = "auto"`. Returns
/// the canonical absolute path that ended up in the marker — desktop
/// callers display this back to the user for confirmation.
pub fn provision_vertex_sa(
    base_dir: &Path,
    slot: AccountNum,
    sa_path: &Path,
) -> Result<PathBuf, ProvisionError> {
    let canon = validate_vertex_sa_path(sa_path)?;
    let binding = GeminiBinding::new(
        AuthMode::VertexSa {
            path: canon.clone(),
        },
        "auto",
    );
    write_binding(base_dir, slot, &binding)?;
    // Marker FIRST, identity LAST (FM-8).
    write_gemini_identity(base_dir, slot, &binding.auth)?;
    Ok(canon)
}

/// Atomically updates `model_name` inside the slot's binding marker.
/// Returns [`ProvisionError::Io`] with `NotFound` if the slot has no
/// Gemini binding (caller renders "run setkey gemini first"). The
/// drift detector picks up the new value on the next `csq run` /
/// session swap that hits this slot.
pub fn set_model_name(
    base_dir: &Path,
    slot: AccountNum,
    model: &str,
) -> Result<(), ProvisionError> {
    let mut binding = read_binding(base_dir, slot)?;
    binding.model_name = model.to_string();
    write_binding(base_dir, slot, &binding)
}

/// Static allowlist of model values the desktop UI's static picker
/// may submit. Mirrors FR-G-UI-02's enumeration:
///
/// - `auto` — synthetic literal, instructs gemini-cli to pick.
/// - `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.5-flash-lite`
///   — concrete catalog ids (see `providers::catalog`).
/// - `gemini-3-pro-preview` — preview tier; the UI shows a downgrade
///   warning when this is selected.
///
/// Used by the desktop `gemini_switch_model` command for boundary
/// validation. CLI callers continue to go through the catalog
/// (`models.rs::resolve_gemini_model`) which accepts user-friendly
/// aliases (`pro`, `flash`); the desktop submits canonical ids only,
/// so a tighter check is correct here.
pub fn is_known_gemini_model(model: &str) -> bool {
    matches!(
        model,
        "auto"
            | "gemini-2.5-pro"
            | "gemini-2.5-flash"
            | "gemini-2.5-flash-lite"
            | "gemini-3-pro-preview"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Seeds a `quota.json` row for `n` shaped the way the
    /// cadence poller writes one for an OAuth slot: `surface:
    /// "gemini"`, `kind: "utilization"`. `updated_at` is the caller's,
    /// so a test can make the row arbitrarily old without a
    /// wall-clock literal that decays into a time-bomb.
    fn seed_oauth_shaped_quota_row(base: &Path, n: u16, updated_at: f64) {
        use crate::quota::{state as quota_state, AccountQuota};

        let row = AccountQuota {
            surface: "gemini".to_string(),
            kind: "utilization".to_string(),
            updated_at,
            ..AccountQuota::default()
        };
        let mut quota = quota_state::load_state_salvage(base);
        quota.set(n, row);
        quota_state::save_state(base, &quota).unwrap();
    }

    fn quota_row_present(base: &Path, n: u16) -> bool {
        crate::quota::state::load_state(base)
            .unwrap()
            .accounts
            .contains_key(&n.to_string())
    }

    /// The regime change the staleness classifier cannot see. An
    /// OAuth row is `kind: "utilization"`, so
    /// `status::is_event_driven_row` reads FALSE and the row is judged
    /// on poll cadence — but nothing polls the slot any more once its
    /// binding is no longer OAuth, so it renders `stale` one hour
    /// after the REBIND while being perfectly healthy and merely idle.
    #[test]
    fn rebind_from_oauth_to_api_key_clears_the_stale_quota_row() {
        let dir = TempDir::new().unwrap();
        write_binding(
            dir.path(),
            slot(13),
            &GeminiBinding::new(AuthMode::CodeAssistOAuth, "gemini-2.5-pro"),
        )
        .unwrap();
        seed_oauth_shaped_quota_row(dir.path(), 13, 1_000.0);
        assert!(
            quota_row_present(dir.path(), 13),
            "precondition: the seeded row must exist, or this test proves nothing"
        );

        write_binding(
            dir.path(),
            slot(13),
            &GeminiBinding::new(AuthMode::ApiKey, "gemini-2.5-pro"),
        )
        .unwrap();

        assert!(
            !quota_row_present(dir.path(), 13),
            "the OAuth-written row outlived its writer: nothing polls an ApiKey slot, \
             so it stays frozen at kind=utilization and renders a false `stale`"
        );
    }

    /// The reverse direction: an event-driven slot rebound to OAuth
    /// must not keep a counter row that the cadence poller would then
    /// be judged against.
    #[test]
    fn rebind_from_api_key_to_oauth_clears_the_stale_quota_row() {
        let dir = TempDir::new().unwrap();
        write_binding(
            dir.path(),
            slot(4),
            &GeminiBinding::new(AuthMode::ApiKey, "gemini-2.5-pro"),
        )
        .unwrap();
        seed_oauth_shaped_quota_row(dir.path(), 4, 1_000.0);

        write_binding(
            dir.path(),
            slot(4),
            &GeminiBinding::new(AuthMode::CodeAssistOAuth, "gemini-2.5-pro"),
        )
        .unwrap();

        assert!(!quota_row_present(dir.path(), 4));
    }

    /// The other half of the precedent: a re-login / re-key inside the
    /// SAME regime is not a regime change, and discarding a valid row
    /// there would throw away real data for nothing.
    #[test]
    fn rewriting_the_same_regime_preserves_the_quota_row() {
        let dir = TempDir::new().unwrap();
        write_binding(
            dir.path(),
            slot(5),
            &GeminiBinding::new(AuthMode::CodeAssistOAuth, "gemini-2.5-pro"),
        )
        .unwrap();
        seed_oauth_shaped_quota_row(dir.path(), 5, 1_000.0);

        // Same regime, different model — an OAuth re-login or a
        // `csq models switch` rewrite.
        write_binding(
            dir.path(),
            slot(5),
            &GeminiBinding::new(AuthMode::CodeAssistOAuth, "gemini-2.5-flash"),
        )
        .unwrap();

        assert!(
            quota_row_present(dir.path(), 5),
            "a same-regime rewrite discarded a valid row"
        );
    }

    /// Discriminant-level comparison: re-pointing Vertex SA at a
    /// different JSON changes the binding but not the polling regime.
    #[test]
    fn repointing_vertex_sa_preserves_the_quota_row() {
        let dir = TempDir::new().unwrap();
        write_binding(
            dir.path(),
            slot(6),
            &GeminiBinding::new(
                AuthMode::VertexSa {
                    path: PathBuf::from("/tmp/sa-one.json"),
                },
                "gemini-2.5-pro",
            ),
        )
        .unwrap();
        seed_oauth_shaped_quota_row(dir.path(), 6, 1_000.0);

        write_binding(
            dir.path(),
            slot(6),
            &GeminiBinding::new(
                AuthMode::VertexSa {
                    path: PathBuf::from("/tmp/sa-two.json"),
                },
                "gemini-2.5-pro",
            ),
        )
        .unwrap();

        assert!(quota_row_present(dir.path(), 6));
    }

    /// A first-ever binding has no prior regime, so there is nothing
    /// to have changed — and a row seeded by any other surface must
    /// not be collateral damage.
    #[test]
    fn first_binding_with_no_prior_marker_preserves_the_quota_row() {
        let dir = TempDir::new().unwrap();
        seed_oauth_shaped_quota_row(dir.path(), 8, 1_000.0);

        write_binding(
            dir.path(),
            slot(8),
            &GeminiBinding::new(AuthMode::ApiKey, "gemini-2.5-pro"),
        )
        .unwrap();

        assert!(quota_row_present(dir.path(), 8));
    }

    #[test]
    fn binding_path_is_credentials_gemini_n_json() {
        let dir = TempDir::new().unwrap();
        let path = binding_path(dir.path(), slot(3));
        assert_eq!(path, dir.path().join("credentials/gemini-3.json"));
    }

    #[test]
    fn write_then_read_round_trip_api_key_mode() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "gemini-2.5-pro");
        write_binding(dir.path(), slot(7), &binding).unwrap();

        let read = read_binding(dir.path(), slot(7)).unwrap();
        assert_eq!(read.v, BINDING_SCHEMA_VERSION);
        assert_eq!(read.auth, AuthMode::ApiKey);
        assert_eq!(read.model_name, "gemini-2.5-pro");
        assert_eq!(read.created_unix_secs, binding.created_unix_secs);
    }

    #[test]
    fn write_then_read_round_trip_vertex_mode() {
        let dir = TempDir::new().unwrap();
        let sa_path = PathBuf::from("/abs/path/sa.json");
        let binding = GeminiBinding::new(
            AuthMode::VertexSa {
                path: sa_path.clone(),
            },
            "auto",
        );
        write_binding(dir.path(), slot(2), &binding).unwrap();

        let read = read_binding(dir.path(), slot(2)).unwrap();
        match read.auth {
            AuthMode::VertexSa { path } => assert_eq!(path, sa_path),
            other => panic!("expected VertexSa, got {other:?}"),
        }
    }

    /// Stage 2 of an internal journal entry: Code Assist OAuth binding marker
    /// round-trips through write → read intact. The marker carries
    /// no payload — its presence is the signal.
    #[test]
    fn write_then_read_round_trip_code_assist_oauth_mode() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "gemini-2.5-pro");
        write_binding(dir.path(), slot(3), &binding).unwrap();

        let read = read_binding(dir.path(), slot(3)).unwrap();
        match read.auth {
            AuthMode::CodeAssistOAuth => {}
            other => panic!("expected CodeAssistOAuth, got {other:?}"),
        }
        assert_eq!(read.model_name, "gemini-2.5-pro");
    }

    /// Stage 2 of an internal journal entry: the on-disk JSON for OAuth mode
    /// uses `mode: "code_assist_oauth"` — pinning the snake_case
    /// rename guards against accidental serde drift.
    #[test]
    fn code_assist_oauth_serde_uses_snake_case_tag() {
        let binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            json.contains(r#""mode":"code_assist_oauth""#),
            "expected snake_case mode tag, got: {json}"
        );
    }

    /// Stage 2 of an internal journal entry: `provision_code_assist_oauth` writes
    /// a binding marker with `auth = CodeAssistOAuth` and
    /// `model_name = "auto"`. No vault interaction.
    #[test]
    fn provision_code_assist_oauth_writes_binding() {
        let dir = TempDir::new().unwrap();
        provision_code_assist_oauth(dir.path(), slot(4)).unwrap();

        let read = read_binding(dir.path(), slot(4)).unwrap();
        match read.auth {
            AuthMode::CodeAssistOAuth => {}
            other => panic!("expected CodeAssistOAuth, got {other:?}"),
        }
        assert_eq!(read.model_name, "auto");
        assert!(is_gemini_bound_slot(dir.path(), slot(4)));
    }

    #[cfg(unix)]
    #[test]
    fn marker_file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(4), &binding).unwrap();
        let perms = std::fs::metadata(binding_path(dir.path(), slot(4)))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "marker must be 0o600");
    }

    #[test]
    fn is_gemini_bound_slot_returns_false_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!is_gemini_bound_slot(dir.path(), slot(5)));
    }

    /// M1/AC: `is_gemini_corrupt_bound` returns false when the marker is absent.
    #[test]
    fn is_gemini_corrupt_bound_returns_false_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!is_gemini_corrupt_bound(dir.path(), slot(5)));
    }

    /// M1/AC: `is_gemini_corrupt_bound` returns false when the binding is valid.
    #[test]
    fn is_gemini_corrupt_bound_returns_false_for_valid_binding() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(5), &binding).unwrap();
        assert!(!is_gemini_corrupt_bound(dir.path(), slot(5)));
    }

    /// M1/AC: `is_gemini_corrupt_bound` returns true when the binding is corrupt.
    #[test]
    fn is_gemini_corrupt_bound_returns_true_for_corrupt_binding() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("gemini-5.json"), b"{ not json").unwrap();
        assert!(is_gemini_corrupt_bound(dir.path(), slot(5)));
    }

    #[test]
    fn is_gemini_bound_slot_returns_true_after_write() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(5), &binding).unwrap();
        assert!(is_gemini_bound_slot(dir.path(), slot(5)));
    }

    #[cfg(unix)]
    #[test]
    fn is_gemini_bound_slot_treats_dangling_symlink_as_bound() {
        // Same posture as `is_codex_bound_slot` (FR-CLI-05): a
        // dangling symlink at the canonical path is still "bound" —
        // refuse to silently re-provision over what may be a
        // user-recoverable broken link.
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        symlink(dir.path().join("nowhere.json"), creds.join("gemini-9.json")).unwrap();
        assert!(is_gemini_bound_slot(dir.path(), slot(9)));
    }

    #[test]
    fn read_binding_returns_io_not_found_when_absent() {
        let dir = TempDir::new().unwrap();
        let err = read_binding(dir.path(), slot(6)).unwrap_err();
        match err {
            ProvisionError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io NotFound, got {other:?}"),
        }
    }

    #[test]
    fn read_binding_rejects_unknown_schema_version() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let raw = serde_json::json!({
            "v": 999,
            "auth": { "mode": "api_key" },
            "model_name": "auto",
            "created_unix_secs": 0_u64,
        });
        std::fs::write(creds.join("gemini-1.json"), raw.to_string()).unwrap();

        let err = read_binding(dir.path(), slot(1)).unwrap_err();
        assert!(matches!(err, ProvisionError::Malformed { .. }));
        assert_eq!(err.error_kind_tag(), "gemini_provision_malformed");
    }

    #[test]
    fn read_binding_rejects_garbage_json() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("gemini-1.json"), "{ this is not json").unwrap();
        let err = read_binding(dir.path(), slot(1)).unwrap_err();
        assert!(matches!(err, ProvisionError::Malformed { .. }));
    }

    #[test]
    fn unbind_is_idempotent_when_absent() {
        let dir = TempDir::new().unwrap();
        unbind(dir.path(), slot(8)).unwrap();
        unbind(dir.path(), slot(8)).unwrap();
    }

    #[test]
    fn unbind_removes_marker_when_present() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(8), &binding).unwrap();
        assert!(is_gemini_bound_slot(dir.path(), slot(8)));
        unbind(dir.path(), slot(8)).unwrap();
        assert!(!is_gemini_bound_slot(dir.path(), slot(8)));
    }

    #[test]
    fn validate_vertex_sa_rejects_missing_path() {
        let err = validate_vertex_sa_path(Path::new("/this/does/not/exist.json")).unwrap_err();
        assert!(matches!(err, ProvisionError::VertexSaInvalid { .. }));
    }

    #[test]
    fn validate_vertex_sa_rejects_directory() {
        let dir = TempDir::new().unwrap();
        let err = validate_vertex_sa_path(dir.path()).unwrap_err();
        assert!(matches!(err, ProvisionError::VertexSaInvalid { .. }));
    }

    #[test]
    fn validate_vertex_sa_rejects_oversized_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("sa.json");
        // Just over 64 KiB.
        std::fs::write(&p, vec![b'{'; 64 * 1024 + 1]).unwrap();
        let err = validate_vertex_sa_path(&p).unwrap_err();
        match err {
            ProvisionError::VertexSaInvalid { reason, .. } => {
                assert!(reason.contains("too large"), "got: {reason}");
            }
            other => panic!("expected VertexSaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_vertex_sa_returns_canonical_path() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("sa.json");
        std::fs::write(&p, br#"{"type":"service_account"}"#).unwrap();
        let canon = validate_vertex_sa_path(&p).unwrap();
        assert!(canon.is_absolute());
        // canonicalize resolves via the platform — assert that the
        // result points back at the same file rather than asserting
        // a literal path (TempDir on macOS goes via `/private/var`).
        assert_eq!(
            std::fs::canonicalize(&p).unwrap(),
            std::fs::canonicalize(&canon).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_vertex_sa_rejects_symlink_to_real_file() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, br#"{"type":"service_account"}"#).unwrap();
        let link = dir.path().join("link.json");
        symlink(&real, &link).unwrap();
        let err = validate_vertex_sa_path(&link).unwrap_err();
        match err {
            ProvisionError::VertexSaInvalid { reason, .. } => {
                assert!(reason.contains("symlink") || reason.contains("regular file"));
            }
            other => panic!("expected VertexSaInvalid, got {other:?}"),
        }
    }

    // ── PR-G5 desktop orchestration helpers ─────────────────────

    use crate::platform::secret::in_memory::InMemoryVault;

    fn write_marker_file(base: &Path, surface: Surface, slot_n: u16, body: &str) {
        let path = canonical_path_for(base, slot(slot_n), surface);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
    }

    #[test]
    fn detect_other_surface_returns_none_when_no_bindings() {
        let dir = TempDir::new().unwrap();
        assert!(crate::accounts::binding_guard::conflicting_bound_surface(
            dir.path(),
            slot(1),
            Surface::Gemini
        )
        .is_none());
    }

    #[test]
    fn detect_other_surface_returns_codex_when_codex_marker_present() {
        let dir = TempDir::new().unwrap();
        write_marker_file(dir.path(), Surface::Codex, 2, "{}");
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(2),
                Surface::Gemini
            ),
            Some(BoundSurface::Codex)
        );
    }

    #[test]
    fn detect_other_surface_returns_claude_code_when_only_claude_marker_present() {
        let dir = TempDir::new().unwrap();
        write_marker_file(dir.path(), Surface::ClaudeCode, 3, "{}");
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(3),
                Surface::Gemini
            ),
            Some(BoundSurface::ClaudeCode)
        );
    }

    #[test]
    fn detect_other_surface_prefers_codex_when_both_present() {
        // The check order is Codex first, then ClaudeCode — if a slot
        // has both markers (an inconsistent state) the desktop
        // refusal message names Codex which is the more recent
        // surface. Either tag is correct factually; this test pins
        // the order so the UI message is deterministic.
        let dir = TempDir::new().unwrap();
        write_marker_file(dir.path(), Surface::Codex, 4, "{}");
        write_marker_file(dir.path(), Surface::ClaudeCode, 4, "{}");
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(4),
                Surface::Gemini
            ),
            Some(BoundSurface::Codex)
        );
    }

    #[test]
    fn detect_other_surface_returns_native_when_kimi_marker_present() {
        // redteam R2 MED-2: `detect_other_surface_binding` was blind to
        // native (Kimi/Grok) bindings — a Gemini bind onto a native-bound
        // slot silently dual-bound it. Now checked (last, after Codex +
        // ClaudeCode) via the shared `native::native_surface_for_slot`
        // primitive.
        let dir = TempDir::new().unwrap();
        write_marker_file(dir.path(), Surface::Kimi, 8, "{}");
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(8),
                Surface::Gemini
            ),
            Some(BoundSurface::Native(Surface::Kimi))
        );
    }

    #[test]
    fn detect_other_surface_returns_native_when_grok_marker_present() {
        let dir = TempDir::new().unwrap();
        write_marker_file(dir.path(), Surface::Grok, 9, "{}");
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(9),
                Surface::Gemini
            ),
            Some(BoundSurface::Native(Surface::Grok))
        );
    }

    #[test]
    fn detect_other_surface_prefers_codex_over_native_when_both_present() {
        // Check order: Codex, ClaudeCode, then native — an inconsistent
        // dual-marker state still resolves deterministically.
        let dir = TempDir::new().unwrap();
        write_marker_file(dir.path(), Surface::Codex, 10, "{}");
        write_marker_file(dir.path(), Surface::Kimi, 10, "{}");
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(10),
                Surface::Gemini
            ),
            Some(BoundSurface::Codex)
        );
    }

    #[test]
    fn detect_other_surface_ignores_gemini_marker() {
        // A slot already bound to Gemini is NOT another-surface — the
        // caller checks `is_gemini_bound_slot` separately for the
        // overwrite-without-confirm decision.
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(5), &binding).unwrap();
        assert!(crate::accounts::binding_guard::conflicting_bound_surface(
            dir.path(),
            slot(5),
            Surface::Gemini
        )
        .is_none());
    }

    /// Plant the post-M4-12 identity-store shape (by_slot → identity, NO legacy
    /// mirror) — the state the pre-fix legacy-marker `detect_other_surface_binding`
    /// was blind to, which would have let a Gemini bind clobber a live login.
    fn plant_identity_by_slot(base: &Path, s: u16, provider: &str) {
        use crate::accounts::identity_store::{
            credentials_codex_path_for, credentials_path_for, identity_path, IdentityId,
        };
        use crate::accounts::profiles::{profiles_path, save, ProfilesFile};
        let uuid = IdentityId::new_v4();
        let idir = identity_path(base, uuid);
        std::fs::create_dir_all(&idir).unwrap();
        std::fs::write(
            idir.join("identity.json"),
            format!(r#"{{"email":"x","provider":"{provider}","created_at":"t","key_id":null}}"#),
        )
        .unwrap();
        let cred = if provider == "codex" {
            credentials_codex_path_for(base, uuid)
        } else {
            credentials_path_for(base, uuid)
        };
        std::fs::write(cred, b"{}").unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert(s.to_string(), uuid);
        save(&profiles_path(base), &pf).unwrap();
    }

    #[test]
    fn detect_other_surface_identity_only_anthropic_no_legacy_mirror() {
        let dir = TempDir::new().unwrap();
        plant_identity_by_slot(dir.path(), 6, "anthropic");
        assert!(
            !dir.path().join("credentials/6.json").exists(),
            "precondition: no legacy mirror"
        );
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(6),
                Surface::Gemini
            ),
            Some(BoundSurface::ClaudeCode),
            "a Gemini bind must be refused over a post-A++ Anthropic OAuth slot"
        );
    }

    #[test]
    fn detect_other_surface_identity_only_codex_no_legacy_marker() {
        let dir = TempDir::new().unwrap();
        plant_identity_by_slot(dir.path(), 7, "codex");
        assert!(!dir.path().join("credentials/codex-7.json").exists());
        assert_eq!(
            crate::accounts::binding_guard::conflicting_bound_surface(
                dir.path(),
                slot(7),
                Surface::Gemini
            ),
            Some(BoundSurface::Codex),
            "a Gemini bind must be refused over a post-A++ Codex slot"
        );
    }

    #[test]
    fn provision_api_key_via_vault_writes_vault_and_marker() {
        let dir = TempDir::new().unwrap();
        let vault = InMemoryVault::new();
        let key = SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into());

        provision_api_key_via_vault(dir.path(), slot(6), &key, &vault).unwrap();

        let stored = vault
            .get(SlotKey {
                surface: SURFACE_GEMINI,
                account: slot(6),
            })
            .unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(
            stored.expose_secret(),
            "AIzaFAKETESTKEYDONOTUSE0000000000000000"
        );

        let read = read_binding(dir.path(), slot(6)).unwrap();
        assert_eq!(read.auth, AuthMode::ApiKey);
        assert_eq!(read.model_name, "auto");
    }

    #[test]
    fn provision_api_key_via_vault_rolls_back_on_marker_write_failure() {
        // Trigger a write_binding failure by pointing base_dir at a
        // non-existent ancestor that cannot be created (a regular
        // file occupies the parent slot of `credentials/`).
        let dir = TempDir::new().unwrap();
        let blocker = dir.path().join("credentials");
        // Make `credentials` a regular file so create_dir_all fails.
        std::fs::write(&blocker, b"not a directory").unwrap();

        let vault = InMemoryVault::new();
        let key = SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into());

        let err = provision_api_key_via_vault(dir.path(), slot(7), &key, &vault).unwrap_err();
        assert!(matches!(err, ProvisionError::Io { .. }));

        // Vault entry must have been rolled back so a retry doesn't
        // see a half-bound state.
        let after = vault.get(SlotKey {
            surface: SURFACE_GEMINI,
            account: slot(7),
        });
        assert!(matches!(after, Err(SecretError::NotFound { .. })));
    }

    #[test]
    fn provision_vertex_sa_writes_binding_with_canonical_path() {
        let dir = TempDir::new().unwrap();
        let sa = dir.path().join("sa.json");
        std::fs::write(&sa, br#"{"type":"service_account"}"#).unwrap();

        let canon = provision_vertex_sa(dir.path(), slot(8), &sa).unwrap();
        assert!(canon.is_absolute());

        let read = read_binding(dir.path(), slot(8)).unwrap();
        match read.auth {
            AuthMode::VertexSa { path } => {
                assert_eq!(
                    std::fs::canonicalize(&path).unwrap(),
                    std::fs::canonicalize(&canon).unwrap()
                );
            }
            other => panic!("expected VertexSa, got {other:?}"),
        }
        assert_eq!(read.model_name, "auto");
    }

    #[test]
    fn provision_vertex_sa_rejects_missing_path_without_writing_marker() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.json");
        let err = provision_vertex_sa(dir.path(), slot(9), &missing).unwrap_err();
        assert!(matches!(err, ProvisionError::VertexSaInvalid { .. }));
        assert!(!is_gemini_bound_slot(dir.path(), slot(9)));
    }

    // ── G1: shared identity-literal producer (FM-3a) ─────────────────────

    /// G1/AC: `gemini_mode_class` + `gemini_identity_label` map each of the
    /// 3 `AuthMode` variants to the pinned mode-class literal. This is the
    /// SINGLE producer consumed by both the synchronous write and the
    /// daemon backfill — divergence here is the FM-3a defect.
    #[test]
    fn gemini_identity_label_covers_all_three_modes() {
        assert_eq!(gemini_mode_class(&AuthMode::ApiKey), "apikey");
        assert_eq!(
            gemini_mode_class(&AuthMode::VertexSa {
                path: PathBuf::from("/x")
            }),
            "vertex"
        );
        assert_eq!(gemini_mode_class(&AuthMode::CodeAssistOAuth), "codeassist");

        assert_eq!(
            gemini_identity_label(slot(13), &AuthMode::ApiKey),
            "gemini-13/apikey"
        );
        assert_eq!(
            gemini_identity_label(
                slot(7),
                &AuthMode::VertexSa {
                    path: PathBuf::from("/abs/sa.json")
                }
            ),
            "gemini-7/vertex"
        );
        assert_eq!(
            gemini_identity_label(slot(4), &AuthMode::CodeAssistOAuth),
            "gemini-4/codeassist"
        );
    }

    // ── G3: synchronous by_slot_identity write per provision path ────────

    /// G3/AC-4: `provision_code_assist_oauth` writes `by_slot_identity[N]`
    /// = `gemini-<N>/codeassist` in the same call (marker FIRST, identity
    /// LAST — FM-8). No vault needed for OAuth mode.
    #[test]
    fn provision_code_assist_oauth_writes_by_slot_identity() {
        let dir = TempDir::new().unwrap();
        provision_code_assist_oauth(dir.path(), slot(4)).unwrap();

        // Marker present (bound).
        assert!(is_gemini_bound_slot(dir.path(), slot(4)));
        // Identity written.
        let pf =
            crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(dir.path()))
                .unwrap();
        assert_eq!(
            pf.by_slot_identity.get("4").map(|s| s.as_str()),
            Some("gemini-4/codeassist"),
            "by_slot_identity[4] must be gemini-4/codeassist after OAuth provision"
        );
    }

    /// G3/AC-4: `provision_api_key_via_vault` writes
    /// `by_slot_identity[N]` = `gemini-<N>/apikey`.
    #[test]
    fn provision_api_key_via_vault_writes_by_slot_identity() {
        let dir = TempDir::new().unwrap();
        let vault = InMemoryVault::new();
        let key = SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into());
        provision_api_key_via_vault(dir.path(), slot(6), &key, &vault).unwrap();

        let pf =
            crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(dir.path()))
                .unwrap();
        assert_eq!(
            pf.by_slot_identity.get("6").map(|s| s.as_str()),
            Some("gemini-6/apikey")
        );
    }

    /// G3/AC-4: `provision_vertex_sa` writes
    /// `by_slot_identity[N]` = `gemini-<N>/vertex`.
    #[test]
    fn provision_vertex_sa_writes_by_slot_identity() {
        let dir = TempDir::new().unwrap();
        let sa = dir.path().join("sa.json");
        std::fs::write(&sa, br#"{"type":"service_account"}"#).unwrap();
        provision_vertex_sa(dir.path(), slot(8), &sa).unwrap();

        let pf =
            crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(dir.path()))
                .unwrap();
        assert_eq!(
            pf.by_slot_identity.get("8").map(|s| s.as_str()),
            Some("gemini-8/vertex")
        );
    }

    /// G3/AC-5 (FM-8 marker-FIRST / identity-LAST): when the identity
    /// write fails, the binding marker MUST still exist (the slot is
    /// bound-but-unidentified; the daemon backfill heals it) and the
    /// error MUST be the distinct `ProfilesIdentity` variant — NEVER a
    /// state where the identity exists but the marker does not.
    ///
    /// Deterministic failure injection (NOT a chmod-permission trick per
    /// the redteam-discipline closure-injection directive): make
    /// `profiles.json` a DIRECTORY so the identity-write branch
    /// (`set_slot_identity` → `load` reads the path; a directory yields an
    /// IO error before `save` is reached) fails — the branch under test —
    /// while `write_binding` (which writes `credentials/gemini-N.json`,
    /// an unrelated path) succeeds first. The exact failing inner call
    /// (load vs save) is irrelevant to the invariant; what matters is
    /// that the failure lands AFTER the marker commit.
    #[test]
    fn provision_identity_failure_leaves_marker_bound_not_phantom() {
        let dir = TempDir::new().unwrap();
        // Occupy profiles.json with a directory → set_slot_identity
        // cannot read/write the file → ProfilesIdentity error, AFTER
        // the marker is committed.
        std::fs::create_dir_all(crate::accounts::profiles::profiles_path(dir.path())).unwrap();

        let err = provision_code_assist_oauth(dir.path(), slot(5)).unwrap_err();
        assert!(
            matches!(err, ProvisionError::ProfilesIdentity { .. }),
            "expected ProfilesIdentity, got {err:?}"
        );
        // FM-8: marker committed (bound-but-unidentified is the safe
        // residue; a daemon backfill re-derives the label). The inverse
        // (identity present, marker absent — a phantom) is the failure
        // this asserts against.
        assert!(
            is_gemini_bound_slot(dir.path(), slot(5)),
            "marker MUST exist after identity-write failure (bound-but-unidentified, never phantom)"
        );
    }

    #[test]
    fn set_model_name_updates_existing_binding() {
        let dir = TempDir::new().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(10), &binding).unwrap();

        set_model_name(dir.path(), slot(10), "gemini-3-pro-preview").unwrap();

        let read = read_binding(dir.path(), slot(10)).unwrap();
        assert_eq!(read.model_name, "gemini-3-pro-preview");
        // Other fields preserved.
        assert_eq!(read.auth, AuthMode::ApiKey);
    }

    #[test]
    fn set_model_name_returns_not_found_when_slot_unbound() {
        let dir = TempDir::new().unwrap();
        let err = set_model_name(dir.path(), slot(11), "auto").unwrap_err();
        match err {
            ProvisionError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io NotFound, got {other:?}"),
        }
    }

    #[test]
    fn is_known_gemini_model_accepts_static_list() {
        assert!(is_known_gemini_model("auto"));
        assert!(is_known_gemini_model("gemini-2.5-pro"));
        assert!(is_known_gemini_model("gemini-2.5-flash"));
        assert!(is_known_gemini_model("gemini-2.5-flash-lite"));
        assert!(is_known_gemini_model("gemini-3-pro-preview"));
    }

    #[test]
    fn is_known_gemini_model_rejects_aliases_and_unknown() {
        // The desktop static picker submits canonical ids only —
        // alias resolution is a CLI concern (`models.rs`).
        assert!(!is_known_gemini_model("pro"));
        assert!(!is_known_gemini_model("flash"));
        assert!(!is_known_gemini_model("flash-lite"));
        assert!(!is_known_gemini_model("3-pro-preview"));
        assert!(!is_known_gemini_model(""));
        assert!(!is_known_gemini_model("claude-opus"));
    }

    #[test]
    fn bound_surface_as_tag_is_stable() {
        assert_eq!(BoundSurface::ClaudeCode.as_tag(), "claude_code");
        assert_eq!(BoundSurface::Codex.as_tag(), "codex");
        assert_eq!(BoundSurface::Native(Surface::Kimi).as_tag(), "kimi");
        assert_eq!(BoundSurface::Native(Surface::Grok).as_tag(), "grok");
    }

    // ── delete_api_key_from_vault ────────────────────────────────────────────

    /// D7 regression: provisioning via vault then calling
    /// `delete_api_key_from_vault` must remove the vault entry so a
    /// future `vault.get` returns `NotFound`. The binding marker is NOT
    /// touched here — `logout_account` owns that via config-N removal.
    #[test]
    fn delete_api_key_from_vault_removes_vault_entry_for_api_key_slot() {
        let dir = TempDir::new().unwrap();
        let vault = InMemoryVault::new();
        let key = SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into());

        // Provision the slot (writes vault + marker).
        provision_api_key_via_vault(dir.path(), slot(6), &key, &vault).unwrap();

        // Confirm vault has the entry before delete.
        assert!(vault
            .get(SlotKey {
                surface: SURFACE_GEMINI,
                account: slot(6)
            })
            .is_ok());

        // Delete the vault entry.
        delete_api_key_from_vault(dir.path(), slot(6), &vault).unwrap();

        // Vault entry must be gone.
        let after = vault.get(SlotKey {
            surface: SURFACE_GEMINI,
            account: slot(6),
        });
        assert!(
            matches!(after, Err(SecretError::NotFound { .. })),
            "vault entry must be NotFound after delete_api_key_from_vault, got: {after:?}"
        );

        // Marker is still present — we only deleted the vault entry.
        assert!(
            is_gemini_bound_slot(dir.path(), slot(6)),
            "binding marker must survive delete_api_key_from_vault"
        );
    }

    /// Calling `delete_api_key_from_vault` on a VertexSa slot is a no-op
    /// — no vault entry is ever written for Vertex SA mode.
    #[test]
    fn delete_api_key_from_vault_is_noop_for_vertex_sa_slot() {
        let dir = TempDir::new().unwrap();
        let vault = InMemoryVault::new();
        let sa = dir.path().join("sa.json");
        std::fs::write(&sa, br#"{"type":"service_account"}"#).unwrap();

        provision_vertex_sa(dir.path(), slot(7), &sa).unwrap();

        // No vault entry was created.
        let before = vault.get(SlotKey {
            surface: SURFACE_GEMINI,
            account: slot(7),
        });
        assert!(matches!(before, Err(SecretError::NotFound { .. })));

        // delete_api_key_from_vault on a VertexSa slot must succeed without
        // touching anything.
        delete_api_key_from_vault(dir.path(), slot(7), &vault).unwrap();
    }

    /// `delete_api_key_from_vault` on an absent marker (slot never bound)
    /// must be a no-op and return Ok.
    #[test]
    fn delete_api_key_from_vault_is_noop_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        let vault = InMemoryVault::new();
        // No binding has been written for slot 8.
        delete_api_key_from_vault(dir.path(), slot(8), &vault).unwrap();
    }

    /// Calling `delete_api_key_from_vault` twice on the same ApiKey slot
    /// must be idempotent — second call returns Ok even though the vault
    /// entry is already gone.
    #[test]
    fn delete_api_key_from_vault_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let vault = InMemoryVault::new();
        let key = SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into());

        provision_api_key_via_vault(dir.path(), slot(9), &key, &vault).unwrap();

        delete_api_key_from_vault(dir.path(), slot(9), &vault).unwrap();
        // Second call with vault entry already absent — must still be Ok.
        delete_api_key_from_vault(dir.path(), slot(9), &vault).unwrap();
    }
}
