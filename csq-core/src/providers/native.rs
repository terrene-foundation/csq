//! Native-CLI session surfaces (Wave 3) — Kimi and Grok.
//!
//! Unlike the Bearer/OAuth providers in [`crate::providers::catalog::PROVIDERS`], a native-CLI
//! surface is a **self-authenticating vendor binary** (`kimi`, `grok`) that
//! csq dispatches sessions to but whose credentials it **never stores**. The
//! vendor CLI owns its own auth (Kimi device-code under `~/.kimi-code/`; Grok
//! OIDC at `~/.grok/auth.json`).
//!
//! **Per-slot vendor HOME model (an internal journal entry).** Each native slot N gets its
//! OWN isolated vendor config dir at `native-homes/<surface>-<N>/`
//! ([`native_home_path`]) — so two slots on the same provider are two
//! independent accounts, exactly like Codex. Binding runs the vendor's own
//! device-code login into that per-slot home (`KIMI_CODE_HOME`/`GROK_HOME` —
//! see [`crate::providers::native_login`]); `csq run N` sets the same env; the
//! vendor self-refreshes in place (csq polls/refreshes nothing native).
//!
//! A slot bound to a native surface is keyed by a **credential-less binding
//! marker** at `credentials/{kimi,grok}-<N>.json`. Per 0135 the marker is
//! written **only after** the vendor's credential file is verified present
//! ([`has_credentials`]), so a marker means "this slot has a working native
//! login," never merely "a bind was attempted." The marker's *existence* keys
//! the surface for [`crate::credentials::file::canonical_path_for`],
//! `surface_cli_for_slot`, and `discover_*`; it stores no secret (the real
//! credentials live in the per-slot vendor home, owned by the vendor CLI).
//!
//! This module is the single source of truth for the native descriptor, the
//! per-slot home path, and the marker lifecycle, so CLI login, desktop login,
//! discovery, launch, and logout all agree.
//!
//! See `internal-design-docs` (per-slot HOME design
//! lock) and `0133` (the superseded marker-only model).

use crate::cli_deps::SurfaceCli;
use crate::credentials::file::canonical_path_for;
use crate::error::PlatformError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Binding-marker schema version. A reader refuses unknown values.
pub const NATIVE_BINDING_SCHEMA_VERSION: u32 = 1;

/// Static descriptor for a native-CLI session surface.
#[derive(Debug, Clone, Copy)]
pub struct NativeCli {
    /// Dispatch-axis surface.
    pub surface: Surface,
    /// Short id used by the desktop picker + `csq login --provider <id>`.
    pub id: &'static str,
    /// Vendor binary name spawned by `csq run` (resolved via PATH + the
    /// known-dir fallback in [`crate::cli_deps::install_path`]).
    pub binary: &'static str,
    /// Display name for the desktop picker.
    pub display_name: &'static str,
    /// Model shown in the picker. Empty string = "vendor-selected" (the
    /// picker hides the line). This is the DISPLAY value; the model csq
    /// actually pins at spawn is [`Self::pinned_model`].
    pub default_model: &'static str,
    /// Model alias csq injects as `--model <alias>` when it spawns the
    /// vendor CLI (`csq run` on this slot), overriding the vendor CLI's own
    /// built-in default. `None` = trust the vendor CLI's self-selected
    /// default (correct when that default already tracks the vendor's
    /// latest model). Injection is SUPPRESSED when the operator passes their
    /// own `-m`/`--model` in the trailing args — see
    /// `csq::cli::commands::run::native_pinned_model_to_inject`. The alias
    /// MUST be a key the vendor resolves (for Kimi, a `[models."…"]` table
    /// key from its `config.toml`, e.g. `"kimi-code/k3"`).
    pub pinned_model: Option<&'static str>,
    /// `SurfaceCli` twin for install/upgrade dispatch (`csq cli install`).
    pub surface_cli: SurfaceCli,
    /// Env var that isolates this vendor's per-slot config/credential dir
    /// (the `CODEX_HOME` pattern, without codex's UUID/symlink/relocation
    /// machinery — native surfaces self-refresh, so csq never needs to
    /// centrally rotate their tokens). Set by `csq run` / `csq login` to
    /// [`native_home_path`] for the target slot.
    pub home_env: &'static str,
    /// Argv (excluding the binary itself) that starts the vendor's
    /// device-code login flow.
    pub login_args: &'static [&'static str],
    /// Path, relative to the slot's vendor home, where the vendor writes
    /// its credential file after a successful login. Checked by
    /// [`has_credentials`] — a marker is written only after this file is
    /// confirmed present (0135 design lock: "a marker now means the slot
    /// has a working native login").
    pub cred_relpath: &'static str,
    /// Exact-match host allowlist for this surface's device-code
    /// verification URL (`providers::native_login::parse_native_device_code`).
    /// A URL on any other host MUST NOT be surfaced as a device-code —
    /// mirrors `codex::desktop_login::extract_codex_url`'s allowlist rigor.
    pub device_code_host: &'static str,
}

/// Native Kimi Code CLI (`kimi`). Distinct from the Bearer 3P `id="kimi"`
/// provider (which runs `claude` with `ANTHROPIC_BASE_URL=kimi.com`).
pub const KIMI: NativeCli = NativeCli {
    surface: Surface::Kimi,
    id: "kimi-cli",
    binary: "kimi",
    display_name: "Kimi (native CLI)",
    // Display + pin both target K3. The native kimi CLI's OWN built-in
    // default is `kimi-for-coding` (= "K2.7 Coding" in its model table), so
    // without a pin `csq run` would launch K2.7. csq injects `--model
    // kimi-code/k3` at spawn to run K3 — the `[models."kimi-code/k3"]`
    // table key the vendor's `config.toml` defines (same namespace as its
    // own `default_model`). Distinct from the 3P-bearer `kimi-k3`
    // (catalog.rs), which is a different surface.
    default_model: "kimi-code/k3",
    pinned_model: Some("kimi-code/k3"),
    surface_cli: SurfaceCli::Kimi,
    home_env: "KIMI_CODE_HOME",
    login_args: &["login"],
    cred_relpath: "credentials/kimi-code.json",
    device_code_host: "www.kimi.com",
};

/// Native xAI Grok CLI (`grok`). Native-only (no Bearer 3P variant).
pub const GROK: NativeCli = NativeCli {
    surface: Surface::Grok,
    id: "grok",
    binary: "grok",
    display_name: "Grok (native CLI)",
    // grok-cli's own default model (0135 Wave A empirical finding). The
    // grok CLI self-defaults to its LATEST model (`grok models` lists
    // `grok-4.5 (default)` as the only model), so csq trusts that default
    // (`pinned_model: None`) rather than hard-pinning an id that would go
    // stale the moment xAI ships a newer model.
    default_model: "grok-4.5",
    pinned_model: None,
    surface_cli: SurfaceCli::Grok,
    home_env: "GROK_HOME",
    login_args: &["login", "--device-auth"],
    cred_relpath: "auth.json",
    device_code_host: "accounts.x.ai",
};

/// All native-CLI session surfaces, in display order.
pub const NATIVE_CLIS: &[&NativeCli] = &[&KIMI, &GROK];

/// Returns the descriptor for a native surface, or `None` for a
/// non-native surface (`ClaudeCode`/`Codex`/`Gemini`).
pub fn descriptor(surface: Surface) -> Option<&'static NativeCli> {
    NATIVE_CLIS.iter().copied().find(|nc| nc.surface == surface)
}

/// Looks up a native descriptor by its picker/login id (`"kimi-cli"`,
/// `"grok"`).
pub fn descriptor_by_id(id: &str) -> Option<&'static NativeCli> {
    NATIVE_CLIS.iter().copied().find(|nc| nc.id == id)
}

/// The credential-less binding marker persisted at
/// `credentials/{kimi,grok}-<N>.json`. Carries NO secret — the vendor CLI
/// owns the real credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBinding {
    /// Schema version. Reader refuses unknown values.
    pub v: u32,
    /// Surface tag (`"kimi"` / `"grok"`), matching [`Surface::as_str`].
    pub surface: String,
    /// Provisioning timestamp — unix seconds. Diagnostic only; nothing in
    /// csq compares against it.
    pub created_unix_secs: u64,
}

impl NativeBinding {
    /// Builds a fresh binding for `surface`, stamping the current wall clock.
    pub fn new(surface: Surface) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            v: NATIVE_BINDING_SCHEMA_VERSION,
            surface: surface.as_str().to_string(),
            created_unix_secs: now,
        }
    }
}

/// Errors raised by native-surface marker operations.
#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    /// The requested surface is not a native-CLI surface.
    #[error("surface {0} is not a native-CLI surface")]
    NotNative(Surface),
    /// Filesystem error writing/reading the marker.
    #[error("native binding I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Serialization failure.
    #[error("native binding serialize: {0}")]
    Serialize(String),
    /// Atomic-replace failure.
    #[error("native binding atomic replace at {path}: {source}")]
    AtomicReplace {
        path: PathBuf,
        #[source]
        source: PlatformError,
    },
    /// `chmod 0o600` (secure_file) failure on the tmp marker. Distinct from
    /// `AtomicReplace` so a permissions failure isn't mislabeled (redteam
    /// LOW-1). No path in Display — it is the same tmp path already scoped.
    #[error("native binding secure_file: {source}")]
    SecureFile {
        #[source]
        source: PlatformError,
    },
    /// Marker JSON is malformed or refers to an unknown schema version.
    /// Caller treats the slot as unbound. Mirrors
    /// [`crate::providers::gemini::provisioning::ProvisionError::Malformed`].
    #[error("malformed native binding at {path}: {reason}")]
    Malformed { path: PathBuf, reason: String },
}

impl NativeError {
    /// Fixed-vocabulary tag for structured logging (`security.md` §2 —
    /// never `error = %e` on a value that could echo file content).
    /// Mirrors `ProvisionError::error_kind_tag` discipline.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            NativeError::NotNative(_) => "native_binding_not_native",
            NativeError::Io { .. } => "native_binding_io",
            NativeError::Serialize(_) => "native_binding_serialize",
            NativeError::AtomicReplace { .. } => "native_binding_atomic_replace",
            NativeError::SecureFile { .. } => "native_binding_secure_file",
            NativeError::Malformed { .. } => "native_binding_malformed",
        }
    }
}

/// Marker path for a native slot: `credentials/{kimi,grok}-<N>.json`.
pub fn marker_path(base_dir: &Path, slot: AccountNum, surface: Surface) -> PathBuf {
    canonical_path_for(base_dir, slot, surface)
}

/// Per-slot vendor home: `<base>/native-homes/<surface>-<N>/`.
///
/// Each native slot gets a persistent, isolated vendor config/credential
/// dir — the `CODEX_HOME` isolation pattern, without codex's UUID/symlink/
/// relocation machinery (native surfaces self-refresh in place; csq never
/// needs to centrally rotate their tokens, so that machinery buys nothing
/// here — 0135 design lock). Two slots bound to the same provider get
/// distinct dirs, so a provider supports multiple independent accounts.
///
/// Infallible by design (a `PathBuf`, not a `Result`): callers that need
/// the "is this actually a native surface" guarantee call
/// [`descriptor`]/[`has_credentials`] first, mirroring [`marker_path`].
pub fn native_home_path(base_dir: &Path, slot: AccountNum, surface: Surface) -> PathBuf {
    base_dir
        .join("native-homes")
        .join(format!("{}-{slot}", surface.as_str()))
}

/// True iff the vendor's credential file (`descriptor.cred_relpath`)
/// exists under slot `N`'s vendor home. The login orchestrator
/// (`providers::native_login`) checks this AFTER a successful vendor
/// login exit and BEFORE writing the binding marker — a marker now means
/// "slot has a working native login" (0135 design lock). Returns `false`
/// for a non-native `surface` (no descriptor to resolve `cred_relpath`
/// from) rather than panicking.
pub fn has_credentials(base_dir: &Path, slot: AccountNum, surface: Surface) -> bool {
    let Some(d) = descriptor(surface) else {
        return false;
    };
    native_home_path(base_dir, slot, surface)
        .join(d.cred_relpath)
        .is_file()
}

/// Reads and validates the binding marker for a native slot. Refuses an
/// unknown schema version or unparseable JSON — the caller (`discover_*`)
/// treats the slot as unbound rather than surfacing corrupt state. Mirrors
/// [`crate::providers::gemini::provisioning::read_binding`].
pub fn read_binding(
    base_dir: &Path,
    slot: AccountNum,
    surface: Surface,
) -> Result<NativeBinding, NativeError> {
    let path = marker_path(base_dir, slot, surface);
    let raw = std::fs::read_to_string(&path).map_err(|source| NativeError::Io {
        path: path.clone(),
        source,
    })?;
    let binding: NativeBinding =
        serde_json::from_str(&raw).map_err(|e| NativeError::Malformed {
            path: path.clone(),
            reason: format!("json parse: {e}"),
        })?;
    if binding.v != NATIVE_BINDING_SCHEMA_VERSION {
        return Err(NativeError::Malformed {
            path,
            reason: format!(
                "unknown schema version {} (expected {})",
                binding.v, NATIVE_BINDING_SCHEMA_VERSION
            ),
        });
    }
    Ok(binding)
}

/// Writes the credential-less binding marker for a native slot (atomic +
/// `0o600`). Idempotent — overwrites any existing marker. The marker stores
/// no secret; the vendor CLI self-authenticates.
///
/// Used by both `csq login --provider {kimi-cli,grok}` (CLI) and the desktop
/// `{kimi,grok}_provision` command, so the two paths stay byte-identical.
pub fn write_binding(
    base_dir: &Path,
    slot: AccountNum,
    surface: Surface,
) -> Result<(), NativeError> {
    if !surface.is_native_cli() {
        return Err(NativeError::NotNative(surface));
    }
    let path = marker_path(base_dir, slot, surface);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| NativeError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let binding = NativeBinding::new(surface);
    let json = serde_json::to_string_pretty(&binding)
        .map_err(|e| NativeError::Serialize(e.to_string()))?;
    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(NativeError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(NativeError::SecureFile { source: e });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(NativeError::AtomicReplace { path, source: e });
    }
    Ok(())
}

/// Removes the credential-less binding marker for a native slot. Does NOT
/// touch the vendor's own per-slot home (`native_home_path`) — a stale-marker
/// cleanup ORPHANS the vendor home rather than deleting it, so the slot's
/// prior native login is recoverable by re-binding the same surface later
/// (mirrors [`crate::accounts::binding_guard`]'s module doc: an OAuth-login
/// onto a marker-bound slot "orphans the vendor home rather than replacing
/// it"). Idempotent — absence is success.
///
/// # Callers (enumerate on every addition — `sentinel-clearing-parity.md` MUST-1)
///
/// - [`crate::accounts::binding_guard::clear_detected_marker_binding`] — an
///   Anthropic or Codex OAuth login onto a native-marked (Kimi/Grok) slot
///   REPLACES the binding; this clears the stale native marker (captured
///   pre-mint by [`crate::accounts::binding_guard::detect_stale_marker_binding`],
///   applied only once the login has succeeded) so the slot does not carry
///   two bindings (GH an internal ticket).
/// - `csq logout <N>` sweeps this marker too, but via the surface-neutral
///   `ALL_SURFACES` loop in `accounts::logout::logout_account` (direct
///   `remove_file` on `canonical_path_for`, plus a separate
///   `remove_native_homes` step for the vendor home), not through this
///   function.
///
/// Guarded the same way as [`write_binding`]: `marker_path` resolves through
/// [`canonical_path_for`], which is NOT native-specific — it also maps
/// [`Surface::ClaudeCode`] to `credentials/<N>.json` (the legacy Anthropic
/// mirror) and [`Surface::Codex`] to `credentials/codex-<N>.json`. Without
/// the guard, a caller passing a non-native `surface` would silently
/// `remove_file` a live OAuth credential mirror instead of failing. All
/// current callers only ever pass a
/// [`crate::accounts::binding_guard::BoundSurface::Native`] payload, so
/// this is unreachable in production today — the guard is defense-in-depth
/// against a future caller, mirroring `write_binding`'s existing guard.
pub fn unbind(base_dir: &Path, slot: AccountNum, surface: Surface) -> Result<(), NativeError> {
    if !surface.is_native_cli() {
        return Err(NativeError::NotNative(surface));
    }
    let path = marker_path(base_dir, slot, surface);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(NativeError::Io { path, source }),
    }
}

/// True if slot `N` carries a binding marker for the given native `surface`.
///
/// Uses `symlink_metadata` (not `.exists()`, which follows symlinks and is
/// false for a dangling link) so a dangling marker symlink is treated as
/// BOUND — fail-toward-refuse, matching the `is_gemini_bound_slot` /
/// `is_codex_bound_slot` posture (`gemini/provisioning.rs`, `identity_store.rs`)
/// that the unified `binding_guard::detect_bound_surface` union detector relies
/// on for uniform fail-closed detection (redteam R1 MEDIUM-2). `.exists()` here
/// would let a Gemini/3P bind clobber a native slot whose marker was replaced
/// with a dangling link.
pub fn marker_exists(base_dir: &Path, slot: AccountNum, surface: Surface) -> bool {
    surface.is_native_cli()
        && std::fs::symlink_metadata(marker_path(base_dir, slot, surface)).is_ok()
}

/// Returns the native [`Surface`] bound to slot `N`, if any — the detection
/// primitive for `surface_cli_for_slot` and `discover_*`.
pub fn native_surface_for_slot(base_dir: &Path, slot: AccountNum) -> Option<Surface> {
    NATIVE_CLIS
        .iter()
        .map(|nc| nc.surface)
        .find(|s| marker_exists(base_dir, slot, *s))
}

/// Surface currently bound to `slot` that would conflict with binding it
/// to `target` (a native-CLI surface), or `None` if the slot is free (or
/// already bound to `target` itself — an idempotent re-provision).
///
/// Thin back-compat wrapper over the unified
/// [`crate::accounts::binding_guard::conflicting_bound_surface`] (an internal journal entry
/// For-Discussion #1): detection now flows through the single
/// [`crate::accounts::binding_guard::detect_bound_surface`] union detector
/// (Codex / Anthropic OAuth / Gemini / the other native surface / 3P bearer),
/// so this guard can never be blind to a surface. The `Option<Surface>` return
/// is preserved for existing callers (a 3P-bearer slot reports
/// [`Surface::ClaudeCode`], matching the prior shape).
pub fn conflicting_bound_surface(
    base_dir: &Path,
    slot: AccountNum,
    target: Surface,
) -> Option<Surface> {
    crate::accounts::binding_guard::conflicting_bound_surface(base_dir, slot, target)
        .map(|bound| bound.to_surface())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn descriptor_round_trips_surface_and_id() {
        assert_eq!(descriptor(Surface::Kimi).unwrap().binary, "kimi");
        assert_eq!(descriptor(Surface::Grok).unwrap().binary, "grok");
        assert!(descriptor(Surface::ClaudeCode).is_none());
        assert_eq!(descriptor_by_id("kimi-cli").unwrap().surface, Surface::Kimi);
        assert_eq!(descriptor_by_id("grok").unwrap().surface, Surface::Grok);
        assert!(descriptor_by_id("kimi").is_none()); // the 3P bearer id, not native
    }

    #[test]
    fn descriptor_carries_wave_b_vendor_fields() {
        let kimi = descriptor(Surface::Kimi).unwrap();
        assert_eq!(kimi.home_env, "KIMI_CODE_HOME");
        assert_eq!(kimi.login_args, &["login"]);
        assert_eq!(kimi.cred_relpath, "credentials/kimi-code.json");
        assert_eq!(kimi.device_code_host, "www.kimi.com");
        // K3 is both the display value and the spawn-time pin — the native
        // kimi CLI's own built-in default is K2.7 (`kimi-for-coding`), which
        // `pinned_model` overrides so `csq run` launches K3.
        assert_eq!(kimi.default_model, "kimi-code/k3");
        assert_eq!(kimi.pinned_model, Some("kimi-code/k3"));

        let grok = descriptor(Surface::Grok).unwrap();
        assert_eq!(grok.home_env, "GROK_HOME");
        assert_eq!(grok.login_args, &["login", "--device-auth"]);
        assert_eq!(grok.cred_relpath, "auth.json");
        assert_eq!(grok.device_code_host, "accounts.x.ai");
        assert_eq!(grok.default_model, "grok-4.5");
        // Grok's CLI self-defaults to its latest model — csq does not pin.
        assert_eq!(grok.pinned_model, None);
    }

    // ── native_home_path / has_credentials ────────────────────────────

    #[test]
    fn native_home_path_is_per_slot_and_per_surface() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let kimi_1 = native_home_path(base, slot(1), Surface::Kimi);
        let kimi_2 = native_home_path(base, slot(2), Surface::Kimi);
        let grok_1 = native_home_path(base, slot(1), Surface::Grok);
        assert_ne!(kimi_1, kimi_2); // two accounts on the same provider
        assert_ne!(kimi_1, grok_1); // two providers on the same slot
        assert_eq!(kimi_1, base.join("native-homes").join("kimi-1"));
        assert_eq!(grok_1, base.join("native-homes").join("grok-1"));
    }

    #[test]
    fn has_credentials_false_until_vendor_cred_file_present() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let s = slot(1);
        assert!(!has_credentials(base, s, Surface::Kimi));

        let home = native_home_path(base, s, Surface::Kimi);
        std::fs::create_dir_all(home.join("credentials")).unwrap();
        std::fs::write(home.join("credentials/kimi-code.json"), "{}").unwrap();
        assert!(has_credentials(base, s, Surface::Kimi));
        // A different slot's home is untouched.
        assert!(!has_credentials(base, slot(2), Surface::Kimi));
    }

    #[test]
    fn has_credentials_false_for_non_native_surface() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!has_credentials(tmp.path(), slot(1), Surface::Codex));
    }

    #[test]
    fn write_then_detect_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        assert!(native_surface_for_slot(base, slot(3)).is_none());
        write_binding(base, slot(3), Surface::Kimi).unwrap();
        assert!(marker_exists(base, slot(3), Surface::Kimi));
        assert!(!marker_exists(base, slot(3), Surface::Grok));
        assert_eq!(native_surface_for_slot(base, slot(3)), Some(Surface::Kimi));
    }

    // ── unbind ────────────────────────────────

    #[test]
    fn unbind_removes_marker_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        write_binding(base, slot(9), Surface::Kimi).unwrap();
        assert!(marker_exists(base, slot(9), Surface::Kimi));
        unbind(base, slot(9), Surface::Kimi).unwrap();
        assert!(!marker_exists(base, slot(9), Surface::Kimi));
        assert!(native_surface_for_slot(base, slot(9)).is_none());
    }

    #[test]
    fn unbind_is_idempotent_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        // No marker was ever written for this slot — must not error.
        unbind(base, slot(10), Surface::Grok).unwrap();
        unbind(base, slot(10), Surface::Grok).unwrap();
    }

    #[test]
    fn unbind_does_not_touch_the_other_surface_marker() {
        // A slot can only be validly bound to one native surface, but unbind
        // is scoped to the surface it's given — it must not reach across to a
        // marker for the OTHER surface (defensive: proves the marker path is
        // surface-keyed, not slot-keyed).
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        write_binding(base, slot(11), Surface::Grok).unwrap();
        unbind(base, slot(11), Surface::Kimi).unwrap();
        assert!(
            marker_exists(base, slot(11), Surface::Grok),
            "unbind(Kimi) must not remove a Grok marker"
        );
    }

    #[test]
    fn write_binding_rejects_non_native_surface() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            write_binding(tmp.path(), slot(1), Surface::Codex),
            Err(NativeError::NotNative(Surface::Codex))
        ));
    }

    /// `unbind` mirrors `write_binding`'s non-native guard. Without it,
    /// `unbind(base, slot, Surface::ClaudeCode)` resolves through
    /// `canonical_path_for` to `credentials/<N>.json` — the legacy Anthropic
    /// credential mirror — and would silently delete it instead of failing.
    /// Unreachable in production today (every caller passes a
    /// `BoundSurface::Native` payload), but a new public credential-deleting
    /// function must fail closed on a misuse the type system does not
    /// prevent (`surface` is a plain `Surface`, not a native-only newtype).
    #[test]
    fn unbind_rejects_non_native_surface() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            unbind(tmp.path(), slot(1), Surface::Codex),
            Err(NativeError::NotNative(Surface::Codex))
        ));
        assert!(matches!(
            unbind(tmp.path(), slot(1), Surface::ClaudeCode),
            Err(NativeError::NotNative(Surface::ClaudeCode))
        ));
    }

    /// Non-vacuity for the guard above: prove it actually protects a live
    /// credential file, not just that the match arm exists. Plants a file at
    /// EXACTLY the path `unbind(.., Surface::ClaudeCode)` would have removed
    /// pre-fix, then asserts the call errors AND the file survives.
    #[test]
    fn unbind_rejects_claude_code_without_touching_the_credential_mirror() {
        use crate::credentials::file::canonical_path_for;

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let legacy_anthropic_mirror = canonical_path_for(base, slot(2), Surface::ClaudeCode);
        std::fs::create_dir_all(legacy_anthropic_mirror.parent().unwrap()).unwrap();
        std::fs::write(&legacy_anthropic_mirror, b"{}").unwrap();

        let err = unbind(base, slot(2), Surface::ClaudeCode).unwrap_err();
        assert!(matches!(err, NativeError::NotNative(Surface::ClaudeCode)));
        assert!(
            legacy_anthropic_mirror.exists(),
            "unbind must refuse a non-native surface WITHOUT deleting the file \
             canonical_path_for resolves it to"
        );
    }

    #[test]
    #[cfg(unix)]
    fn marker_exists_treats_dangling_symlink_as_bound() {
        // redteam R1 MEDIUM-2: fail-toward-refuse parity with gemini/codex —
        // a dangling marker symlink MUST read as bound so a Gemini/3P bind
        // cannot clobber the slot via the `binding_guard` union detector.
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let path = marker_path(base, slot(4), Surface::Kimi);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(base.join("does-not-exist.json"), &path).unwrap();
        assert!(!path.exists(), "precondition: symlink target is absent");
        assert!(
            marker_exists(base, slot(4), Surface::Kimi),
            "dangling marker symlink must read as bound (fail-toward-refuse)"
        );
        assert_eq!(native_surface_for_slot(base, slot(4)), Some(Surface::Kimi));
    }

    #[test]
    fn marker_content_is_secret_free_and_versioned() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        write_binding(base, slot(5), Surface::Grok).unwrap();
        let body = std::fs::read_to_string(marker_path(base, slot(5), Surface::Grok)).unwrap();
        let parsed: NativeBinding = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.v, NATIVE_BINDING_SCHEMA_VERSION);
        assert_eq!(parsed.surface, "grok");
    }

    // ── read_binding ────────────────────────────────

    #[test]
    fn read_binding_round_trips_write_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        write_binding(base, slot(7), Surface::Kimi).unwrap();
        let binding = read_binding(base, slot(7), Surface::Kimi).unwrap();
        assert_eq!(binding.v, NATIVE_BINDING_SCHEMA_VERSION);
        assert_eq!(binding.surface, "kimi");
    }

    #[test]
    fn read_binding_returns_io_not_found_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_binding(tmp.path(), slot(6), Surface::Grok).unwrap_err();
        assert_eq!(err.error_kind_tag(), "native_binding_io");
        match err {
            NativeError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io NotFound, got {other:?}"),
        }
    }

    #[test]
    fn read_binding_rejects_unknown_schema_version() {
        let tmp = tempfile::tempdir().unwrap();
        let creds = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let raw = serde_json::json!({
            "v": 999,
            "surface": "kimi",
            "created_unix_secs": 0_u64,
        });
        std::fs::write(creds.join("kimi-1.json"), raw.to_string()).unwrap();

        let err = read_binding(tmp.path(), slot(1), Surface::Kimi).unwrap_err();
        assert!(matches!(err, NativeError::Malformed { .. }));
        assert_eq!(err.error_kind_tag(), "native_binding_malformed");
    }

    #[test]
    fn read_binding_rejects_garbage_json() {
        let tmp = tempfile::tempdir().unwrap();
        let creds = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("grok-1.json"), "{ this is not json").unwrap();
        let err = read_binding(tmp.path(), slot(1), Surface::Grok).unwrap_err();
        assert!(matches!(err, NativeError::Malformed { .. }));
    }

    // ── conflicting_bound_surface ────────────────────────────────

    #[test]
    fn conflicting_bound_surface_none_when_slot_free() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(conflicting_bound_surface(tmp.path(), slot(1), Surface::Kimi).is_none());
    }

    #[test]
    fn conflicting_bound_surface_detects_legacy_codex_marker() {
        // Mirrors the legacy-mirror fallback path `detect_other_surface_binding`
        // already covers; native provisioning reuses that helper as-is.
        let tmp = tempfile::tempdir().unwrap();
        let path = canonical_path_for(tmp.path(), slot(2), Surface::Codex);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}").unwrap();
        assert_eq!(
            conflicting_bound_surface(tmp.path(), slot(2), Surface::Kimi),
            Some(Surface::Codex)
        );
    }

    #[test]
    fn conflicting_bound_surface_detects_gemini_binding() {
        use crate::providers::gemini::provisioning::{
            write_binding as gemini_write_binding, AuthMode, GeminiBinding,
        };
        let tmp = tempfile::tempdir().unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        gemini_write_binding(tmp.path(), slot(3), &binding).unwrap();
        assert_eq!(
            conflicting_bound_surface(tmp.path(), slot(3), Surface::Grok),
            Some(Surface::Gemini)
        );
    }

    #[test]
    fn conflicting_bound_surface_detects_other_native_surface() {
        let tmp = tempfile::tempdir().unwrap();
        write_binding(tmp.path(), slot(4), Surface::Kimi).unwrap();
        assert_eq!(
            conflicting_bound_surface(tmp.path(), slot(4), Surface::Grok),
            Some(Surface::Kimi)
        );
    }

    #[test]
    fn conflicting_bound_surface_allows_idempotent_reprovision() {
        // Slot already bound to the SAME native surface — not a conflict,
        // the caller re-provisions (refreshes the marker timestamp).
        let tmp = tempfile::tempdir().unwrap();
        write_binding(tmp.path(), slot(5), Surface::Grok).unwrap();
        assert!(conflicting_bound_surface(tmp.path(), slot(5), Surface::Grok).is_none());
    }

    #[test]
    fn conflicting_bound_surface_detects_3p_bearer_binding() {
        // redteam MED-1: a slot bound to a 3P-bearer provider (settings.json
        // with ANTHROPIC_BASE_URL, classified Surface::ClaudeCode) must block a
        // native provision — otherwise the on-disk dual-bind slips past every
        // guard and the run.rs collision check then rejects the slot.
        let tmp = tempfile::tempdir().unwrap();
        let s = slot(7);
        crate::accounts::third_party::bind_provider_to_slot(
            tmp.path(),
            "deepseek",
            s,
            Some("sk-deepseek-xxxxxxxx"),
            None,
        )
        .unwrap();
        assert_eq!(
            conflicting_bound_surface(tmp.path(), s, Surface::Kimi),
            Some(Surface::ClaudeCode),
        );
    }
}
