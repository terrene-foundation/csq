//! Persisted user toggles for the capability layer (FR-CL-05 opt-out
//! granularity). Spec 10 §10.2.3 defines four per-technique flags
//! (`--no-scaffold`, `--no-mcp-gate`, `--no-post-validate`,
//! `--no-structured-output`) and one global flag
//! (`--no-capability-layer`). The desktop tray (M6 PR-CA12) writes
//! user choices into this file; the CLI reads them at `csq run`
//! startup and combines with explicit CLI flags.
//!
//! # File location and shape
//!
//! Stored at `<base_dir>/capability_layer.json` as plain JSON. No
//! secrets in this file — all fields are booleans — but writes still
//! go through [`crate::platform::fs::atomic_replace`] +
//! [`crate::platform::fs::secure_file`] for shape-consistency with
//! every other on-disk csq state file. A torn write would not leak
//! credentials but would corrupt user intent (e.g. a partially
//! written `{"disable_scaffold": true` truncated mid-key would parse
//! as defaults).
//!
//! ```json
//! {
//!   "disable_capability_layer": false,
//!   "disable_scaffold":         false,
//!   "disable_mcp_gate":         false,
//!   "disable_post_validate":    false,
//!   "disable_struct_out":       false
//! }
//! ```
//!
//! Default-allow semantics: a missing file or missing field reads as
//! `false` (technique enabled), so a fresh install behaves identically
//! to a default-on capability layer (post-PR-CA14). Explicit `true`
//! disables a single technique; `disable_capability_layer = true`
//! disables every technique regardless of the per-technique flags.
//!
//! # Precedence with CLI flags
//!
//! CLI flags WIN. The per-invocation CLI flag is the highest-priority
//! signal; persisted settings provide the durable default. The CLI
//! integration in `csq-cli/src/commands/run.rs` reads these settings
//! at startup and OR's them with any explicit `--no-*` flag, so the
//! CLI flag can disable a technique even if the persisted setting
//! says enabled.
//!
//! # Why JSON, not the provider settings shape
//!
//! [`crate::providers::settings::save_settings`] writes
//! `settings-<provider>.json` keyed by the provider catalog. The
//! capability layer is not a provider — it's a global pre-spawn
//! pipeline that runs in front of any surface (cc, codex, gemini).
//! Inventing a fake `capability_layer` provider catalog entry would
//! mix layer state with provider state and confuse `list_configured`.
//! The capability layer gets its own file with its own load/save.

use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Persisted toggles for the capability layer's per-technique opt-out
/// (FR-CL-05). Each `disable_*` field defaults to `false` (technique
/// enabled). The desktop tray writes this struct via
/// [`save_capability_layer_toggles`]; the CLI reads it via
/// [`load_capability_layer_toggles`] before computing
/// `LayerControl::Inherit` vs `LayerControl::WithLayer`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLayerToggles {
    /// Global kill switch. When `true`, the entire capability-layer
    /// pipeline is bypassed regardless of the per-technique flags.
    /// Equivalent to `--no-capability-layer` per spec 10 §10.2.3.
    #[serde(default)]
    pub disable_capability_layer: bool,
    /// Skip the scaffold stage. The driver still runs the
    /// classifier; `pre_spawn.scaffold` stays `None` so no rule
    /// citation directive is appended to the user's prompt.
    /// Equivalent to `--no-scaffold` per spec 10 §10.2.3.
    #[serde(default)]
    pub disable_scaffold: bool,
    /// Skip the MCP gate stage. `pre_spawn.mcp_filter` keeps its
    /// `default()` value (allow-all) so MCP tools are not policy-
    /// filtered for this invocation. Equivalent to `--no-mcp-gate`
    /// per spec 10 §10.2.3.
    #[serde(default)]
    pub disable_mcp_gate: bool,
    /// Skip the post-validate stage. Captured CC output is echoed to
    /// the user's stdout without rule-citation enforcement.
    /// Equivalent to `--no-post-validate` per spec 10 §10.2.3.
    #[serde(default)]
    pub disable_post_validate: bool,
    /// Skip the struct-out (JSON envelope) decode stage in
    /// post-spawn. The post-validate stage falls back to substring
    /// citation matching as if no envelopes were present.
    /// Equivalent to `--no-structured-output` per spec 10 §10.2.3.
    #[serde(default)]
    pub disable_struct_out: bool,
}

impl CapabilityLayerToggles {
    /// Returns `true` if the entire capability layer is disabled —
    /// either by the global flag or by every per-technique flag
    /// being set. Convenience for the CLI's preflight short-circuit.
    pub fn is_layer_fully_disabled(&self) -> bool {
        self.disable_capability_layer
            || (self.disable_scaffold
                && self.disable_mcp_gate
                && self.disable_post_validate
                && self.disable_struct_out)
    }
}

/// Filename for the persisted toggles, relative to `base_dir`.
pub const CAPABILITY_LAYER_FILE: &str = "capability_layer.json";

/// Loads persisted capability-layer toggles. Returns the default
/// (every technique enabled) when the file does not exist, is empty,
/// or fails to parse — these are not error conditions for the CLI
/// hot path. Read errors are logged at WARN with `error_kind` tags
/// per `rules/security.md` Rule 2.
pub fn load_capability_layer_toggles(base_dir: &Path) -> CapabilityLayerToggles {
    let path = base_dir.join(CAPABILITY_LAYER_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            match serde_json::from_str::<CapabilityLayerToggles>(&content) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        error_kind = "capability_layer_settings_parse",
                        error = %e,
                        "capability_layer.json failed to parse, using defaults"
                    );
                    CapabilityLayerToggles::default()
                }
            }
        }
        Ok(_) => CapabilityLayerToggles::default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CapabilityLayerToggles::default(),
        Err(e) => {
            tracing::warn!(
                error_kind = "capability_layer_settings_read",
                error = %e,
                "capability_layer.json read failed, using defaults"
            );
            CapabilityLayerToggles::default()
        }
    }
}

/// Persists capability-layer toggles using the same atomic-write +
/// chmod-0o600 contract as
/// [`crate::providers::settings::save_settings`]. The file holds no
/// secrets, but the cleanup-on-failure pattern mirrors security.md
/// §5a so a future change that adds a per-toggle metadata field
/// (e.g. timestamp, source attribution) does not introduce a new
/// secret-bearing tmp-file leak path.
pub fn save_capability_layer_toggles(
    base_dir: &Path,
    toggles: &CapabilityLayerToggles,
) -> Result<(), ConfigError> {
    let path = base_dir.join(CAPABILITY_LAYER_FILE);

    let json = serde_json::to_string_pretty(toggles).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("serialize: {e}"),
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("write: {e}"),
        });
    }
    if secure_file(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: "secure_file: chmod failed".into(),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_have_every_technique_enabled() {
        let t = CapabilityLayerToggles::default();
        assert!(!t.disable_capability_layer);
        assert!(!t.disable_scaffold);
        assert!(!t.disable_mcp_gate);
        assert!(!t.disable_post_validate);
        assert!(!t.disable_struct_out);
        assert!(!t.is_layer_fully_disabled());
    }

    #[test]
    fn missing_file_returns_default() {
        let dir = TempDir::new().unwrap();
        let t = load_capability_layer_toggles(dir.path());
        assert_eq!(t, CapabilityLayerToggles::default());
    }

    #[test]
    fn corrupt_file_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(CAPABILITY_LAYER_FILE), "{ not valid json,").unwrap();
        let t = load_capability_layer_toggles(dir.path());
        assert_eq!(t, CapabilityLayerToggles::default());
    }

    #[test]
    fn empty_file_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(CAPABILITY_LAYER_FILE), "").unwrap();
        let t = load_capability_layer_toggles(dir.path());
        assert_eq!(t, CapabilityLayerToggles::default());
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let dir = TempDir::new().unwrap();
        let original = CapabilityLayerToggles {
            disable_capability_layer: false,
            disable_scaffold: true,
            disable_mcp_gate: false,
            disable_post_validate: true,
            disable_struct_out: false,
        };
        save_capability_layer_toggles(dir.path(), &original).unwrap();
        let loaded = load_capability_layer_toggles(dir.path());
        assert_eq!(loaded, original);
    }

    #[test]
    fn missing_field_in_json_reads_as_false() {
        let dir = TempDir::new().unwrap();
        // Forward-compat shape: a future version may add a field
        // that older csq does not understand. Older csq must not
        // refuse to parse it.
        std::fs::write(
            dir.path().join(CAPABILITY_LAYER_FILE),
            r#"{"disable_scaffold": true}"#,
        )
        .unwrap();
        let t = load_capability_layer_toggles(dir.path());
        assert!(!t.disable_capability_layer);
        assert!(t.disable_scaffold);
        assert!(!t.disable_mcp_gate);
        assert!(!t.disable_post_validate);
        assert!(!t.disable_struct_out);
    }

    #[test]
    fn global_disable_implies_full_disable() {
        let t = CapabilityLayerToggles {
            disable_capability_layer: true,
            ..Default::default()
        };
        assert!(t.is_layer_fully_disabled());
    }

    #[test]
    fn all_techniques_disabled_implies_full_disable() {
        let t = CapabilityLayerToggles {
            disable_capability_layer: false,
            disable_scaffold: true,
            disable_mcp_gate: true,
            disable_post_validate: true,
            disable_struct_out: true,
        };
        assert!(t.is_layer_fully_disabled());
    }

    #[test]
    fn three_of_four_disabled_does_not_imply_full_disable() {
        let t = CapabilityLayerToggles {
            disable_capability_layer: false,
            disable_scaffold: true,
            disable_mcp_gate: true,
            disable_post_validate: true,
            disable_struct_out: false,
        };
        assert!(!t.is_layer_fully_disabled());
    }
}
