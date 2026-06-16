//! Data-driven surface registry and per-version decoder dispatcher (F-SEAM-08).
//!
//! The surface registry is loaded from
//! `<base>/audit/surface-registry.json` (a JSON array of surface-id strings).
//! When absent, defaults to `["cc","codex","gemini"]` without writing the file.
//!
//! The version dispatcher maps `f101_schema_version` strings to decoder
//! functions. As of M18-bind the PRODUCTION registry registers exactly ONE arm
//! — `"1"` (the frozen F101-1 v1 schema, loom tag `provenance-event-schema/v1`,
//! decoded by `decode::v1::decode_v1`). Unknown versions still park visibly in
//! `.pending/provenance/` (no lossy-parse); a future frozen version is an
//! additional registry arm, not a code change to the dispatcher.
//!
//! A `#[cfg(test)]` helper additionally registers a synthetic `test-v0` decoder
//! so the legacy `F101Envelope` scaffolding path stays exercisable in unit
//! tests alongside the production v1 arm.

use std::path::Path;

/// Maximum surface entries in the registry file.
///
/// A file with more than this many entries is treated as malformed.
/// Defends against a misconfigured or adversarially crafted registry that
/// would cause O(n) `contains` scans to become a DoS vector.
const SURFACE_REGISTRY_MAX_ENTRIES: usize = 256;

/// Data-driven surface registry.
///
/// Loaded from `<base>/audit/surface-registry.json` or defaulting to the
/// three built-in surfaces. New surfaces are registry entries (config),
/// not code changes — per F-SEAM-08.
///
/// Internally stored as a `HashSet` for O(1) `contains` lookups.
#[derive(Debug, Clone)]
pub struct SurfaceRegistry {
    surfaces: std::collections::HashSet<String>,
}

impl SurfaceRegistry {
    /// Default built-in surfaces used when no registry file is present.
    const DEFAULTS: &'static [&'static str] = &["cc", "codex", "gemini"];

    /// Load the registry from `<base>/audit/surface-registry.json`.
    ///
    /// Returns the default registry (`["cc","codex","gemini"]`) when the file
    /// is absent. Returns `RegistryLoad` error when:
    /// - The file is present but cannot be read.
    /// - The file is present but not a JSON array of strings.
    /// - The file contains more than `SURFACE_REGISTRY_MAX_ENTRIES` entries
    ///   (treated as malformed).
    pub fn load(base: &Path) -> Result<Self, crate::audit::seam::error::SeamError> {
        let path = base.join("audit").join("surface-registry.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let raw: Vec<String> = serde_json::from_slice(&bytes)
                    .map_err(|_| crate::audit::seam::error::SeamError::RegistryLoad)?;
                // An empty array would reject EVERY surface (quarantine-everything)
                // while `csq doctor` reported "ok" — a diagnostic-honesty lie (R2
                // F-R2-1). An absent file is the supported "I want defaults" path;
                // an explicit `[]` is never a valid intended state → treat as malformed.
                if raw.is_empty() {
                    tracing::warn!(
                        error_kind = "seam_registry_invalid",
                        "seam: surface-registry.json is an empty array; treating as malformed \
                         (remove the file to use the cc/codex/gemini defaults)"
                    );
                    return Err(crate::audit::seam::error::SeamError::RegistryLoad);
                }
                if raw.len() > SURFACE_REGISTRY_MAX_ENTRIES {
                    tracing::warn!(
                        error_kind = "seam_registry_invalid",
                        count = raw.len(),
                        max = SURFACE_REGISTRY_MAX_ENTRIES,
                        "seam: surface-registry.json exceeds max entry limit; treating as malformed"
                    );
                    return Err(crate::audit::seam::error::SeamError::RegistryLoad);
                }
                // LOW-1: allowlist charset validation for surface ids.
                //
                // Allowed chars: ASCII alphanumeric, '-', '.', '_'.
                // Rationale for the ALLOWLIST (not denylist) approach:
                //   - `matrix_content_hash` formats entries as "surface:state\n"
                //     so ':' and '\n' corrupt domain separation.
                //   - `csq doctor` Drift text outputs via `drift.join(", ")` so
                //     ',' and '"' and spaces would corrupt operator-visible output.
                //   - Allowlisting closes all current and future punctuation
                //     injection vectors with a single predicate.
                //
                // Permitted examples: "cc", "codex", "gemini", "custom-lane",
                //   ".coc" (loom#392 leading-dot form), "my_surface_2".
                // The rejected id is NOT interpolated into the log — fixed vocab only.
                for id in &raw {
                    let valid = !id.is_empty()
                        && id
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
                    if !valid {
                        tracing::warn!(
                            error_kind = "seam_registry_invalid",
                            "seam: surface-registry.json contains a surface id with \
                             characters outside the allowed set [a-zA-Z0-9._-]; \
                             treating as malformed"
                        );
                        return Err(crate::audit::seam::error::SeamError::RegistryLoad);
                    }
                }
                // Deduplicate into HashSet for O(1) lookups.
                let surfaces: std::collections::HashSet<String> = raw.into_iter().collect();
                Ok(Self { surfaces })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Absent = use defaults; do NOT write the file (per spec).
                Ok(Self::default())
            }
            Err(_) => Err(crate::audit::seam::error::SeamError::RegistryLoad),
        }
    }

    /// Returns `true` when `surface` is in the registry.
    ///
    /// O(1) — backed by a `HashSet`.
    pub fn contains(&self, surface: &str) -> bool {
        self.surfaces.contains(surface)
    }

    /// Returns an iterator over the surface ids in the registry.
    ///
    /// Iteration order is unspecified (backed by `HashSet`). Callers that
    /// need deterministic order (e.g. content-hashing) MUST sort the
    /// result themselves.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.surfaces.iter().map(String::as_str)
    }
}

impl Default for SurfaceRegistry {
    fn default() -> Self {
        Self {
            surfaces: Self::DEFAULTS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-version decoder dispatcher (F-SEAM-01, ADR-B2)
// ---------------------------------------------------------------------------

/// Outcome of dispatching on `f101_schema_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// The version is registered and a decoder is available.
    KnownVersion,
    /// The version is not registered — park in `.pending/provenance/`.
    UnknownVersion,
}

/// Registry of F101-1 schema version → decoder.
///
/// As of M18-bind the PRODUCTION registry registers exactly ONE arm — `"1"`
/// (the frozen F101-1 v1 schema, decoded by `decode::v1::decode_v1`). An event
/// whose `f101_schema_version` is `"1"` dispatches to the v1 decoder; any other
/// version is `UnknownVersion` and is parked visibly in `.pending/provenance/`
/// (no lossy-parse). A future frozen version is an additional registry arm, not
/// a dispatcher code change.
///
/// A `#[cfg(test)]` constructor additionally registers a synthetic `test-v0` arm
/// so the legacy `F101Envelope` scaffolding pipeline stays unit-testable.
pub struct VersionRegistry {
    /// The registered schema versions. Production registers exactly `"1"`
    /// (M18-bind); the test constructor adds `test-v0`.
    #[allow(dead_code)]
    registered: std::collections::HashSet<String>,
}

impl VersionRegistry {
    /// Production constructor — registers `"1"` (M18-bind).
    ///
    /// Version `"1"` is the frozen F101-1 schema version registered as the
    /// first production decoder arm. Events with `schema_version: 1` are now
    /// dispatched to `decode::v1::decode_v1` instead of being parked.
    pub fn production() -> Self {
        let mut registered = std::collections::HashSet::new();
        registered.insert("1".to_string());
        Self { registered }
    }

    /// Dispatch on `f101_schema_version`.
    ///
    /// Returns `KnownVersion` when the version is registered — `"1"` in
    /// production (M18-bind), plus `test-v0` under the test constructor —
    /// `UnknownVersion` otherwise.
    ///
    /// There is NO lossy-parse path: an unknown version parks visibly, it
    /// is never silently processed.
    pub fn dispatch(&self, version: &str) -> DispatchOutcome {
        if self.registered.contains(version) {
            DispatchOutcome::KnownVersion
        } else {
            DispatchOutcome::UnknownVersion
        }
    }
}

/// Test-only constructor that registers a synthetic version arm so the full
/// pipeline (envelope → attestation → ProvenanceAnchored) is exercisable in
/// unit tests without the frozen F101-1 decoder being in production.
#[cfg(any(test, feature = "test-utils"))]
impl VersionRegistry {
    /// Constructs a registry with a single test version registered.
    ///
    /// The test version string is `"test-v0"`. Pass this version in the
    /// `f101_schema_version` field of a test event to exercise the
    /// `KnownVersion` path and trigger the full sign-over-exact-bytes →
    /// ProvenanceAnchored pipeline.
    pub fn with_test_version() -> Self {
        let mut registered = std::collections::HashSet::new();
        registered.insert(TEST_VERSION.to_string());
        Self { registered }
    }
}

/// The synthetic version string used by `VersionRegistry::with_test_version`.
///
/// Only meaningful in `#[cfg(test)]` / `test-utils` contexts. Not registered
/// in the production dispatcher.
#[cfg(any(test, feature = "test-utils"))]
pub const TEST_VERSION: &str = "test-v0";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::seam::error::SeamError;
    use tempfile::TempDir;

    fn write_registry(base: &Path, json: &str) {
        let dir = base.join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("surface-registry.json"), json).unwrap();
    }

    #[test]
    fn absent_registry_uses_defaults() {
        let dir = TempDir::new().unwrap();
        let reg = SurfaceRegistry::load(dir.path()).expect("absent → defaults");
        assert!(reg.contains("cc") && reg.contains("codex") && reg.contains("gemini"));
        assert!(!reg.contains("nope"));
    }

    #[test]
    fn empty_array_registry_is_rejected() {
        // R2 F-R2-1: an explicit `[]` would quarantine every event while doctor
        // reported "ok". It MUST be treated as malformed, not silently accepted.
        let dir = TempDir::new().unwrap();
        write_registry(dir.path(), "[]");
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "empty-array registry must be rejected as malformed (F-R2-1)"
        );
    }

    #[test]
    fn malformed_and_oversized_registries_are_rejected() {
        let dir = TempDir::new().unwrap();
        write_registry(dir.path(), "{ not an array");
        assert!(matches!(
            SurfaceRegistry::load(dir.path()),
            Err(SeamError::RegistryLoad)
        ));

        let too_many = (0..=SURFACE_REGISTRY_MAX_ENTRIES)
            .map(|i| format!("\"s{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        write_registry(dir.path(), &format!("[{too_many}]"));
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            ">{SURFACE_REGISTRY_MAX_ENTRIES} entries must be rejected"
        );
    }

    #[test]
    fn valid_custom_registry_loads_and_dedups() {
        let dir = TempDir::new().unwrap();
        write_registry(dir.path(), r#"["cc","cc","coc"]"#);
        let reg = SurfaceRegistry::load(dir.path()).expect("valid → ok");
        assert!(reg.contains("cc") && reg.contains("coc"));
        assert!(!reg.contains("gemini"), "custom registry replaces defaults");
    }

    // ── LOW-1: surface-id allowlist charset validation ─────────────────────────
    //
    // Allowed set: [a-zA-Z0-9._-] (ASCII alphanumeric + hyphen + dot + underscore).
    // The ALLOWLIST (not denylist) closes all punctuation injection vectors:
    //   ':'/'\n' → matrix_content_hash domain corruption.
    //   ','      → drift.join(", ") output injection.
    //   '"'      → JSON injection in operator-visible output.
    //   spaces   → drift display corruption.

    /// LOW-1: surface ids containing ':' must be rejected (not in allowlist).
    /// A surface id like "cc:wired" would corrupt the matrix_content_hash
    /// domain separation ("surface:state\n" format).
    #[test]
    fn surface_id_with_colon_is_rejected() {
        let dir = TempDir::new().unwrap();
        write_registry(dir.path(), r#"["cc:wired","codex"]"#);
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "surface id containing ':' must be rejected (allowlist)"
        );
    }

    /// LOW-1: surface ids containing '\n' must be rejected (not in allowlist).
    #[test]
    fn surface_id_with_newline_is_rejected() {
        let dir = TempDir::new().unwrap();
        // JSON string with embedded newline escape.
        write_registry(dir.path(), "[\"cc\\nmalicious\",\"codex\"]");
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "surface id containing newline must be rejected (allowlist)"
        );
    }

    /// LOW-1: surface ids containing control chars must be rejected (not in allowlist).
    #[test]
    fn surface_id_with_control_char_is_rejected() {
        let dir = TempDir::new().unwrap();
        // JSON string with embedded tab (control char U+0009).
        write_registry(dir.path(), "[\"cc\\u0009malicious\"]");
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "surface id containing control char must be rejected (allowlist)"
        );
    }

    /// LOW-1: surface ids containing ',' must be rejected — comma would inject
    /// into `drift.join(", ")` operator-visible output.
    #[test]
    fn surface_id_with_comma_is_rejected() {
        let dir = TempDir::new().unwrap();
        write_registry(dir.path(), r#"["cc,injected","codex"]"#);
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "surface id containing ',' must be rejected (allowlist — drift.join injection)"
        );
    }

    /// LOW-1: surface ids containing '"' must be rejected — quote would inject
    /// into JSON operator-visible output and drift display.
    #[test]
    fn surface_id_with_double_quote_is_rejected() {
        let dir = TempDir::new().unwrap();
        // JSON-escaped double-quote inside a string value: ["cc\"x","codex"].
        write_registry(dir.path(), r#"["cc\"x","codex"]"#);
        // This is invalid JSON (unescaped quote in JSON context) — parse will fail
        // before charset check; still results in RegistryLoad error.
        // Use a properly escaped variant to test charset directly.
        // serde_json does not expose bare U+0022 in a valid parsed String, so
        // the charset check path is exercised via a tab (U+0009) which serde
        // does decode into the String but the allowlist rejects.
        // This test verifies the JSON parse path — the result is RegistryLoad.
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "surface id with invalid JSON (embedded quote) must be rejected"
        );
    }

    /// LOW-1: surface ids containing spaces must be rejected (not in allowlist).
    /// Spaces would corrupt `drift.join(", ")` display.
    #[test]
    fn surface_id_with_space_is_rejected() {
        let dir = TempDir::new().unwrap();
        write_registry(dir.path(), r#"["cc lane","codex"]"#);
        assert!(
            matches!(
                SurfaceRegistry::load(dir.path()),
                Err(SeamError::RegistryLoad)
            ),
            "surface id containing space must be rejected (allowlist)"
        );
    }

    /// LOW-1: valid surface ids from the allowlist [a-zA-Z0-9._-] pass through.
    /// Includes: multi-word hyphenated ("custom-lane"), leading-dot (".coc"
    /// per loom#392), underscore ("my_surface"), and alphanumeric ("lane2").
    #[test]
    fn valid_surface_ids_pass_charset_check() {
        let dir = TempDir::new().unwrap();
        write_registry(
            dir.path(),
            r#"["cc","codex","gemini","custom-lane",".coc","my_surface","lane2"]"#,
        );
        let reg = SurfaceRegistry::load(dir.path()).expect("valid surface ids must load");
        assert!(reg.contains("cc"), "cc must be in registry");
        assert!(reg.contains("codex"), "codex must be in registry");
        assert!(reg.contains("gemini"), "gemini must be in registry");
        assert!(
            reg.contains("custom-lane"),
            "custom-lane (hyphen) must pass allowlist"
        );
        assert!(
            reg.contains(".coc"),
            ".coc (leading dot, loom#392) must pass allowlist"
        );
        assert!(reg.contains("my_surface"), "underscore must pass allowlist");
        assert!(reg.contains("lane2"), "alphanumeric must pass allowlist");
    }
}
