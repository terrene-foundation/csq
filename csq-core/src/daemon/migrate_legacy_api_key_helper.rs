//! One-shot migration: strip the legacy `apiKeyHelper` field from
//! 3P settings files written before the alpha.7 → alpha.8 fix
//! (issue #184).
//!
//! # The bug being repaired
//!
//! Before alpha.8, `bind_provider_to_slot` and the provider-level
//! `save_settings` path serialized `Provider::system_primer` (a long
//! English instruction string like *"You are a helpful coding
//! assistant…"*) under a top-level `apiKeyHelper` key. Claude Code
//! interprets `apiKeyHelper` as a SHELL COMMAND that prints an API
//! key on stdout. So at every CC launch the user sees:
//!
//! ```text
//! apiKeyHelper failed: exited 127: /bin/sh: You: command not found
//! ⚠ Auth conflict: Both a token (ANTHROPIC_AUTH_TOKEN) and an API
//!   key (apiKeyHelper) are set.
//! ```
//!
//! The write paths were hardened in `csq-core/src/providers/settings.rs`
//! (line 151 NOTE) and `csq-core/src/accounts/third_party.rs` (regression
//! test `bind_strips_api_key_helper`), but **on-disk artifacts on
//! upgraded machines were never cleaned up**. This module is the
//! cleanup pass.
//!
//! # Migration semantics
//!
//! Walks two file shapes under `base_dir`:
//!
//! 1. `<base_dir>/config-<N>/settings.json` — slot-bound settings.
//! 2. `<base_dir>/settings-*.json` — provider-level settings (the
//!    bare `settings.json` is the OAuth Anthropic shape and is NOT
//!    touched).
//!
//! A file is rewritten ONLY when BOTH conditions hold:
//!
//! - top-level `apiKeyHelper` is present
//! - `env.ANTHROPIC_AUTH_TOKEN` is present
//!
//! Both-present is the unambiguous legacy-bug signature: csq itself
//! never wrote an `apiKeyHelper` shape. Files where `apiKeyHelper`
//! is the only auth source (impossible from csq, but defensive) are
//! left alone.
//!
//! Idempotent by construction — second run finds nothing to strip.
//!
//! # Out of scope
//!
//! User-authored `apiKeyHelper` entries outside csq-managed files
//! (`~/.claude/settings.json`, etc.) are NOT touched. Those are the
//! user's own CC config and csq must not edit them.

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Outcome counters for the migration. Surfaced via the daemon's
/// reconciler summary + asserted in unit tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApiKeyHelperMigrationSummary {
    /// Number of candidate files inspected (`config-N/settings.json`
    /// and `settings-*.json`).
    pub files_seen: usize,
    /// Number of files whose `apiKeyHelper` field was stripped.
    pub files_migrated: usize,
}

/// Runs the migration. Safe to call repeatedly; idempotent.
///
/// I/O failures on individual files are logged at WARN and counted
/// against `files_seen` but do NOT halt the walk — one corrupt file
/// must not block migration of the rest.
pub fn run(base_dir: &Path) -> ApiKeyHelperMigrationSummary {
    let mut summary = ApiKeyHelperMigrationSummary::default();

    for path in discover_candidate_files(base_dir) {
        summary.files_seen += 1;
        match migrate_one(&path) {
            Ok(true) => {
                summary.files_migrated += 1;
                info!(
                    error_kind = "migrate_strip_api_key_helper",
                    path = %path.display(),
                    "stripped legacy apiKeyHelper"
                );
            }
            Ok(false) => {
                debug!(
                    path = %path.display(),
                    "no legacy apiKeyHelper present; leaving file untouched"
                );
            }
            Err(e) => {
                warn!(
                    error_kind = "migrate_strip_api_key_helper_failed",
                    path = %path.display(),
                    error = %e,
                    "skipping file due to I/O or parse error"
                );
            }
        }
    }

    summary
}

/// Enumerates the candidate file paths in deterministic
/// (directory-order-independent) order. Returns paths whose existence
/// has been verified at enumeration time; per-file read may still
/// fail later if a concurrent process unlinks them.
fn discover_candidate_files(base_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return out, // base_dir absent → nothing to migrate
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };

        // Slot-bound settings: <base_dir>/config-<N>/settings.json
        if let Some(slot_str) = name_str.strip_prefix("config-") {
            if slot_str.parse::<u16>().is_ok() {
                let p = entry.path().join("settings.json");
                if p.is_file() {
                    out.push(p);
                }
                continue;
            }
        }

        // Provider-level settings: <base_dir>/settings-<provider>.json
        // Note the dash — the bare `settings.json` (Anthropic OAuth
        // shape) is intentionally excluded.
        if let Some(rest) = name_str.strip_prefix("settings-") {
            if rest.ends_with(".json") {
                let p = entry.path();
                if p.is_file() {
                    out.push(p);
                }
            }
        }
    }

    out.sort();
    out
}

/// Inspects one settings file. Returns `Ok(true)` if the file was
/// rewritten, `Ok(false)` if it was missing, empty, unparseable,
/// non-object at the root, or did not satisfy the both-present
/// strip predicate.
///
/// On rewrite: atomic via `unique_tmp_path` + `atomic_replace`,
/// permissions clamped to 0o600 via `secure_file` so the file
/// stays at the same posture the original 3P settings writers use
/// (the file contains `env.ANTHROPIC_AUTH_TOKEN`).
fn migrate_one(path: &Path) -> Result<bool> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) if !c.trim().is_empty() => c,
        Ok(_) => return Ok(false), // empty file
        Err(e) => return Err(anyhow!(e).context(format!("read {}", path.display()))),
    };

    let mut value: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Ok(false), // unparseable; leave alone (user repair surface)
    };

    let Some(obj) = value.as_object_mut() else {
        return Ok(false); // top-level not an object
    };

    if !is_legacy_api_key_helper_shape(obj) {
        return Ok(false);
    }

    obj.remove("apiKeyHelper");

    let json = serde_json::to_string_pretty(&value)
        .with_context(|| format!("serialize after strip {}", path.display()))?;

    let tmp = unique_tmp_path(path);
    // Per `rules/security.md` §5a: clean up the umask-default tmp file
    // on every failure branch so we never leave a token-bearing file
    // at world-readable perms on disk.
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(e).context(format!("write tmp {}", tmp.display())));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("secure_file {}: {e}", tmp.display()));
    }
    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("atomic replace {}: {e}", path.display()));
    }

    Ok(true)
}

/// The "both present" signature that uniquely identifies a legacy
/// pre-alpha.8 csq-written settings file. csq has never written
/// `apiKeyHelper` without also setting `env.ANTHROPIC_AUTH_TOKEN`,
/// so the two together are an unambiguous fingerprint of the bug.
fn is_legacy_api_key_helper_shape(obj: &Map<String, Value>) -> bool {
    let has_helper = obj.get("apiKeyHelper").is_some();
    if !has_helper {
        return false;
    }
    let has_token = obj
        .get("env")
        .and_then(|v| v.as_object())
        .and_then(|env| env.get("ANTHROPIC_AUTH_TOKEN"))
        .is_some();
    has_token
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn read_json(path: &Path) -> Value {
        let s = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    fn legacy_settings_with_token() -> &'static str {
        r#"{
            "apiKeyHelper": "You are a helpful coding assistant. Use the tools available to you.",
            "env": {
                "ANTHROPIC_AUTH_TOKEN": "tok_abc123",
                "ANTHROPIC_BASE_URL": "https://api.minimax.io",
                "ANTHROPIC_MODEL": "minimax-m2"
            },
            "permissions": {"defaultMode": "auto"}
        }"#
    }

    // ── Acceptance criteria from issue #184 ───────────────────────

    /// Acceptance #1: settings file with legacy apiKeyHelper +
    /// env.ANTHROPIC_AUTH_TOKEN → migrator strips helper, preserves
    /// env, preserves file perms (0o600).
    #[cfg(unix)]
    #[test]
    fn strips_helper_and_preserves_env_and_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let p = base.join("config-3").join("settings.json");
        write(&p, legacy_settings_with_token());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();

        let summary = run(base);

        assert_eq!(summary.files_seen, 1);
        assert_eq!(summary.files_migrated, 1);

        let v = read_json(&p);
        assert!(
            v.get("apiKeyHelper").is_none(),
            "apiKeyHelper must be stripped"
        );
        assert_eq!(v["env"]["ANTHROPIC_AUTH_TOKEN"], "tok_abc123");
        assert_eq!(v["env"]["ANTHROPIC_BASE_URL"], "https://api.minimax.io");
        assert_eq!(v["env"]["ANTHROPIC_MODEL"], "minimax-m2");
        assert_eq!(v["permissions"]["defaultMode"], "auto");

        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "file perms must be clamped to 0o600 by secure_file"
        );
    }

    /// Acceptance #2: clean settings file → migrator is a no-op.
    /// Critically, the mtime must NOT bump (CC reloads on mtime
    /// change per spec 01 §1.4 — an unnecessary mtime tick triggers
    /// every running CC to re-stat for nothing).
    #[test]
    fn clean_settings_file_is_noop_no_mtime_bump() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let p = base.join("config-2").join("settings.json");
        write(
            &p,
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"tok_clean","ANTHROPIC_BASE_URL":"https://api.minimax.io"}}"#,
        );

        let mtime_before = std::fs::metadata(&p).unwrap().modified().unwrap();

        // Sleep enough to make a mtime bump observable on every fs.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let summary = run(base);

        let mtime_after = std::fs::metadata(&p).unwrap().modified().unwrap();

        assert_eq!(summary.files_seen, 1);
        assert_eq!(summary.files_migrated, 0);
        assert_eq!(
            mtime_before, mtime_after,
            "clean file must not be rewritten — mtime must not bump"
        );
    }

    /// Acceptance #3: settings file with apiKeyHelper only (no
    /// token) → migrator leaves it alone. Defensive — csq itself
    /// never writes this shape, but a hypothetical user could.
    #[test]
    fn helper_only_no_token_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let p = base.join("config-7").join("settings.json");
        let user_helper = r#"{"apiKeyHelper":"my-keychain-extractor.sh"}"#;
        write(&p, user_helper);

        let summary = run(base);

        assert_eq!(summary.files_seen, 1);
        assert_eq!(summary.files_migrated, 0);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert_eq!(raw, user_helper, "user-only apiKeyHelper must be preserved");
    }

    /// Acceptance #4: provider-level files (`settings-mm.json`,
    /// `settings-zai.json`) are also walked.
    #[test]
    fn provider_level_files_are_migrated() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let mm = base.join("settings-mm.json");
        let zai = base.join("settings-zai.json");
        write(&mm, legacy_settings_with_token());
        write(&zai, legacy_settings_with_token());

        let summary = run(base);

        assert_eq!(summary.files_seen, 2);
        assert_eq!(summary.files_migrated, 2);
        assert!(read_json(&mm).get("apiKeyHelper").is_none());
        assert!(read_json(&zai).get("apiKeyHelper").is_none());
    }

    /// The bare `settings.json` (Anthropic OAuth shape) at base_dir
    /// root is intentionally excluded — the prefix is `settings-`,
    /// not `settings`.
    #[test]
    fn bare_settings_json_at_base_root_is_not_touched() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let bare = base.join("settings.json");
        write(&bare, legacy_settings_with_token());

        let summary = run(base);

        assert_eq!(summary.files_seen, 0, "bare settings.json must be skipped");
        assert_eq!(summary.files_migrated, 0);
        let v = read_json(&bare);
        assert!(
            v.get("apiKeyHelper").is_some(),
            "bare settings.json must remain untouched"
        );
    }

    /// Idempotency: running twice migrates only on the first pass.
    #[test]
    fn second_run_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let p = base.join("config-9").join("settings.json");
        write(&p, legacy_settings_with_token());

        let first = run(base);
        let second = run(base);

        assert_eq!(first.files_migrated, 1);
        assert_eq!(second.files_migrated, 0);
        assert_eq!(second.files_seen, 1);
    }

    /// Multiple slots with mixed legacy / clean / helper-only state
    /// produce exactly the right counts.
    #[test]
    fn mixed_population_counts_are_correct() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        write(
            &base.join("config-1").join("settings.json"),
            legacy_settings_with_token(),
        );
        write(
            &base.join("config-2").join("settings.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"clean"}}"#,
        );
        write(
            &base.join("config-3").join("settings.json"),
            r#"{"apiKeyHelper":"user-script.sh"}"#,
        );
        write(&base.join("settings-mm.json"), legacy_settings_with_token());

        let summary = run(base);

        assert_eq!(summary.files_seen, 4);
        assert_eq!(summary.files_migrated, 2);
    }

    /// Non-numeric `config-` suffix is skipped.
    #[test]
    fn non_numeric_config_suffix_is_skipped() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // `config-foo` is not a valid slot dir.
        let bogus = base.join("config-foo").join("settings.json");
        write(&bogus, legacy_settings_with_token());

        let summary = run(base);

        assert_eq!(summary.files_seen, 0);
        let v = read_json(&bogus);
        assert!(v.get("apiKeyHelper").is_some(), "bogus dir untouched");
    }

    /// Missing base_dir returns an empty summary without error.
    #[test]
    fn missing_base_dir_is_empty_summary() {
        let dir = TempDir::new().unwrap();
        let summary = run(&dir.path().join("nonexistent"));
        assert_eq!(summary.files_seen, 0);
        assert_eq!(summary.files_migrated, 0);
    }

    /// Unparseable JSON is skipped (counted as seen, not migrated)
    /// and the file is preserved verbatim. Matches the install-path
    /// migration's "skip and let the user repair" posture.
    #[test]
    fn unparseable_json_is_skipped_and_preserved() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let p = base.join("config-1").join("settings.json");
        write(&p, "not valid json {{{");

        let summary = run(base);

        assert_eq!(summary.files_seen, 1);
        assert_eq!(summary.files_migrated, 0);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert_eq!(raw, "not valid json {{{");
    }

    /// `is_legacy_api_key_helper_shape` predicate sanity checks.
    #[test]
    fn predicate_requires_both_helper_and_token() {
        let neither: Map<String, Value> = serde_json::from_str(r#"{"env":{}}"#).unwrap();
        assert!(!is_legacy_api_key_helper_shape(&neither));

        let helper_only: Map<String, Value> =
            serde_json::from_str(r#"{"apiKeyHelper":"x"}"#).unwrap();
        assert!(!is_legacy_api_key_helper_shape(&helper_only));

        let token_only: Map<String, Value> =
            serde_json::from_str(r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"t"}}"#).unwrap();
        assert!(!is_legacy_api_key_helper_shape(&token_only));

        let both: Map<String, Value> =
            serde_json::from_str(r#"{"apiKeyHelper":"x","env":{"ANTHROPIC_AUTH_TOKEN":"t"}}"#)
                .unwrap();
        assert!(is_legacy_api_key_helper_shape(&both));
    }
}
