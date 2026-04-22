//! Daemon startup reconciler — clamps invariants the running daemon
//! later relies on (PR-C4).
//!
//! Two passes, both surface-scoped to Codex (the only surface today
//! with the 0o400-outside-refresh invariant + the
//! `cli_auth_credentials_store = "file"` config.toml directive).
//!
//! # Pass 1 — credential mode flip (INV-P08)
//!
//! Walks `{base_dir}/credentials/codex-<N>.json` and flips any file
//! whose mode is not 0o400 back to 0o400 under the per-account
//! `(Surface::Codex, AccountNum)` write mutex (INV-P09). The mutex
//! coordinates with the live refresher so a flip cannot land mid-
//! refresh — the refresher already holds the same mutex through
//! `save_canonical_for`'s 0o400→0o600→write→0o400 dance, so the
//! reconciler simply blocks until any in-flight refresh completes
//! and then asserts the canonical sits at 0o400.
//!
//! Catches the failure mode where `save_canonical_for` crashes
//! between `secure_file` (0o600) and `secure_file_readonly` (0o400)
//! — atomically replaced files always have a mode, but the post-
//! write flip is a separate syscall and a sigkill in between leaves
//! the canonical at 0o600 until the next reconciler pass.
//!
//! # Pass 2 — config.toml drift rewrite (INV-P03)
//!
//! Walks every `config-<N>/config.toml` for slots that have a Codex
//! canonical credential and ensures the file contains
//! `cli_auth_credentials_store = "file"`. If the directive is
//! missing or the value drifted, the reconciler rewrites via
//! `surface::write_config_toml` preserving any existing `model` key
//! (parsed line-wise — csq has no TOML parser dep, and the file
//! shape is fixed by spec 07 §7.3.3 to two keys).
//!
//! Codex respects the file-backed auth store ONLY when this key is
//! present at startup; a rewrite landed AFTER codex starts does not
//! migrate an existing keychain entry. Repairing it at daemon
//! startup means the next `csq run N` (which already requires the
//! daemon — INV-P02) sees a correctly-configured codex.
//!
//! No-op on Windows for Pass 1 — `secure_file_readonly` is a no-op
//! there. Pass 2 still runs to close the config.toml drift gap.

use crate::credentials::file as cred_file;
use crate::credentials::mutex::AccountMutexTable;
use crate::platform::fs::secure_file_readonly;
use crate::providers::catalog::Surface;
use crate::providers::codex::surface as codex_surface;
use crate::types::AccountNum;
use std::path::Path;
use tracing::{debug, info, warn};

/// Outcome counters returned to the daemon start path. Useful for
/// telemetry / `csq doctor` and asserted in unit tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Number of Codex canonical files inspected.
    pub codex_credentials_seen: usize,
    /// Number of Codex canonicals whose mode was already 0o400 → no-op.
    pub codex_credentials_already_ok: usize,
    /// Number of Codex canonicals flipped from 0o600 → 0o400.
    pub codex_credentials_repaired: usize,
    /// Number of `config-<N>/config.toml` files inspected.
    pub config_tomls_seen: usize,
    /// Number of `config.toml` files whose `cli_auth_credentials_store`
    /// key was already `"file"` → no-op.
    pub config_tomls_already_ok: usize,
    /// Number of `config.toml` files rewritten because the directive
    /// was missing or had drifted to a non-`"file"` value.
    pub config_tomls_repaired: usize,
    /// PR-C6: whether a v1→v2 `quota.json` migration ran this start.
    /// `None` means no file existed (fresh install); `Some(false)` means
    /// the file was already at v2; `Some(true)` means the reconciler
    /// rewrote it atomically from v1 to v2.
    pub quota_migrated: Option<bool>,
    /// Number of account records that survived the v1→v2 quota migration
    /// (0 if no migration ran).
    pub quota_accounts_migrated: usize,
}

/// Runs the reconciler synchronously. Safe to call before
/// [`crate::daemon::spawn_refresher`] because both writers
/// (reconciler + refresher) coordinate via the same per-account
/// mutex table.
///
/// Returns a [`ReconcileSummary`] with per-pass counters.
pub fn run_reconciler(base_dir: &Path) -> ReconcileSummary {
    let mut summary = ReconcileSummary::default();
    pass1_codex_credential_mode(base_dir, &mut summary);
    pass2_codex_config_toml(base_dir, &mut summary);
    pass3_quota_v1_to_v2(base_dir, &mut summary);
    info!(
        codex_credentials_seen = summary.codex_credentials_seen,
        codex_credentials_repaired = summary.codex_credentials_repaired,
        config_tomls_seen = summary.config_tomls_seen,
        config_tomls_repaired = summary.config_tomls_repaired,
        quota_migrated = ?summary.quota_migrated,
        quota_accounts_migrated = summary.quota_accounts_migrated,
        "startup reconciler complete"
    );
    summary
}

/// Pass 3 — PR-C6 quota v1→v2 migration.
///
/// Runs BEFORE any poller starts writing, so live writers never race
/// the migration. Idempotent: an already-v2 file is left untouched.
/// Atomic: a SIGKILL between tmp write and rename leaves the original
/// v1 file intact and the next daemon start re-runs the migration.
///
/// Non-fatal on error: a corrupt file is logged but does not crash
/// the daemon. The usage poller will still write new quota records
/// (with schema_version=2) after starting, replacing the corrupt
/// file on first successful write.
fn pass3_quota_v1_to_v2(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::quota::state::{migrate_v1_to_v2_if_needed, MigrationOutcome};
    match migrate_v1_to_v2_if_needed(base_dir) {
        Ok(MigrationOutcome::NoFile) => {
            summary.quota_migrated = None;
        }
        Ok(MigrationOutcome::AlreadyV2 { schema_version }) => {
            debug!(
                schema_version,
                "pass 3 quota v1→v2: file already at v2, skipping"
            );
            summary.quota_migrated = Some(false);
        }
        Ok(MigrationOutcome::Migrated { account_count }) => {
            info!(
                account_count,
                "pass 3 quota v1→v2: rewrote quota.json with schema_version=2"
            );
            summary.quota_migrated = Some(true);
            summary.quota_accounts_migrated = account_count;
        }
        Err(e) => {
            warn!(
                error_kind = "quota_migration_failed",
                error = %e,
                "pass 3 quota v1→v2: migration error — leaving file as-is; next poller write will overwrite"
            );
            summary.quota_migrated = None;
        }
    }
}

fn pass1_codex_credential_mode(base_dir: &Path, summary: &mut ReconcileSummary) {
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let Some(num_str) = stem.strip_prefix("codex-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };
        let account = match AccountNum::try_from(id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        summary.codex_credentials_seen += 1;

        // Acquire the per-account mutex BEFORE inspecting the mode.
        // The refresher's `save_canonical_for` holds the same mutex
        // while it's mid-flip; waiting here means we always observe
        // the post-write steady state (0o400) rather than the
        // transient 0o600 window.
        let slot_mutex = AccountMutexTable::global().get_or_insert(Surface::Codex, account);
        let _guard = match slot_mutex.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if is_already_readonly(&path) {
            summary.codex_credentials_already_ok += 1;
            continue;
        }

        match secure_file_readonly(&path) {
            Ok(()) => {
                summary.codex_credentials_repaired += 1;
                debug!(
                    account = id,
                    surface = "codex",
                    path = %path.display(),
                    "reconciler flipped Codex canonical to 0o400 (drift from prior crash mid-write)"
                );
            }
            Err(e) => {
                warn!(
                    account = id,
                    surface = "codex",
                    error_kind = "reconciler_mode_flip_failed",
                    error = %e,
                    "reconciler could not flip Codex canonical to 0o400"
                );
            }
        }
    }
}

#[cfg(unix)]
fn is_already_readonly(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => (m.permissions().mode() & 0o777) == 0o400,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_already_readonly(_path: &Path) -> bool {
    // Windows: no POSIX 0o400 concept — the credential writer uses
    // DACLs at file-creation time. The reconciler treats every file
    // as "already OK" so the no-op `secure_file_readonly` does not
    // bump the repair counter.
    true
}

fn pass2_codex_config_toml(base_dir: &Path, summary: &mut ReconcileSummary) {
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let Some(num_str) = stem.strip_prefix("codex-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };
        let account = match AccountNum::try_from(id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        summary.config_tomls_seen += 1;

        let toml_path = codex_surface::config_toml_path(base_dir, account);
        let existing = std::fs::read_to_string(&toml_path).ok();
        let existing_model = existing.as_deref().and_then(extract_model_key);
        let directive_ok = existing
            .as_deref()
            .map(has_file_backed_directive)
            .unwrap_or(false);

        if directive_ok {
            summary.config_tomls_already_ok += 1;
            continue;
        }

        // Repair: rewrite via the canonical writer, preserving the
        // existing model key when present. Falls back to the
        // catalog default model otherwise.
        let model: String = match existing_model.as_deref() {
            Some(m) => m.to_string(),
            None => codex_surface::default_model().to_string(),
        };
        match codex_surface::write_config_toml(base_dir, account, &model) {
            Ok(()) => {
                summary.config_tomls_repaired += 1;
                info!(
                    account = id,
                    surface = "codex",
                    model = %model,
                    "reconciler rewrote config.toml — `cli_auth_credentials_store = \"file\"` was missing or drifted"
                );
            }
            Err(e) => {
                warn!(
                    account = id,
                    surface = "codex",
                    error_kind = "reconciler_config_toml_write_failed",
                    error = %e,
                    "reconciler could not rewrite config.toml"
                );
            }
        }

        // Verify the canonical credential file is loadable as a Codex
        // variant before we trust the slot — protects against the
        // operator pasting an Anthropic shape into a `codex-N.json`
        // path (already guarded at discovery; the reconciler re-tags
        // it for the daemon-start log).
        if let Err(e) = cred_file::load(&path) {
            // CredentialError::Corrupt may carry a serde error Display
            // that echoes credential JSON fragments — redact first.
            let redacted = crate::error::redact_tokens(&e.to_string());
            warn!(
                account = id,
                surface = "codex",
                error_kind = "reconciler_canonical_unreadable",
                error = %redacted,
                "Codex canonical credential file is not parseable — slot will be skipped by the refresher until repaired"
            );
        }
    }
}

/// Returns true iff the `cli_auth_credentials_store` key is set to
/// `"file"` exactly. Tolerates surrounding whitespace; rejects any
/// other value. Comments after the value are ignored.
fn has_file_backed_directive(toml: &str) -> bool {
    for raw in toml.lines() {
        let line = raw.split('#').next().unwrap_or(raw).trim();
        let Some(rest) = line.strip_prefix("cli_auth_credentials_store") else {
            continue;
        };
        let after_eq = rest.trim_start().strip_prefix('=').map(|s| s.trim());
        if let Some(value) = after_eq {
            // Accept only the canonical double-quoted form: "file".
            if value == "\"file\"" {
                return true;
            }
            // Single-quoted TOML literal "file" is also valid TOML.
            if value == "'file'" {
                return true;
            }
        }
    }
    false
}

/// Extracts the value of the top-level `model = "..."` key, if
/// present. Returns the unquoted string. Tolerates leading/trailing
/// whitespace and inline `# comments`.
fn extract_model_key(toml: &str) -> Option<String> {
    for raw in toml.lines() {
        let line = raw.split('#').next().unwrap_or(raw).trim();
        let Some(rest) = line.strip_prefix("model") else {
            continue;
        };
        let after_eq = rest.trim_start().strip_prefix('=').map(|s| s.trim())?;
        // Strip quotes (double or single) on both ends.
        if let Some(inner) = after_eq.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            return Some(inner.to_string());
        }
        if let Some(inner) = after_eq
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
        {
            return Some(inner.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn install_codex_canonical(base: &Path, id: u16) {
        let num = AccountNum::try_from(id).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-test".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.payload.sig".into(),
                refresh_token: Some("rt_test".into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        // Use save_canonical_for so the canonical lands at 0o400 (the
        // INV-P08 steady state). Plain `save` lands at 0o600 — which is
        // the post-crash drifted state we exercise separately.
        cred_file::save_canonical_for(base, num, &creds).unwrap();
    }

    #[test]
    fn run_reconciler_on_empty_dir_is_noop() {
        let dir = TempDir::new().unwrap();
        let s = run_reconciler(dir.path());
        assert_eq!(s, ReconcileSummary::default());
    }

    /// Pass 1: A canonical sitting at 0o600 (post-crash mid-write) is
    /// flipped to 0o400. The repaired counter increments.
    #[cfg(unix)]
    #[test]
    fn pass1_flips_0o600_canonical_to_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 7);

        // The canonical writer normally lands at 0o400; force 0o600
        // to simulate a crash between secure_file (write window) and
        // secure_file_readonly (close window).
        let canonical = cred_file::canonical_path_for(
            dir.path(),
            AccountNum::try_from(7u16).unwrap(),
            Surface::Codex,
        );
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let s = run_reconciler(dir.path());
        assert_eq!(s.codex_credentials_seen, 1);
        assert_eq!(s.codex_credentials_repaired, 1);
        assert_eq!(s.codex_credentials_already_ok, 0);

        assert_eq!(
            std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o400,
            "reconciler must flip canonical back to 0o400"
        );
    }

    /// Pass 1: A canonical already at 0o400 is left alone (no
    /// double-write under the mutex).
    #[cfg(unix)]
    #[test]
    fn pass1_leaves_0o400_canonical_untouched() {
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 8);
        // save_canonical_for landed it at 0o400 already.

        let s = run_reconciler(dir.path());
        assert_eq!(s.codex_credentials_seen, 1);
        assert_eq!(s.codex_credentials_already_ok, 1);
        assert_eq!(s.codex_credentials_repaired, 0);
    }

    /// Pass 2: missing config.toml is created with the default model
    /// + the file-backed directive.
    #[test]
    fn pass2_creates_missing_config_toml_with_directive() {
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 9);

        let s = run_reconciler(dir.path());
        assert_eq!(s.config_tomls_seen, 1);
        assert_eq!(s.config_tomls_repaired, 1);

        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(9u16).unwrap());
        let contents = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            contents.contains("cli_auth_credentials_store = \"file\""),
            "rewritten config.toml must carry the directive: {contents}"
        );
        assert!(
            contents.contains("model = "),
            "rewritten config.toml must carry a model key: {contents}"
        );
    }

    /// Pass 2: a config.toml whose `cli_auth_credentials_store` key
    /// was manually deleted gets rewritten, preserving the existing
    /// model key value.
    #[test]
    fn pass2_rewrites_drifted_config_toml_preserving_model() {
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 10);

        // Write a drifted config.toml: model is set, but the
        // file-backed directive was removed.
        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(10u16).unwrap());
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        std::fs::write(&toml_path, "model = \"gpt-custom-user-pick\"\n").unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.config_tomls_repaired, 1);

        let contents = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            contents.contains("cli_auth_credentials_store = \"file\""),
            "directive must be present after repair: {contents}"
        );
        assert!(
            contents.contains("model = \"gpt-custom-user-pick\""),
            "user's model selection must be preserved across repair: {contents}"
        );
    }

    /// Pass 2: a config.toml that already has the directive is left
    /// alone (no rewrite).
    #[test]
    fn pass2_leaves_correct_config_toml_untouched() {
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 11);

        // Write a correct config.toml.
        codex_surface::write_config_toml(
            dir.path(),
            AccountNum::try_from(11u16).unwrap(),
            "gpt-keep",
        )
        .unwrap();
        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(11u16).unwrap());
        let before = std::fs::metadata(&toml_path).unwrap().modified().unwrap();

        // Sleep 10ms so a stray rewrite would change mtime.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let s = run_reconciler(dir.path());
        assert_eq!(s.config_tomls_already_ok, 1);
        assert_eq!(s.config_tomls_repaired, 0);

        let after = std::fs::metadata(&toml_path).unwrap().modified().unwrap();
        assert_eq!(before, after, "untouched file must keep its mtime");
    }

    #[test]
    fn has_file_backed_directive_accepts_canonical_form() {
        assert!(has_file_backed_directive(
            "cli_auth_credentials_store = \"file\"\n"
        ));
        assert!(has_file_backed_directive(
            "cli_auth_credentials_store='file'\nmodel = \"x\"\n"
        ));
    }

    #[test]
    fn has_file_backed_directive_rejects_drift() {
        assert!(!has_file_backed_directive("model = \"x\"\n"));
        assert!(!has_file_backed_directive(
            "cli_auth_credentials_store = \"keychain\"\n"
        ));
        assert!(!has_file_backed_directive(
            "cli_auth_credentials_store = \"FILE\"\n" // case-sensitive
        ));
    }

    #[test]
    fn has_file_backed_directive_strips_inline_comment() {
        assert!(has_file_backed_directive(
            "cli_auth_credentials_store = \"file\"  # csq-managed\n"
        ));
    }

    #[test]
    fn extract_model_key_round_trips() {
        assert_eq!(
            extract_model_key("model = \"gpt-test\"\n"),
            Some("gpt-test".into())
        );
        assert_eq!(
            extract_model_key("model='gpt-single'\n"),
            Some("gpt-single".into())
        );
        assert_eq!(extract_model_key("# model = \"x\"\n"), None);
        assert_eq!(extract_model_key("nomodel = \"x\"\n"), None);
    }

    /// Files at non-`codex-N.json` paths in `credentials/` are
    /// ignored by both passes (no false positives on Anthropic
    /// canonical files or unrelated junk).
    #[test]
    fn reconciler_ignores_non_codex_credential_files() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("not-a-codex-file.txt"), b"junk").unwrap();
        std::fs::write(creds_dir.join("codex-bogus.json"), b"{}").unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.codex_credentials_seen, 0);
        assert_eq!(s.config_tomls_seen, 0);
    }

    // ─── PR-C6 pass 3 tests ───────────────────────────────────────

    #[test]
    fn pass3_no_quota_file_reports_none() {
        let dir = TempDir::new().unwrap();
        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, None);
        assert_eq!(s.quota_accounts_migrated, 0);
    }

    #[test]
    fn pass3_migrates_v1_to_v2_and_reports_count() {
        let dir = TempDir::new().unwrap();
        let v1 = r#"{
            "accounts": {
                "5": {
                    "five_hour": {"used_percentage": 20.0, "resets_at": 4102444800},
                    "updated_at": 123.0
                }
            }
        }"#;
        std::fs::write(dir.path().join("quota.json"), v1).unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, Some(true));
        assert_eq!(s.quota_accounts_migrated, 1);

        // Confirm on-disk rewrite
        let raw = std::fs::read_to_string(dir.path().join("quota.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schema_version"].as_u64(), Some(2));
        assert_eq!(v["accounts"]["5"]["surface"].as_str(), Some("claude-code"));
    }

    #[test]
    fn pass3_already_v2_file_reports_false() {
        let dir = TempDir::new().unwrap();
        // Write a real v2 file via save_state so it matches the exact
        // on-disk shape the writer produces.
        let mut qf = crate::quota::QuotaFile::empty();
        qf.set(
            1,
            crate::quota::AccountQuota {
                five_hour: Some(crate::quota::UsageWindow {
                    used_percentage: 50.0,
                    resets_at: 4_102_444_800,
                }),
                updated_at: 100.0,
                ..Default::default()
            },
        );
        crate::quota::state::save_state(dir.path(), &qf).unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, Some(false));
        assert_eq!(s.quota_accounts_migrated, 0);
    }

    #[test]
    fn pass3_corrupt_file_does_not_crash_reconciler() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("quota.json"), "this is not json").unwrap();
        // Must not panic; summary reports migrated=None (treated as
        // no-viable-migration; the poller will overwrite on next write).
        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, None);
    }
}
