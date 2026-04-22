//! Codex surface constants + `config.toml` pre-seed helpers.
//!
//! Companion to `providers::catalog` that pins the Codex-specific
//! on-disk knobs the login (PR-C3b), refresher (PR-C4), and launch
//! (PR-C3c) paths all need. Entries here mirror spec 07 §7.2.2
//! (on-disk layout) and §7.3.3 (login sequence); any drift between
//! the spec and this module is a spec violation.

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::providers;
use crate::types::AccountNum;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Binary name csq spawns for a Codex-surface slot. The full spawn
/// command lives in `Provider.spawn_command` (PR-C3c); kept here so
/// the login path can `find_on_path`-check before shelling out.
pub const CLI_BINARY: &str = "codex";

/// Environment variable codex respects to relocate its state dir.
/// Passed to `codex login --device-auth` in the login path and to
/// the launched codex process in PR-C3c.
pub const HOME_ENV_VAR: &str = "CODEX_HOME";

/// Filename codex-cli writes into `$CODEX_HOME` after a successful
/// `codex login --device-auth`. csq relocates it to
/// `credentials/codex-<N>.json` per spec 07 §7.3.3 step 4.
pub const CODEX_WRITTEN_AUTH_JSON: &str = "auth.json";

/// The config.toml filename inside `config-<N>/` codex reads. Written
/// by csq pre-login (INV-P03) with `cli_auth_credentials_store` +
/// `model` keys.
pub const CONFIG_TOML_FILENAME: &str = "config.toml";

/// Per-account persistent Codex-sessions directory. Symlinked from
/// handle dirs so daemon sweep does not delete user transcripts
/// (spec 07 §7.2.2 and INV-P04).
pub const SESSIONS_DIRNAME: &str = "codex-sessions";

/// Returns the absolute path to `config-<N>/config.toml`.
pub fn config_toml_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(CONFIG_TOML_FILENAME)
}

/// Returns the absolute path to `config-<N>/codex-sessions/`.
pub fn sessions_dir(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(SESSIONS_DIRNAME)
}

/// Returns the absolute path to `config-<N>/auth.json` — where
/// codex-cli writes tokens after `codex login --device-auth` when
/// csq invokes it with `CODEX_HOME=config-<N>`. csq relocates the
/// file post-login.
pub fn written_auth_json_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(CODEX_WRITTEN_AUTH_JSON)
}

/// Returns the Codex provider's default model, read from the catalog
/// so the spec §7.3.3 pre-seed stays aligned with `catalog::PROVIDERS`
/// — one source of truth across login (this module) and model-switch
/// (PR-C7).
pub fn default_model() -> &'static str {
    providers::get_provider("codex")
        .expect("codex provider must be registered in catalog")
        .default_model
}

/// Renders the `config.toml` contents csq writes before the first
/// `codex login --device-auth`. Two keys:
///
/// ```toml
/// cli_auth_credentials_store = "file"
/// model = "<model>"
/// ```
///
/// String values are TOML-quoted; trailing newline included.
///
/// The `cli_auth_credentials_store = "file"` line is the mandatory
/// INV-P03 directive — codex respects a file-backed auth store only
/// when this key exists BEFORE login. A later rewrite does not
/// migrate an existing keychain entry (spec 07 §7.3.3 step 2
/// rationale).
pub fn render_config_toml(model: &str) -> String {
    format!(
        "cli_auth_credentials_store = \"file\"\nmodel = \"{}\"\n",
        model
    )
}

/// Atomically writes `config-<N>/config.toml` with the rendered
/// contents of [`render_config_toml`]. Creates the parent
/// `config-<N>/` directory if missing. File permissions are set to
/// 0o600 via [`secure_file`] — the pre-seed contains no secrets but
/// keeps the directory's permission story uniform with the other
/// credential-adjacent files csq writes.
///
/// Used by the login path (this PR) and by the refresher's startup
/// reconciler (PR-C4) to repair drift after a manual edit.
/// Idempotent.
pub fn write_config_toml(base_dir: &Path, account: AccountNum, model: &str) -> io::Result<()> {
    let target = config_toml_path(base_dir, account);
    let parent = target
        .parent()
        .expect("config_toml_path always has a parent");
    std::fs::create_dir_all(parent)?;

    let tmp = unique_tmp_path(&target);
    let contents = render_config_toml(model);

    if let Err(e) = write_and_sync(&tmp, contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    Ok(())
}

fn write_and_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn constants_align_with_spec() {
        assert_eq!(CLI_BINARY, "codex");
        assert_eq!(HOME_ENV_VAR, "CODEX_HOME");
        assert_eq!(CODEX_WRITTEN_AUTH_JSON, "auth.json");
        assert_eq!(CONFIG_TOML_FILENAME, "config.toml");
        assert_eq!(SESSIONS_DIRNAME, "codex-sessions");
    }

    #[test]
    fn config_toml_path_is_under_config_n() {
        let base = Path::new("/tmp/csq");
        let p = config_toml_path(base, acc(4));
        assert_eq!(p, Path::new("/tmp/csq/config-4/config.toml"));
    }

    #[test]
    fn sessions_dir_is_under_config_n() {
        let base = Path::new("/tmp/csq");
        let p = sessions_dir(base, acc(7));
        assert_eq!(p, Path::new("/tmp/csq/config-7/codex-sessions"));
    }

    #[test]
    fn written_auth_json_path_is_under_config_n() {
        let base = Path::new("/tmp/csq");
        let p = written_auth_json_path(base, acc(3));
        assert_eq!(p, Path::new("/tmp/csq/config-3/auth.json"));
    }

    #[test]
    fn default_model_matches_catalog() {
        let m = default_model();
        assert_eq!(
            m,
            providers::get_provider("codex").unwrap().default_model,
            "default_model() must mirror the catalog — one source of truth"
        );
    }

    #[test]
    fn render_config_toml_emits_both_required_keys() {
        let out = render_config_toml("gpt-test");
        assert!(
            out.contains("cli_auth_credentials_store = \"file\""),
            "must pin file-backed auth store per INV-P03; got: {out}"
        );
        assert!(
            out.contains("model = \"gpt-test\""),
            "must carry the requested model; got: {out}"
        );
        assert!(out.ends_with('\n'), "trailing newline expected");
    }

    #[test]
    fn render_config_toml_keys_are_ordered_auth_before_model() {
        // Reviewer-ergonomic stability: `cli_auth_credentials_store`
        // first flags the INV-P03 directive at the top of the file.
        let out = render_config_toml("x");
        let auth_idx = out.find("cli_auth_credentials_store").unwrap();
        let model_idx = out.find("model =").unwrap();
        assert!(
            auth_idx < model_idx,
            "auth-store line must precede model line; got: {out}"
        );
    }

    #[test]
    fn write_config_toml_creates_parent_config_n_dir() {
        let dir = TempDir::new().unwrap();
        let account = acc(2);
        assert!(!dir.path().join("config-2").exists());

        write_config_toml(dir.path(), account, "gpt-test").unwrap();

        assert!(dir.path().join("config-2").is_dir());
        let contents = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        assert!(contents.contains("cli_auth_credentials_store = \"file\""));
        assert!(contents.contains("model = \"gpt-test\""));
    }

    #[test]
    fn write_config_toml_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let account = acc(5);
        write_config_toml(dir.path(), account, "m1").unwrap();
        write_config_toml(dir.path(), account, "m1").unwrap();
        let contents = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        assert_eq!(contents, render_config_toml("m1"));
    }

    #[test]
    fn write_config_toml_replaces_user_tampered_auth_store_line() {
        // Post-login tamper scenario (spec 07 §7.3.3 step 2 rationale):
        // user hand-edits `cli_auth_credentials_store = "keychain"`,
        // refresher reconciler rewrites it back to file.
        let dir = TempDir::new().unwrap();
        let account = acc(9);
        write_config_toml(dir.path(), account, "m1").unwrap();

        let tampered = "cli_auth_credentials_store = \"keychain\"\nmodel = \"m1\"\n";
        std::fs::write(config_toml_path(dir.path(), account), tampered).unwrap();

        write_config_toml(dir.path(), account, "m1").unwrap();

        let after = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        assert!(after.contains("cli_auth_credentials_store = \"file\""));
        assert!(!after.contains("keychain"));
    }

    #[cfg(unix)]
    #[test]
    fn write_config_toml_sets_600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let account = acc(6);
        write_config_toml(dir.path(), account, "m1").unwrap();
        let path = config_toml_path(dir.path(), account);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config.toml should be 0o600 after write");
    }
}
