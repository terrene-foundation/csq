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

/// Keys csq controls per-slot — these MUST always come from csq, NEVER
/// from user-global `~/.codex/config.toml`. Every other top-level key in
/// the user-global file is propagated into the slot's `config.toml` so
/// user-global preferences (`approval_policy`, `sandbox_mode`,
/// `model_provider`, `model_reasoning_*`, `[mcp_servers.*]`,
/// `[shell_environment_policy]`, …) reach Codex via `$CODEX_HOME/config.toml`.
///
/// Without this propagation, csq's slot-isolation `CODEX_HOME` redirect
/// silently drops every user-global preference, because Codex reads
/// only `$CODEX_HOME/config.toml`, never `~/.codex/config.toml`. The
/// originating bug report (2026-05-15): user ran `csq run 12` with
/// `approval_policy = "never"` + `sandbox_mode = "danger-full-access"`
/// in `~/.codex/config.toml`, and the session came up with Codex's
/// built-in `workspace-write` defaults instead — because the slot's
/// `config.toml` only had `cli_auth_credentials_store` + `model`.
const CSQ_CONTROLLED_KEYS: &[&str] = &["cli_auth_credentials_store", "model"];

/// Environment variable that overrides the user-global Codex config
/// path. Tests and CI set this to point at a controlled fixture.
/// When unset, `read_user_global_config_toml` looks at
/// `$HOME/.codex/config.toml`.
pub const USER_CONFIG_ENV_OVERRIDE: &str = "CODEX_USER_CONFIG";

/// Reads `~/.codex/config.toml` (or the path in
/// [`USER_CONFIG_ENV_OVERRIDE`] if set) and returns its content as a
/// `String`. Returns `None` if the file is missing, unreadable, or the
/// path resolution fails (no `$HOME`). Never panics — fall back to the
/// 2-key slot config in every failure mode (graceful degradation per
/// `rules/security.md` § "Fail-Closed on Keychain/Lock Contention" — a
/// missing user-global is not an error, just absent preferences).
pub fn read_user_global_config_toml() -> Option<String> {
    let path = user_global_config_path()?;
    std::fs::read_to_string(&path).ok()
}

fn user_global_config_path() -> Option<PathBuf> {
    if let Some(override_path) = std::env::var_os(USER_CONFIG_ENV_OVERRIDE) {
        return Some(PathBuf::from(override_path));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".codex").join("config.toml"))
}

/// Renders the `config.toml` contents csq writes before the first
/// `codex login --device-auth`, with no user-global merge. Two keys:
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
///
/// This is a thin wrapper around [`render_config_toml_with_global`] for
/// callers (notably tests) that don't need user-global merging.
pub fn render_config_toml(model: &str) -> String {
    render_config_toml_with_global(model, None)
}

/// Renders the slot's `config.toml` content, merging non-csq-controlled
/// top-level keys from `user_global_toml` (typically the contents of
/// `~/.codex/config.toml`).
///
/// csq's `CODEX_HOME` redirect at spawn time means Codex reads its
/// config from `config-<N>/config.toml`, NEVER from `~/.codex/config.toml`.
/// Without this merge, user-global preferences like `approval_policy`,
/// `sandbox_mode`, `model_provider`, `model_reasoning_effort`,
/// `[mcp_servers.*]`, `[shell_environment_policy]`, and every other
/// top-level Codex configuration silently never apply to csq-managed
/// slots.
///
/// Merge rules:
/// 1. csq-controlled keys (see [`CSQ_CONTROLLED_KEYS`]) are rendered
///    from csq's arguments. The user-global file CANNOT override them
///    (e.g. a user-global `model = "o4-mini"` does NOT replace the
///    slot's csq-set model).
/// 2. Every other top-level key in `user_global_toml` is propagated
///    verbatim (tables, arrays, scalars — TOML round-trip via
///    `toml::Value`).
/// 3. On parse error, the user-global is treated as absent and the
///    2-key fallback is returned (graceful degradation — never break
///    the slot operation because the user's global TOML is malformed).
pub fn render_config_toml_with_global(model: &str, user_global_toml: Option<&str>) -> String {
    let csq_block = format!(
        "cli_auth_credentials_store = \"file\"\nmodel = \"{}\"\n",
        model
    );

    let Some(user_toml) = user_global_toml else {
        return csq_block;
    };

    let parsed: toml::Value = match toml::from_str(user_toml) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error_kind = "codex_user_global_config_unparseable",
                error = %e,
                "skipping ~/.codex/config.toml merge — file is not valid TOML; \
                 slot will receive Codex built-in defaults for any keys outside cli_auth_credentials_store + model"
            );
            return csq_block;
        }
    };

    let toml::Value::Table(mut user_table) = parsed else {
        // A valid TOML document is always a table at the root; defensive
        // fall-back if `toml` ever changes that contract.
        return csq_block;
    };

    for key in CSQ_CONTROLLED_KEYS {
        user_table.remove(*key);
    }

    if user_table.is_empty() {
        return csq_block;
    }

    let user_block = match toml::to_string(&toml::Value::Table(user_table)) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error_kind = "codex_user_global_config_serialize_failed",
                error = %e,
                "skipping ~/.codex/config.toml merge — could not serialize merged table; \
                 slot will receive Codex built-in defaults"
            );
            return csq_block;
        }
    };

    format!("{}{}", csq_block, user_block)
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
/// Derives Codex CLI flags from user-global `~/.codex/config.toml`.
/// These flags are passed at spawn time to ensure the sandbox/approval
/// policy reaches Codex's runtime at process start.
///
/// # Why not rely on config.toml alone?
///
/// `write_config_toml` already merges these keys into
/// `config-<N>/config.toml`. Codex CLI reads that file at startup —
/// in principle, that's enough. In practice (2026-05-15 user report),
/// Codex CLI's policy precedence treats CLI flags as authoritative
/// over config.toml for the strict policy layer; setting only the
/// config keys produced sessions where the model still had to request
/// escalation despite `approval_policy = "never"` +
/// `sandbox_mode = "danger-full-access"` being present in the slot's
/// config.toml. Passing the flag at spawn closes the gap.
///
/// # Translation rules
///
/// - **Full-bypass combination** (`approval_policy = "never"` AND
///   `sandbox_mode = "danger-full-access"`): emits
///   `--dangerously-bypass-approvals-and-sandbox`. This is the user's
///   documented intent — global `~/.codex/config.toml` files that set
///   this combination explicitly comment the equivalent CLI flag.
/// - **Partial coverage**: emits granular `-a <policy>` and/or
///   `-s <mode>` flags for whichever keys are present.
/// - **No relevant keys / parse error / no user-global**: returns an
///   empty vec — Codex uses its built-in defaults (or whatever the
///   merged config.toml supplies as fallback).
///
/// Returns owned `String`s so callers can pass them directly to
/// `Command::args(...)` without lifetime gymnastics.
pub fn derive_spawn_flags(user_global_toml: Option<&str>) -> Vec<String> {
    let Some(user_toml) = user_global_toml else {
        return vec![];
    };
    let parsed: toml::Value = match toml::from_str(user_toml) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let table = match parsed {
        toml::Value::Table(t) => t,
        _ => return vec![],
    };

    let approval = table.get("approval_policy").and_then(|v| v.as_str());
    let sandbox = table.get("sandbox_mode").and_then(|v| v.as_str());

    // Full-bypass combination → single flag with bypass semantics.
    if approval == Some("never") && sandbox == Some("danger-full-access") {
        return vec!["--dangerously-bypass-approvals-and-sandbox".into()];
    }

    // Granular flags for partial coverage.
    let mut flags = Vec::new();
    if let Some(p) = approval {
        flags.push("-a".into());
        flags.push(p.into());
    }
    if let Some(s) = sandbox {
        flags.push("-s".into());
        flags.push(s.into());
    }
    flags
}

pub fn write_config_toml(base_dir: &Path, account: AccountNum, model: &str) -> io::Result<()> {
    let target = config_toml_path(base_dir, account);
    let parent = target
        .parent()
        .expect("config_toml_path always has a parent");
    std::fs::create_dir_all(parent)?;

    let tmp = unique_tmp_path(&target);
    // Merge user-global ~/.codex/config.toml into the slot config so
    // user preferences (approval_policy, sandbox_mode, mcp_servers, …)
    // reach Codex via $CODEX_HOME/config.toml. csq-controlled keys
    // (cli_auth_credentials_store, model) always come from csq.
    let user_global = read_user_global_config_toml();
    let contents = render_config_toml_with_global(model, user_global.as_deref());

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

    /// Holds the workspace-wide env mutex + a deterministic
    /// CODEX_USER_CONFIG override. Tests that call write_config_toml or
    /// read_user_global_config_toml acquire this guard to be insulated
    /// from (a) the dev machine's actual `~/.codex/config.toml` and
    /// (b) concurrent tests in this module that set CODEX_USER_CONFIG.
    ///
    /// Default behavior: points the override at a nonexistent path so
    /// `read_user_global_config_toml` returns None and `write_config_toml`
    /// emits the 2-key fallback. Pass `Some(content)` to install a
    /// fixture file and exercise the merge path.
    struct EnvGuard {
        _shared: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
        _fixture_dir: Option<TempDir>,
    }

    impl EnvGuard {
        fn new_isolated() -> Self {
            let shared = crate::platform::test_env::lock();
            let prev = std::env::var_os(USER_CONFIG_ENV_OVERRIDE);
            // SAFETY: test_env::lock serialises env mutations across the
            // workspace per rules/testing.md MUST Rule 6.
            unsafe {
                std::env::set_var(
                    USER_CONFIG_ENV_OVERRIDE,
                    "/nonexistent/csq-codex-surface-test-isolated",
                );
            }
            Self {
                _shared: shared,
                prev,
                _fixture_dir: None,
            }
        }

        fn new_with_fixture(content: &str) -> Self {
            let shared = crate::platform::test_env::lock();
            let prev = std::env::var_os(USER_CONFIG_ENV_OVERRIDE);
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("user-config.toml");
            std::fs::write(&path, content).unwrap();
            // SAFETY: test_env::lock serialises env mutations.
            unsafe {
                std::env::set_var(USER_CONFIG_ENV_OVERRIDE, &path);
            }
            Self {
                _shared: shared,
                prev,
                _fixture_dir: Some(dir),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: test_env::lock is held by self until end of drop.
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(USER_CONFIG_ENV_OVERRIDE, v),
                    None => std::env::remove_var(USER_CONFIG_ENV_OVERRIDE),
                }
            }
        }
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
        let _env = EnvGuard::new_isolated();
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
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(5);
        write_config_toml(dir.path(), account, "m1").unwrap();
        write_config_toml(dir.path(), account, "m1").unwrap();
        let contents = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        // EnvGuard::new_isolated points CODEX_USER_CONFIG at a
        // nonexistent path, so read_user_global_config_toml returns None
        // and write_config_toml emits the 2-key fallback exclusively.
        assert_eq!(contents, render_config_toml("m1"));
    }

    #[test]
    fn write_config_toml_replaces_user_tampered_auth_store_line() {
        // Post-login tamper scenario (spec 07 §7.3.3 step 2 rationale):
        // user hand-edits `cli_auth_credentials_store = "keychain"`,
        // refresher reconciler rewrites it back to file.
        let _env = EnvGuard::new_isolated();
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
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(6);
        write_config_toml(dir.path(), account, "m1").unwrap();
        let path = config_toml_path(dir.path(), account);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config.toml should be 0o600 after write");
    }

    // ── User-global merge tests ────────────────────────────────────────

    #[test]
    fn render_with_global_none_returns_two_key_fallback() {
        let out = render_config_toml_with_global("m1", None);
        assert_eq!(
            out,
            "cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"
        );
    }

    #[test]
    fn render_with_global_propagates_user_top_level_keys() {
        let user_global = r#"
approval_policy = "never"
sandbox_mode = "danger-full-access"
"#;
        let out = render_config_toml_with_global("m1", Some(user_global));
        // csq-controlled keys appear first.
        assert!(out.starts_with("cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"));
        // user-global keys propagated.
        assert!(
            out.contains("approval_policy = \"never\""),
            "approval_policy must propagate from user-global; got:\n{out}"
        );
        assert!(
            out.contains("sandbox_mode = \"danger-full-access\""),
            "sandbox_mode must propagate from user-global; got:\n{out}"
        );
    }

    #[test]
    fn render_with_global_denies_csq_controlled_keys() {
        // User-global tries to override csq-controlled keys. csq wins.
        let user_global = r#"
cli_auth_credentials_store = "keychain"
model = "user-global-model"
approval_policy = "never"
"#;
        let out = render_config_toml_with_global("csq-set-model", Some(user_global));
        // csq's values for the controlled keys.
        assert!(
            out.contains("cli_auth_credentials_store = \"file\""),
            "csq must override user-global's cli_auth_credentials_store; got:\n{out}"
        );
        assert!(
            out.contains("model = \"csq-set-model\""),
            "csq must override user-global's model; got:\n{out}"
        );
        assert!(
            !out.contains("keychain"),
            "user-global keychain attempt must be denied; got:\n{out}"
        );
        assert!(
            !out.contains("user-global-model"),
            "user-global model attempt must be denied; got:\n{out}"
        );
        // Non-csq-controlled keys still propagate.
        assert!(out.contains("approval_policy = \"never\""));
    }

    #[test]
    fn render_with_global_propagates_nested_tables() {
        // Codex's [mcp_servers.<name>] tables and [shell_environment_policy]
        // are common user-global preferences.
        let user_global = r#"
approval_policy = "on-failure"

[shell_environment_policy]
inherit = "core"

[mcp_servers.github]
command = "/usr/local/bin/github-mcp"
args = []
"#;
        let out = render_config_toml_with_global("m1", Some(user_global));
        assert!(out.contains("approval_policy = \"on-failure\""));
        assert!(
            out.contains("[shell_environment_policy]"),
            "nested table must propagate; got:\n{out}"
        );
        assert!(
            out.contains("[mcp_servers.github]"),
            "mcp_servers nested table must propagate; got:\n{out}"
        );
        assert!(out.contains("command = \"/usr/local/bin/github-mcp\""));
    }

    #[test]
    fn render_with_global_malformed_falls_back_to_two_keys() {
        // Malformed TOML — must not panic, must not propagate, must fall
        // back to the 2-key safe shape. Graceful degradation per
        // rules/security.md § "Fail-Closed on Keychain/Lock Contention".
        let malformed = "approval_policy = \"never\nsandbox_mode = \"unterminated";
        let out = render_config_toml_with_global("m1", Some(malformed));
        assert_eq!(
            out, "cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n",
            "malformed user-global must fall back to 2-key safe shape"
        );
    }

    #[test]
    fn render_with_global_empty_string_falls_back_to_two_keys() {
        // Empty TOML parses to an empty table. The csq block alone is
        // returned (no trailing merge block).
        let out = render_config_toml_with_global("m1", Some(""));
        assert_eq!(
            out,
            "cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"
        );
    }

    #[test]
    fn render_with_global_only_csq_controlled_keys_falls_back_to_two_keys() {
        // User-global contains ONLY denylisted keys → after removal the
        // table is empty → no trailing user block.
        let user_global = r#"
cli_auth_credentials_store = "keychain"
model = "user-model"
"#;
        let out = render_config_toml_with_global("csq-model", Some(user_global));
        assert_eq!(
            out,
            "cli_auth_credentials_store = \"file\"\nmodel = \"csq-model\"\n"
        );
    }

    #[test]
    fn read_user_global_config_toml_honors_env_override() {
        let _env = EnvGuard::new_with_fixture("approval_policy = \"sentinel\"\n");
        let read = read_user_global_config_toml();
        assert!(read.is_some(), "env override must be honored");
        assert!(
            read.unwrap().contains("sentinel"),
            "must read the override path's content"
        );
    }

    #[test]
    fn read_user_global_config_toml_returns_none_for_missing_file() {
        let _env = EnvGuard::new_isolated();
        let read = read_user_global_config_toml();
        assert!(
            read.is_none(),
            "missing file must return None (no panic, no error)"
        );
    }

    #[test]
    fn derive_spawn_flags_none_returns_empty() {
        assert!(derive_spawn_flags(None).is_empty());
    }

    #[test]
    fn derive_spawn_flags_full_bypass_combination_returns_single_flag() {
        let user_global = r#"
approval_policy = "never"
sandbox_mode = "danger-full-access"
"#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["--dangerously-bypass-approvals-and-sandbox"]);
    }

    #[test]
    fn derive_spawn_flags_only_approval_emits_granular() {
        let user_global = r#"approval_policy = "never""#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["-a", "never"]);
    }

    #[test]
    fn derive_spawn_flags_only_sandbox_emits_granular() {
        let user_global = r#"sandbox_mode = "workspace-write""#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["-s", "workspace-write"]);
    }

    #[test]
    fn derive_spawn_flags_partial_combination_emits_both_granular() {
        // approval_policy = "on-request" + sandbox_mode = "workspace-write"
        // is NOT the full-bypass combination → granular flags.
        let user_global = r#"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
"#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["-a", "on-request", "-s", "workspace-write"]);
    }

    #[test]
    fn derive_spawn_flags_no_relevant_keys_returns_empty() {
        let user_global = r#"
model = "gpt-5.5"
[mcp_servers.foo]
command = "/usr/bin/foo"
"#;
        let flags = derive_spawn_flags(Some(user_global));
        assert!(
            flags.is_empty(),
            "no approval/sandbox keys → no flags; got: {flags:?}"
        );
    }

    #[test]
    fn derive_spawn_flags_malformed_returns_empty() {
        let flags = derive_spawn_flags(Some("approval_policy = \"never\nbroken"));
        assert!(flags.is_empty(), "malformed TOML → empty (no panic)");
    }

    #[test]
    fn write_config_toml_merges_user_global() {
        // End-to-end: write_config_toml reads the env-override
        // user-global and produces a merged slot config.toml.
        let _env = EnvGuard::new_with_fixture(
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        let tmp_base = TempDir::new().unwrap();
        let account = acc(7);
        write_config_toml(tmp_base.path(), account, "csq-set-model").unwrap();

        let contents = std::fs::read_to_string(config_toml_path(tmp_base.path(), account)).unwrap();

        assert!(contents.contains("cli_auth_credentials_store = \"file\""));
        assert!(contents.contains("model = \"csq-set-model\""));
        assert!(
            contents.contains("approval_policy = \"never\""),
            "user-global approval_policy must reach the slot; got:\n{contents}"
        );
        assert!(
            contents.contains("sandbox_mode = \"danger-full-access\""),
            "user-global sandbox_mode must reach the slot; got:\n{contents}"
        );
    }
}
