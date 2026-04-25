//! `spawn_gemini` — the ONLY supported path to invoke `gemini-cli`
//! across csq.
//!
//! Per PR-G2a "lint" gate: any direct `Command::new("gemini")` call
//! site outside this module is a review failure. The lint test in
//! `tests/no_direct_gemini_spawn.rs` greps the workspace and fails
//! the build if found.
//!
//! # What this function does
//!
//! 1. **EP2/EP3/EP6 pre-spawn `.env` scan** — refuse to spawn if
//!    the spawn CWD or any ancestor up to `$HOME` contains a `.env`
//!    file declaring `GOOGLE_API_KEY` / `GEMINI_API_KEY` /
//!    `GOOGLE_APPLICATION_CREDENTIALS`. Per OPEN-G02 finding
//!    (journal 0004 RESOLVED), gemini-cli DOES walk CWD ancestors
//!    for `.env` and prefers them over `Command::env()`.
//!    Specifically: csq's injected `GEMINI_API_KEY` would be
//!    OVERRIDDEN by an ancestor `.env` — that is the silent-shadow
//!    auth path. Refuse rather than allow the override to win.
//! 2. **EP1 drift detector** — call
//!    [`super::probe::reassert_api_key_selected_type`] to re-assert
//!    `selectedType=gemini-api-key` in the handle dir.
//! 3. **`Command::env_clear()` + allowlist** — clear the parent env
//!    and reinject only `HOME`, `PATH`, `XDG_RUNTIME_DIR`,
//!    `GEMINI_CLI_HOME`, and the secret env var.
//! 4. **`setrlimit(RLIMIT_CORE, 0)` on Unix** — prevent core dumps
//!    that would write the gemini-cli memory image (containing the
//!    cleartext key) to `/cores/<pid>` per security review §5
//!    "Subprocess crash core dump".
//! 5. **NO secret in argv** — the secret reaches `gemini-cli`
//!    only via env (`GEMINI_API_KEY=` or
//!    `GOOGLE_APPLICATION_CREDENTIALS=`). Lint test asserts no
//!    argv element matches `^AIza` or `BEGIN.*PRIVATE KEY`.
//!
//! # Status of this PR
//!
//! PR-G2a ships the `prepare_env` and `pre_spawn_dotenv_scan`
//! helpers as standalone units with full tests. The end-to-end
//! `spawn_gemini` function that actually `exec`s gemini-cli is
//! intentionally NOT here — it requires the `Surface::Gemini` enum
//! variant (PR-G1) and the daemon-side event consumer (PR-G3).
//! PR-G2b will compose these helpers into the live spawn path.

use super::{GEMINI_CLI_BINARY, SURFACE_GEMINI};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Outcome of the pre-spawn `.env` scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DotenvScanResult {
    /// No shadow auth found — safe to spawn.
    Clean,
    /// At least one `.env` file in CWD or ancestors contains a key
    /// gemini-cli would interpret as auth. The spawn MUST be
    /// refused.
    ShadowAuthFound {
        /// `.env` file containing the offending key.
        env_file: PathBuf,
        /// Variable name found (e.g. `"GEMINI_API_KEY"`).
        variable: String,
    },
}

/// Variables that gemini-cli treats as authentication. Any one of
/// these found in a `.env` file in the spawn CWD or ancestor would
/// be loaded by gemini-cli and prefer-over csq's injected env.
const SHADOW_AUTH_VARS: &[&str] = &[
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
];

/// Walks `cwd` and its ancestors up to `$HOME` (inclusive) looking
/// for `.env` files declaring any of [`SHADOW_AUTH_VARS`]. Returns
/// the FIRST hit (CWD-first walk order matches gemini-cli's own
/// resolution order per OPEN-G02 finding).
///
/// Per security review §5 "argv / env / log" row — this is EP2/EP3/
/// EP6 from the implementation plan.
pub fn pre_spawn_dotenv_scan(cwd: &Path, home: Option<&Path>) -> DotenvScanResult {
    let mut current: Option<&Path> = Some(cwd);
    let stop_at = home.map(|h| h.to_path_buf());
    while let Some(dir) = current {
        let env_path = dir.join(".env");
        if env_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&env_path) {
                if let Some(var) = scan_env_content_for_shadow_auth(&content) {
                    return DotenvScanResult::ShadowAuthFound {
                        env_file: env_path,
                        variable: var.to_string(),
                    };
                }
            }
        }
        // Stop AFTER scanning $HOME — gemini-cli's resolution
        // includes $HOME itself per the upstream issue.
        if let Some(stop) = &stop_at {
            if dir == stop.as_path() {
                break;
            }
        }
        current = dir.parent();
    }
    DotenvScanResult::Clean
}

/// Scans one `.env` file's content for shadow-auth variables.
/// Recognises bare `KEY=value` and `export KEY=value` forms; ignores
/// commented (`#`) lines. Returns the FIRST matching variable name.
fn scan_env_content_for_shadow_auth(content: &str) -> Option<&'static str> {
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let after_export = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let key = after_export.split('=').next().unwrap_or("").trim();
        for var in SHADOW_AUTH_VARS {
            if key == *var {
                return Some(*var);
            }
        }
    }
    None
}

/// Builds the env map passed to `Command::env_clear()` +
/// `Command::envs(...)`. Allowlist-only — never inherits the parent
/// shell's environment wholesale.
///
/// Allowlist:
/// - `HOME` — gemini-cli relies on it for ancillary lookups
/// - `PATH` — required for any subprocess gemini-cli spawns (none
///   today, but a defensive no-op)
/// - `XDG_RUNTIME_DIR` — Linux-only; nullable
/// - `GEMINI_CLI_HOME` — set to the handle dir
/// - `<secret_var>` → `<secret_value>` — `GEMINI_API_KEY` or
///   `GOOGLE_APPLICATION_CREDENTIALS`
///
/// `secret_value` is the cleartext key (or path, for Vertex). The
/// caller has already pulled it from the vault; this function does
/// NOT call the vault. Keeping vault access in the caller means the
/// caller controls the audit log entry (one read, one audit line).
pub fn prepare_env(
    parent_env: &HashMap<String, String>,
    handle_dir: &Path,
    secret_var: &str,
    secret_value: &str,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(8);
    for key in ["HOME", "PATH", "XDG_RUNTIME_DIR"] {
        if let Some(v) = parent_env.get(key) {
            out.push((key.to_string(), v.clone()));
        }
    }
    out.push((
        "GEMINI_CLI_HOME".to_string(),
        handle_dir.to_string_lossy().to_string(),
    ));
    // Push the secret last so review diffs land on the leak-sensitive
    // line at a predictable cursor position.
    out.push((secret_var.to_string(), secret_value.to_string()));
    out
}

/// Returns the const binary name spawned by csq. Centralized for
/// the lint test.
pub fn cli_binary_name() -> &'static str {
    GEMINI_CLI_BINARY
}

/// Returns the const surface tag for audit-log entries. Centralized
/// to keep the placeholder visible in one spot until PR-G2b ships
/// the enum.
pub fn surface_tag() -> &'static str {
    SURFACE_GEMINI
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_env(dir: &Path, content: &str) -> PathBuf {
        let p = dir.join(".env");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn dotenv_scan_clean_when_no_env_file() {
        let dir = TempDir::new().unwrap();
        assert_eq!(
            pre_spawn_dotenv_scan(dir.path(), None),
            DotenvScanResult::Clean
        );
    }

    #[test]
    fn dotenv_scan_clean_when_env_has_unrelated_vars() {
        let dir = TempDir::new().unwrap();
        write_env(dir.path(), "DATABASE_URL=postgres://x\nDEBUG=1\n");
        assert_eq!(
            pre_spawn_dotenv_scan(dir.path(), None),
            DotenvScanResult::Clean
        );
    }

    #[test]
    fn dotenv_scan_finds_gemini_api_key() {
        let dir = TempDir::new().unwrap();
        write_env(
            dir.path(),
            "GEMINI_API_KEY=AIzaSyTESTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
        );
        let result = pre_spawn_dotenv_scan(dir.path(), None);
        match result {
            DotenvScanResult::ShadowAuthFound { variable, .. } => {
                assert_eq!(variable, "GEMINI_API_KEY");
            }
            other => panic!("expected ShadowAuthFound, got {other:?}"),
        }
    }

    #[test]
    fn dotenv_scan_finds_google_application_credentials() {
        let dir = TempDir::new().unwrap();
        write_env(dir.path(), "GOOGLE_APPLICATION_CREDENTIALS=/tmp/sa.json\n");
        let result = pre_spawn_dotenv_scan(dir.path(), None);
        assert!(matches!(result, DotenvScanResult::ShadowAuthFound { .. }));
    }

    #[test]
    fn dotenv_scan_handles_export_prefix() {
        let dir = TempDir::new().unwrap();
        write_env(
            dir.path(),
            "export GOOGLE_API_KEY=AIzaSyTESTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
        );
        let result = pre_spawn_dotenv_scan(dir.path(), None);
        assert!(matches!(result, DotenvScanResult::ShadowAuthFound { .. }));
    }

    #[test]
    fn dotenv_scan_ignores_comments() {
        let dir = TempDir::new().unwrap();
        write_env(dir.path(), "# GEMINI_API_KEY=AIzaSyXXX\nDB=local\n");
        assert_eq!(
            pre_spawn_dotenv_scan(dir.path(), None),
            DotenvScanResult::Clean
        );
    }

    #[test]
    fn dotenv_scan_walks_ancestors_up_to_home() {
        // Layout: <home>/proj/sub/cwd/.env-clean, <home>/proj/.env-with-key
        let home = TempDir::new().unwrap();
        let proj = home.path().join("proj");
        let cwd = proj.join("sub").join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        // Ancestor has the offending key.
        write_env(
            &proj,
            "GEMINI_API_KEY=AIzaSyTESTANCESTORxxxxxxxxxxxxxxxxxxxxxxxx\n",
        );

        let result = pre_spawn_dotenv_scan(&cwd, Some(home.path()));
        match result {
            DotenvScanResult::ShadowAuthFound { env_file, .. } => {
                assert!(env_file.starts_with(&proj));
            }
            other => panic!("expected ancestor hit, got {other:?}"),
        }
    }

    #[test]
    fn dotenv_scan_stops_at_home() {
        // Above $HOME exists an offending file but we stop before
        // scanning it.
        let outer = TempDir::new().unwrap();
        let home = outer.path().join("user");
        let cwd = home.join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        write_env(
            outer.path(),
            "GEMINI_API_KEY=AIzaSyTESTOUTERxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
        );

        let result = pre_spawn_dotenv_scan(&cwd, Some(&home));
        // Outer hit is above HOME → not reached.
        assert_eq!(result, DotenvScanResult::Clean);
    }

    #[test]
    fn prepare_env_includes_secret_and_handle_dir() {
        let mut parent = HashMap::new();
        parent.insert("HOME".into(), "/home/u".into());
        parent.insert("PATH".into(), "/usr/bin".into());
        parent.insert("XDG_RUNTIME_DIR".into(), "/run/user/1000".into());
        parent.insert("ANTHROPIC_API_KEY".into(), "leak-me".into());

        let handle = Path::new("/tmp/term-1234");
        let env = prepare_env(
            &parent,
            handle,
            "GEMINI_API_KEY",
            "AIzaSyTESTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        );

        let map: HashMap<_, _> = env.iter().cloned().collect();
        assert_eq!(map.get("HOME").unwrap(), "/home/u");
        assert_eq!(map.get("PATH").unwrap(), "/usr/bin");
        assert_eq!(map.get("XDG_RUNTIME_DIR").unwrap(), "/run/user/1000");
        assert_eq!(map.get("GEMINI_CLI_HOME").unwrap(), "/tmp/term-1234");
        assert_eq!(
            map.get("GEMINI_API_KEY").unwrap(),
            "AIzaSyTESTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        );
        // Critically: parent-shell ANTHROPIC_API_KEY MUST NOT appear.
        assert!(
            !map.contains_key("ANTHROPIC_API_KEY"),
            "allowlist must not include parent ANTHROPIC_API_KEY"
        );
    }

    #[test]
    fn prepare_env_omits_unset_optional_vars() {
        // PATH is required but if the parent didn't set it (rare),
        // we don't synthesise one.
        let mut parent = HashMap::new();
        parent.insert("HOME".into(), "/home/u".into());

        let env = prepare_env(&parent, Path::new("/tmp/x"), "GEMINI_API_KEY", "k");
        let map: HashMap<_, _> = env.iter().cloned().collect();
        assert!(!map.contains_key("PATH"));
        assert!(!map.contains_key("XDG_RUNTIME_DIR"));
        // But the secret + GEMINI_CLI_HOME always go in.
        assert!(map.contains_key("GEMINI_CLI_HOME"));
        assert!(map.contains_key("GEMINI_API_KEY"));
    }

    #[test]
    fn cli_binary_name_is_gemini() {
        assert_eq!(cli_binary_name(), "gemini");
    }

    #[test]
    fn surface_tag_is_gemini() {
        assert_eq!(surface_tag(), "gemini");
    }
}
