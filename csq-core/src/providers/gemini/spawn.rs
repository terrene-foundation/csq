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

use super::provisioning::{self, AuthMode, GeminiBinding, ProvisionError};
use super::{GEMINI_CLI_BINARY, SURFACE_GEMINI};
use crate::platform::secret::{SecretError, SlotKey, Vault};
use crate::types::AccountNum;
use secrecy::ExposeSecret;
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

// ============================================================
// PR-G4a: end-to-end spawn composition
// ============================================================

/// Outcome of [`build_spawn_plan`] — every datum the caller needs to
/// hand to `Command` before exec. Pure data; no resources held.
///
/// Splitting plan-construction from `exec` keeps the composition
/// layer unit-testable without a TTY or a `gemini-cli` binary on
/// `PATH`. [`execute_plan`] is the thin wrapper that turns one of
/// these into an `exec(2)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnPlan {
    /// Binary to invoke. Always [`GEMINI_CLI_BINARY`] today.
    pub binary: &'static str,
    /// Allowlisted env passed to `Command::env_clear` +
    /// `Command::envs`. Order is preserved so review diffs land on
    /// the secret line at a predictable cursor position.
    pub envs: Vec<(String, String)>,
    /// CLI arguments, forwarded verbatim.
    pub args: Vec<String>,
    /// `current_dir(handle_dir)` is set on the `Command` so
    /// `gemini-cli` resolves its working directory beneath the
    /// handle dir rather than the operator's shell CWD. The
    /// pre-spawn `.env` scan walks the operator's CWD because that
    /// is where shadow auth would actually be placed; the spawn
    /// itself runs from `handle_dir`.
    pub handle_dir: PathBuf,
}

/// Errors raised while preparing or executing a Gemini spawn.
/// Typed so the CLI can map each variant to actionable user text
/// per `rules/tauri-commands.md` §6.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// Pre-spawn `.env` scan flagged shadow auth — refuse the spawn
    /// rather than let an ancestor `.env` override the csq-injected
    /// `GEMINI_API_KEY`. Per OPEN-G02 (journal 0004 RESOLVED) this
    /// is the silent-shadow vector the EP2/EP3/EP6 layer defends
    /// against.
    #[error("shadow auth in {env_file}: {variable} would override csq-injected env")]
    ShadowAuth { env_file: PathBuf, variable: String },
    /// Drift detector failed (cannot read or rewrite handle-dir
    /// settings). The settings.json may be in an inconsistent state
    /// — refuse to spawn rather than risk routing OAuth subscription
    /// traffic through gemini-cli (ToS violation per ADR-G01).
    #[error(transparent)]
    Probe(#[from] super::probe::ProbeError),
    /// Binding marker is missing or malformed. Caller's slot
    /// argument did not match a provisioned Gemini slot. Most likely
    /// a typo, or the slot was provisioned for another surface.
    #[error(transparent)]
    Provision(#[from] ProvisionError),
    /// Vault read failed — store locked, backend unavailable, or
    /// the caller's key was never written. CLI maps each variant to
    /// remediation text.
    #[error(transparent)]
    Vault(#[from] SecretError),
}

impl SpawnError {
    /// Fixed-vocabulary tag for structured logging.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            SpawnError::ShadowAuth { .. } => "gemini_spawn_shadow_auth",
            SpawnError::Probe(_) => "gemini_spawn_probe_failed",
            SpawnError::Provision(e) => e.error_kind_tag(),
            SpawnError::Vault(e) => e.error_kind_tag(),
        }
    }
}

/// Resolves the (env-var-name, secret-value) pair for a given
/// binding. API-key bindings call into `vault`; Vertex SA bindings
/// re-validate the path is still a regular file (the operator may
/// have moved or unlinked the file since provisioning) and return
/// its absolute path as the secret value.
///
/// Returns the env-var name as `&'static str` so the caller does not
/// allocate when assembling the env. The secret value is owned to
/// keep the cleartext window bounded by the caller's frame.
pub fn resolve_secret_for_binding(
    binding: &GeminiBinding,
    slot: AccountNum,
    vault: &dyn Vault,
) -> Result<(&'static str, String), SpawnError> {
    match &binding.auth {
        AuthMode::ApiKey => {
            let key = SlotKey {
                surface: SURFACE_GEMINI,
                account: slot,
            };
            let secret = vault.get(key)?;
            Ok(("GEMINI_API_KEY", secret.expose_secret().to_string()))
        }
        AuthMode::VertexSa { path } => {
            // Re-validate at spawn time. The provisioning-time
            // check ran when the operator pasted `--vertex-sa-json
            // <path>`; the file may have moved or been deleted
            // since. This is the spawn-time guard.
            let _ = provisioning::validate_vertex_sa_path(path)?;
            Ok((
                "GOOGLE_APPLICATION_CREDENTIALS",
                path.to_string_lossy().to_string(),
            ))
        }
    }
}

/// Builds a [`SpawnPlan`] for the slot at `handle_dir`. Pure
/// composition of the four PR-G2a-shipped helpers plus a vault
/// resolve. Does NOT exec.
///
/// Order of operations (matching the security review §5):
///
/// 1. **`.env` scan from `cwd`** — refuses on shadow-auth hit.
/// 2. **Read binding** from `credentials/gemini-<slot>.json`.
/// 3. **Re-assert `selectedType=gemini-api-key`** in the handle
///    dir's `settings.json` (EP1 drift detector).
/// 4. **Resolve secret** from the vault (or re-validate Vertex SA
///    path).
/// 5. **Build env allowlist**. Parent env's `HOME` / `PATH` /
///    `XDG_RUNTIME_DIR` are forwarded; the secret is appended last
///    for diff visibility.
///
/// `cwd` is the user's shell CWD (where shadow auth lives). The
/// resulting plan's `handle_dir` is the spawn-time working
/// directory, NOT `cwd` — see [`SpawnPlan::handle_dir`].
#[allow(clippy::too_many_arguments)]
pub fn build_spawn_plan(
    base_dir: &Path,
    handle_dir: &Path,
    slot: AccountNum,
    parent_env: &HashMap<String, String>,
    cwd: &Path,
    home: Option<&Path>,
    vault: &dyn Vault,
    args: Vec<String>,
) -> Result<SpawnPlan, SpawnError> {
    // 1. Shadow-auth scan (EP2/EP3/EP6).
    if let DotenvScanResult::ShadowAuthFound { env_file, variable } =
        pre_spawn_dotenv_scan(cwd, home)
    {
        return Err(SpawnError::ShadowAuth { env_file, variable });
    }

    // 2. Read binding marker.
    let binding = provisioning::read_binding(base_dir, slot)?;

    // 3. EP1 drift detector — refresh handle-dir settings.json.
    super::probe::reassert_api_key_selected_type(handle_dir, &binding.model_name)?;

    // 4. Resolve secret (vault read for API key, path re-validate
    //    for Vertex SA).
    let (secret_var, secret_value) = resolve_secret_for_binding(&binding, slot, vault)?;

    // 5. Build allowlisted env.
    let envs = prepare_env(parent_env, handle_dir, secret_var, &secret_value);

    Ok(SpawnPlan {
        binary: GEMINI_CLI_BINARY,
        envs,
        args,
        handle_dir: handle_dir.to_path_buf(),
    })
}

/// Executes a [`SpawnPlan`]. On Unix this calls `exec(2)` so the
/// `gemini-cli` process replaces csq-cli; on Windows this spawns a
/// child and waits.
///
/// On Unix, [`pre_exec`] sets `RLIMIT_CORE=0` to prevent core dumps
/// from writing the gemini-cli memory image (containing the
/// cleartext key) to disk per security review §5 "subprocess crash
/// core dump".
///
/// Returns the wrapped exec error on Unix (exec only returns on
/// failure); returns the child's exit code via
/// [`std::process::exit`] on Windows.
///
/// [`pre_exec`]: std::os::unix::process::CommandExt::pre_exec
pub fn execute_plan(plan: SpawnPlan) -> std::io::Result<std::convert::Infallible> {
    use std::process::Command;

    let mut cmd = Command::new(plan.binary);
    cmd.env_clear();
    for (k, v) in &plan.envs {
        cmd.env(k, v);
    }
    cmd.args(&plan.args);
    cmd.current_dir(&plan.handle_dir);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // exec replaces the current process. Returns only on error.
        Err(cmd.exec())
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// End-to-end spawn entry. Composes [`build_spawn_plan`] +
/// [`execute_plan`]. The ONLY caller of this function is csq-cli's
/// `run` command — desktop callers should also funnel through here
/// rather than reimplementing.
///
/// # Side effects
///
/// On Unix this never returns to the caller — `exec(2)` replaces
/// the current process image with `gemini-cli`. On Windows this
/// process exits via [`std::process::exit`] with the child's exit
/// code.
///
/// # Errors
///
/// All [`SpawnError`] variants are caller-actionable; the binary
/// MUST surface a clear remediation per rules/tauri-commands.md §6
/// before exiting.
pub fn spawn_gemini(
    base_dir: &Path,
    handle_dir: &Path,
    slot: AccountNum,
    args: Vec<String>,
    vault: &dyn Vault,
) -> Result<std::convert::Infallible, SpawnError> {
    let parent_env: HashMap<String, String> = std::env::vars().collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let home = std::env::var_os("HOME").map(PathBuf::from);

    let plan = build_spawn_plan(
        base_dir,
        handle_dir,
        slot,
        &parent_env,
        &cwd,
        home.as_deref(),
        vault,
        args,
    )?;

    // execute_plan returns Infallible on success path (exec or
    // exit). Map io::Error to a synthesized Vault-shaped error so
    // the caller has a typed return — but in practice the unix
    // branch returns Err(io_error) only when exec failed (binary
    // missing, etc.).
    match execute_plan(plan) {
        Ok(never) => Ok(never),
        Err(e) => Err(SpawnError::Provision(ProvisionError::Io {
            path: PathBuf::from(GEMINI_CLI_BINARY),
            source: e,
        })),
    }
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

    // ============================================================
    // PR-G4a: build_spawn_plan composition tests
    // ============================================================

    use crate::platform::secret::in_memory::InMemoryVault;
    use crate::providers::gemini::provisioning::{write_binding, AuthMode, GeminiBinding};
    use secrecy::SecretString;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Provisions a fresh API-key Gemini slot inside `base_dir` and
    /// stores the matching key in `vault`. Returns the binding so
    /// tests can refer back to its model_name.
    fn provision_api_key(
        base_dir: &Path,
        vault: &dyn Vault,
        n: u16,
        model: &str,
        key: &str,
    ) -> GeminiBinding {
        let binding = GeminiBinding::new(AuthMode::ApiKey, model);
        write_binding(base_dir, slot(n), &binding).unwrap();
        let secret = SecretString::new(key.to_string().into());
        vault
            .set(
                SlotKey {
                    surface: SURFACE_GEMINI,
                    account: slot(n),
                },
                &secret,
            )
            .unwrap();
        binding
    }

    fn empty_parent_env() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("HOME".into(), "/home/u".into());
        m.insert("PATH".into(), "/usr/bin".into());
        m
    }

    #[test]
    fn build_plan_api_key_inserts_gemini_api_key_env() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1234");
        std::fs::create_dir_all(&handle).unwrap();
        let cwd = dir.path().join("workspace");
        std::fs::create_dir_all(&cwd).unwrap();
        let vault = InMemoryVault::new();

        provision_api_key(
            dir.path(),
            &vault,
            3,
            "gemini-2.5-pro",
            "AIzaSyTEST_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        );

        let plan = build_spawn_plan(
            dir.path(),
            &handle,
            slot(3),
            &empty_parent_env(),
            &cwd,
            Some(dir.path()),
            &vault,
            vec!["-p".into(), "ping".into()],
        )
        .unwrap();

        let map: HashMap<_, _> = plan.envs.iter().cloned().collect();
        assert_eq!(
            map.get("GEMINI_API_KEY").map(String::as_str),
            Some("AIzaSyTEST_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );
        assert!(!map.contains_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert_eq!(plan.binary, "gemini");
        assert_eq!(plan.args, vec!["-p".to_string(), "ping".to_string()]);
        assert_eq!(plan.handle_dir, handle);
    }

    #[test]
    fn build_plan_api_key_runs_drift_detector() {
        // The drift detector seeds .gemini/settings.json on first
        // call. After build_spawn_plan returns, the file MUST exist
        // with selectedType=gemini-api-key + the binding's model.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        let vault = InMemoryVault::new();
        provision_api_key(
            dir.path(),
            &vault,
            7,
            "gemini-2.5-flash",
            "AIzaSy_test_drift_key_xxxxxxxxxxxxxxxxxxxxx",
        );

        let _plan = build_spawn_plan(
            dir.path(),
            &handle,
            slot(7),
            &empty_parent_env(),
            dir.path(),
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap();

        let written = std::fs::read_to_string(handle.join(".gemini/settings.json")).unwrap();
        assert!(written.contains("\"selectedType\": \"gemini-api-key\""));
        assert!(written.contains("\"name\": \"gemini-2.5-flash\""));
    }

    #[test]
    fn build_plan_vertex_sa_inserts_application_credentials_env() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-2");
        std::fs::create_dir_all(&handle).unwrap();
        let sa_path = dir.path().join("sa.json");
        std::fs::write(&sa_path, br#"{"type":"service_account"}"#).unwrap();
        let canon = std::fs::canonicalize(&sa_path).unwrap();

        let vault = InMemoryVault::new();
        let binding = GeminiBinding::new(
            AuthMode::VertexSa {
                path: canon.clone(),
            },
            "auto",
        );
        write_binding(dir.path(), slot(5), &binding).unwrap();

        let plan = build_spawn_plan(
            dir.path(),
            &handle,
            slot(5),
            &empty_parent_env(),
            dir.path(),
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap();

        let map: HashMap<_, _> = plan.envs.iter().cloned().collect();
        assert!(!map.contains_key("GEMINI_API_KEY"));
        assert_eq!(
            map.get("GOOGLE_APPLICATION_CREDENTIALS")
                .map(String::as_str),
            Some(canon.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn build_plan_refuses_when_dotenv_shadow_auth_present() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-3");
        std::fs::create_dir_all(&handle).unwrap();
        let cwd = dir.path().join("workspace");
        std::fs::create_dir_all(&cwd).unwrap();
        write_env(
            &cwd,
            "GEMINI_API_KEY=AIzaSyMALICIOUS_xxxxxxxxxxxxxxxxxxxxxxxxx\n",
        );

        let vault = InMemoryVault::new();
        provision_api_key(dir.path(), &vault, 1, "auto", "AIzaSy_csq_xxxxx");

        let err = build_spawn_plan(
            dir.path(),
            &handle,
            slot(1),
            &empty_parent_env(),
            &cwd,
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap_err();

        match err {
            SpawnError::ShadowAuth { variable, .. } => assert_eq!(variable, "GEMINI_API_KEY"),
            other => panic!("expected ShadowAuth, got {other:?}"),
        }
    }

    #[test]
    fn build_plan_refuses_when_binding_missing() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-4");
        std::fs::create_dir_all(&handle).unwrap();
        let vault = InMemoryVault::new();

        let err = build_spawn_plan(
            dir.path(),
            &handle,
            slot(2),
            &empty_parent_env(),
            dir.path(),
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap_err();

        match err {
            SpawnError::Provision(ProvisionError::Io { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Provision Io NotFound, got {other:?}"),
        }
    }

    #[test]
    fn build_plan_refuses_when_vault_lacks_secret() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-5");
        std::fs::create_dir_all(&handle).unwrap();
        let vault = InMemoryVault::new();
        // Provision binding marker WITHOUT calling vault.set —
        // mirrors a half-completed setkey or post-uninstall vault.
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(8), &binding).unwrap();

        let err = build_spawn_plan(
            dir.path(),
            &handle,
            slot(8),
            &empty_parent_env(),
            dir.path(),
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap_err();

        match err {
            SpawnError::Vault(SecretError::NotFound { .. }) => {}
            other => panic!("expected Vault NotFound, got {other:?}"),
        }
    }

    #[test]
    fn build_plan_refuses_when_vertex_sa_path_disappears() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-6");
        std::fs::create_dir_all(&handle).unwrap();
        let phantom = dir.path().join("never-existed.json");
        let binding = GeminiBinding::new(AuthMode::VertexSa { path: phantom }, "auto");
        write_binding(dir.path(), slot(9), &binding).unwrap();

        let vault = InMemoryVault::new();
        let err = build_spawn_plan(
            dir.path(),
            &handle,
            slot(9),
            &empty_parent_env(),
            dir.path(),
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap_err();

        match err {
            SpawnError::Provision(ProvisionError::VertexSaInvalid { .. }) => {}
            other => panic!("expected VertexSaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn build_plan_does_not_leak_parent_anthropic_key() {
        // The allowlist-only env build must drop ANTHROPIC_API_KEY
        // even when it is set in the parent shell. Spawn-time
        // regression for the env-leak class.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-7");
        std::fs::create_dir_all(&handle).unwrap();

        let mut parent = empty_parent_env();
        parent.insert("ANTHROPIC_API_KEY".into(), "sk-ant-leak-me".into());

        let vault = InMemoryVault::new();
        provision_api_key(dir.path(), &vault, 4, "auto", "AIzaSy_csq_xxxxx");

        let plan = build_spawn_plan(
            dir.path(),
            &handle,
            slot(4),
            &parent,
            dir.path(),
            Some(dir.path()),
            &vault,
            vec![],
        )
        .unwrap();

        let map: HashMap<_, _> = plan.envs.iter().cloned().collect();
        assert!(
            !map.contains_key("ANTHROPIC_API_KEY"),
            "build_spawn_plan must not forward parent ANTHROPIC_API_KEY into the gemini child"
        );
    }

    #[test]
    fn spawn_error_kind_tags_are_distinct() {
        let tags = [
            SpawnError::ShadowAuth {
                env_file: PathBuf::from("/tmp/.env"),
                variable: "GEMINI_API_KEY".into(),
            }
            .error_kind_tag(),
            SpawnError::Probe(super::super::probe::ProbeError::RewriteFailed {
                path: PathBuf::from("/tmp/x"),
                reason: "test".into(),
            })
            .error_kind_tag(),
            SpawnError::Provision(ProvisionError::Malformed {
                path: PathBuf::from("/tmp/x"),
                reason: "test".into(),
            })
            .error_kind_tag(),
            SpawnError::Vault(SecretError::Locked).error_kind_tag(),
        ];
        let unique: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len(), "tag collision: {tags:?}");
    }
}
