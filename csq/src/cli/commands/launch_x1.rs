//! Fact Guard X1 wiring — the launch path around the reviewed core in
//! [`csq_core::launch_isolation`].
//!
//! Every `csq run` arm that launches a CLI calls `plan` after its handle dir
//! exists and before it builds the child command, and `X1Launch::commit`
//! immediately before the spawn/exec. The split is deliberate:
//!
//! - `plan` reads the launch facts (identity, config-dir fingerprint, guard
//!   manifest), scrubs the inherited environment, and creates the per-launch
//!   empty `GH_CONFIG_DIR`. It writes NO receipt, so a launch refused earlier
//!   in its own arm (a missing vault, a dead daemon, a bad plan) leaves none.
//! - `X1Launch::commit` writes `<handle_dir>/launch-receipt.json` (0600,
//!   atomic, via the §5a private-temp factory) and then enforces the guard
//!   manifest: `mismatch`/`invalid` refuses the launch AFTER the receipt
//!   records that outcome. A receipt that cannot be written refuses the launch
//!   (`csq_run_receipt_unwritable`).
//!
//! The child must be constructed with `env_clear()` and the map in
//! `X1Launch::env` (see `apply_to_command`): a non-UTF-8 variable cannot be
//! classified, so inheriting it would be a fail-open path
//! (`security.md` §2/§5a; plan §35.3).
//!
//! Stated limits are the plan's: the scrub is environment-only (`gh auth token`,
//! `hosts.yml` and `git credential-osxkeychain` stay reachable until the planned P2 credential
//! broker), and the receipt records the launch instant, not a live integrity
//! assertion (plan §35.6).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};
use csq_core::launch_isolation::{
    self, config_dir_digest, identity_digest, identity_label_digest, isolate_gh_config,
    scrub_os_env, verify_manifest, Digest256, EnvScrubScope, LaunchReceipt, ManifestCheck,
    SandboxState,
};
use csq_core::types::AccountNum;

/// The launch receipt could not be assembled or written; the session does not start.
pub(crate) const TAG_RECEIPT_UNWRITABLE: &str = "csq_run_receipt_unwritable";
/// A manifest entry did not hash to its declared value.
pub(crate) const TAG_GUARD_MISMATCH: &str = "csq_run_guard_mismatch";
/// The manifest existed but was unreadable, unparseable or not contained.
pub(crate) const TAG_GUARD_INVALID: &str = "csq_run_guard_manifest_invalid";
/// `--sandbox` was combined with a flag it cannot honour.
pub(crate) const TAG_SANDBOX_CONFLICT: &str = "csq_run_sandbox_bypass_conflict";
/// `--sandbox` was requested on a surface whose CLI has no Claude permission mode.
pub(crate) const TAG_SANDBOX_UNSUPPORTED: &str = "csq_run_sandbox_unsupported";
/// The child environment could not be isolated (per-launch `GH_CONFIG_DIR`).
pub(crate) const TAG_ENV_ISOLATION: &str = "csq_run_env_isolation_failed";
/// `--sandbox` was requested in a repository with an active csq Gate. The Gate
/// hooks and a pinned `manual` mode cannot both be honoured, and silently
/// dropping either one is not allowed.
pub(crate) const TAG_SANDBOX_GATE_ACTIVE: &str = "csq_run_sandbox_gate_active";
/// The Gate activation state could not be inspected. Distinct from
/// [`TAG_SANDBOX_GATE_ACTIVE`]: the launch still refuses (fail closed), but the
/// operator is told the state is unknown rather than that a Gate exists.
pub(crate) const TAG_SANDBOX_GATE_UNVERIFIABLE: &str = "csq_run_sandbox_gate_unverifiable";
/// `--allow-env` was requested on a surface whose child environment is a fixed
/// allowlist (Gemini), where the listed key cannot reach the child.
pub(crate) const TAG_ALLOW_ENV_UNSUPPORTED: &str = "csq_run_allow_env_unsupported";
/// The slot's identity could not be read: `profiles.json` exists but cannot be
/// loaded. A receipt MUST NOT silently substitute a fabricated identity.
pub(crate) const TAG_IDENTITY_UNREADABLE: &str = "csq_run_identity_unreadable";
/// `csq swap` was requested from a terminal launched with `--sandbox`: the
/// exec-replace child would run WITHOUT the pinned permission mode, so the
/// swap refuses (R2 N6, ROOT decision) rather than silently dropping it.
pub(crate) const TAG_SWAP_SANDBOX_SESSION: &str = "csq_swap_sandbox_session_refused";

/// The `csq run` flags this module honours. Defaults are the pre-X1 behaviour:
/// no sandbox, no allowlisted variables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct X1Options {
    /// `--sandbox`: pin the Claude permission mode to `manual` and refuse every
    /// flag that could replace the settings, load hooks/plugins or delegate
    /// approval (plan §35.5).
    pub sandbox: bool,
    /// `--allow-env <NAME>` (repeatable): names the operator explicitly passes
    /// through despite the admin-token scrub. A scope-bearing allowed name is
    /// recorded in `unresolved_env_keys`.
    pub allow_env: BTreeSet<String>,
}

/// The prepared launch: the exact child environment and the facts needed to
/// write the receipt. Nothing is written until [`Self::commit`].
#[derive(Debug)]
pub(crate) struct X1Launch {
    /// The complete child environment after `env_clear`-style scrubbing.
    pub env: BTreeMap<String, String>,
    receipt_path: PathBuf,
    sandbox: bool,
    handle_dir: PathBuf,
    base_dir: PathBuf,
    repo_root: PathBuf,
    account: AccountNum,
    identity: Digest256,
    scrubbed_env_keys: Vec<String>,
    unresolved_env_keys: Vec<String>,
    allowed_env_keys: Vec<String>,
}

impl X1Launch {
    /// The arguments `--sandbox` contributes to the child, in the space form the
    /// installed Claude Code accepts. Empty when the sandbox was not requested.
    pub fn sandbox_args(&self) -> Vec<String> {
        if self.sandbox {
            launch_isolation::sandbox_args()
        } else {
            Vec::new()
        }
    }

    /// True when this launch requested `--sandbox`.
    pub fn sandbox_requested(&self) -> bool {
        self.sandbox
    }

    /// The only variables a fixed-allowlist child (Gemini's `SpawnPlan`) needs
    /// from the prepared environment: the receipt path and the per-launch `gh`
    /// config dir. The allowlist itself already excludes the admin tokens.
    pub fn env_overlay(&self) -> Vec<(String, String)> {
        let mut overlay = Vec::with_capacity(2);
        for key in [launch_isolation::RECEIPT_ENV_VAR, "GH_CONFIG_DIR"] {
            if let Some(value) = self.env.get(key) {
                overlay.push((key.to_owned(), value.clone()));
            }
        }
        overlay
    }

    /// Writes the receipt and enforces the guard manifest. MUST be called
    /// immediately before the child is spawned or exec'd; an `Err` means the
    /// launch does not start.
    pub fn commit(&self) -> Result<()> {
        // The fingerprint is taken HERE, at the spawn instant, not when the plan
        // was read: an arm that materialized settings, plugins or rules after
        // `plan` would otherwise leave a digest that its own launch invalidated.
        let config_dir_digest = config_dir_digest(&self.handle_dir).map_err(|_| {
            anyhow!(
                "{TAG_RECEIPT_UNWRITABLE}: could not fingerprint {}",
                redact_path_for_error(&self.handle_dir)
            )
        })?;
        // The manifest check also runs at the spawn instant, after every arm's
        // materialization: a check at plan time would hash files csq itself was
        // about to write (Gemini's settings.json is the concrete case).
        let manifest = verify_manifest(&self.base_dir, &self.handle_dir, &self.repo_root);
        let receipt = LaunchReceipt {
            receipt_version: launch_isolation::RECEIPT_VERSION,
            session_handle: self.handle_dir.to_string_lossy().into_owned(),
            account_slot: self.account,
            account_identity_digest: self.identity.clone(),
            identity_basis: launch_isolation::IdentityBasis::LaunchInstant,
            config_dir_digest,
            guard_manifest: manifest.state(),
            env_scrub_scope: EnvScrubScope::EnvOnly,
            scrubbed_env_keys: self.scrubbed_env_keys.clone(),
            unresolved_env_keys: self.unresolved_env_keys.clone(),
            allowed_env_keys: self.allowed_env_keys.clone(),
            sandbox: if self.sandbox {
                SandboxState::PermissionModeOnly
            } else {
                SandboxState::NotRequested
            },
            permission_mode: if self.sandbox {
                launch_isolation::PERMISSION_MODE_SANDBOXED.to_owned()
            } else {
                "unset".to_owned()
            },
            launched_at: unix_now(),
            csq_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        launch_isolation::write_receipt(&self.handle_dir, &receipt).map_err(|_| {
            anyhow!(
                "{TAG_RECEIPT_UNWRITABLE}: {}",
                redact_path_for_error(&self.receipt_path)
            )
        })?;
        match &manifest {
            ManifestCheck::Mismatch { path } => Err(anyhow!(
                "{TAG_GUARD_MISMATCH}: manifest entry did not match its declared hash: {path}"
            )),
            ManifestCheck::Invalid { reason, path } => {
                let suffix = path
                    .as_deref()
                    .map(|path| format!(": {path}"))
                    .unwrap_or_default();
                Err(anyhow!(
                    "{TAG_GUARD_INVALID}: guard manifest refused ({reason}){suffix}"
                ))
            }
            ManifestCheck::Verified | ManifestCheck::Absent => Ok(()),
        }
    }
}

/// A relative path is a programming error in this module; never echo the whole
/// path when the failure is about its container.
fn redact_path_for_error(path: &Path) -> String {
    csq_core::cli_deps::sanitize::redact_path(path)
}

/// Prepares the child environment and the launch facts that do not depend on
/// what the arm materializes later. No receipt is written and the guard
/// manifest is not read here; `X1Launch::commit` does both immediately before
/// the spawn, so both describe the launch instant.
///
/// Side effects: creates one fresh empty `<handle_dir>/gh-config-empty-*`
/// directory (0700). Failure to create/verify it refuses the launch
/// (`TAG_ENV_ISOLATION`) — `gh` falling back to the parent's `hosts.yml` is
/// exactly what the scrub exists to prevent.
pub(crate) fn plan(
    base_dir: &Path,
    handle_dir: &Path,
    account: AccountNum,
    options: &X1Options,
    rest: &[String],
) -> Result<X1Launch> {
    plan_with_env(
        base_dir,
        handle_dir,
        account,
        options,
        rest,
        std::env::vars_os(),
    )
}

/// `plan` with an explicit environment source. Production passes
/// `std::env::vars_os()`; tests pass their own so no process-global mutation is
/// needed (`test-isolation.md`).
pub(crate) fn plan_with_env<I>(
    base_dir: &Path,
    handle_dir: &Path,
    account: AccountNum,
    options: &X1Options,
    rest: &[String],
    vars: I,
) -> Result<X1Launch>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    if !handle_dir.is_absolute() || !base_dir.is_absolute() {
        return Err(anyhow!(
            "{TAG_RECEIPT_UNWRITABLE}: handle and accounts directories must be absolute"
        ));
    }
    // The refusal precedes every side effect: a conflicting flag must not produce
    // a receipt, a `gh` dir or a half-launched session.
    if options.sandbox && launch_isolation::sandbox_conflict(rest) {
        return Err(anyhow!(
            "{TAG_SANDBOX_CONFLICT}: --sandbox cannot be combined with a bypass, \
             settings, plugin, hook or approval-delegating flag; pass the CLI's own \
             flags after `--`"
        ));
    }

    // The launched workspace root: the same CWD the child inherits. If it cannot
    // be read, fall back to the accounts root (absolute) so a present manifest
    // still fails closed on containment instead of silently passing.
    let repo_root = std::env::current_dir().unwrap_or_else(|_| base_dir.to_path_buf());

    let (mut env, scrub) = scrub_os_env(vars, &options.allow_env);
    if isolate_gh_config(&mut env, handle_dir).is_err() {
        return Err(anyhow!(
            "{TAG_ENV_ISOLATION}: could not create a private per-launch GH_CONFIG_DIR in {}",
            redact_path_for_error(handle_dir)
        ));
    }

    let handle_dir_abs =
        std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
    let identity = identity_digest_for_slot(base_dir, account)?;
    let receipt_path = handle_dir_abs.join(launch_isolation::RECEIPT_FILE);
    // `scrub.allowed` is the keys the allowlist ACTUALLY passed through: a name
    // that was never at risk, or that the scrub removes unconditionally (a
    // plumbing key), is not recorded as allowed. `unresolved_env_keys` separately
    // states which allowed keys csq could not classify.
    let allowed_env_keys: Vec<String> = scrub.allowed.clone();
    // The child learns where its receipt is even before it is written; `commit`
    // runs before the spawn, so a session that starts always has one on disk.
    env.insert(
        launch_isolation::RECEIPT_ENV_VAR.to_owned(),
        receipt_path.to_string_lossy().into_owned(),
    );

    Ok(X1Launch {
        env,
        receipt_path,
        sandbox: options.sandbox,
        handle_dir: handle_dir_abs,
        base_dir: base_dir.to_path_buf(),
        repo_root,
        account,
        identity,
        scrubbed_env_keys: scrub.removed,
        unresolved_env_keys: scrub.unresolved,
        allowed_env_keys,
    })
}

/// The slot's identity digest, read through the WIDEST accessor
/// (`guard-reader-writer-parity.md` MUST-1): the `by_slot` UUID when one exists,
/// then the non-OAuth `by_slot_identity` label, then `slot:<N>` for a legacy slot
/// with neither. The receipt never claims a UUID the slot does not have.
///
/// A missing `profiles.json` is the legacy fallback. A file that EXISTS but
/// cannot be read or parsed is [`TAG_IDENTITY_UNREADABLE`], not a silent
/// `slot:<N>`: substituting a fabricated identity would hide a broken mapping
/// exactly where a guard reads the account's identity.
fn identity_digest_for_slot(base_dir: &Path, account: AccountNum) -> Result<Digest256> {
    if let Some(uuid) = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get())
    {
        return Ok(identity_digest(&uuid.as_uuid()));
    }
    let profiles_path = csq_core::accounts::profiles::profiles_path(base_dir);
    match std::fs::symlink_metadata(&profiles_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(identity_label_digest(&format!("slot:{account}")));
        }
        Err(_) => {
            return Err(anyhow!(
                "{TAG_IDENTITY_UNREADABLE}: the slot identity store could not be inspected"
            ));
        }
    }
    let profiles = csq_core::accounts::profiles::load(&profiles_path).map_err(|_| {
        anyhow!("{TAG_IDENTITY_UNREADABLE}: the slot identity store could not be parsed")
    })?;
    if let Some(label) = profiles.by_slot_identity.get(&account.to_string()) {
        return Ok(identity_label_digest(label));
    }
    Ok(identity_label_digest(&format!("slot:{account}")))
}

/// Applies the X1 environment to a child command: `env_clear()` first, then the
/// scrubbed map. Call this BEFORE the arm's own `env`/`env_remove` calls so they
/// still refine the result.
pub(crate) fn apply_to_command(cmd: &mut Command, launch: &X1Launch) {
    cmd.env_clear();
    cmd.envs(&launch.env);
}

/// The vanilla (no-account) path has no slot and no handle dir, so it cannot
/// produce a receipt or a per-launch `GH_CONFIG_DIR`. It still gets the token
/// scrub: every GitHub admin credential that can be identified in the parent's
/// environment is removed, `--allow-env` names are honoured, and any non-UTF-8
/// variable is dropped rather than inherited. Plan §35.8 records the
/// receipt/handle gap.
pub(crate) fn apply_scrub_only(cmd: &mut Command, allow: &BTreeSet<String>) {
    let (mut env, _outcome) = scrub_os_env(std::env::vars_os(), allow);
    // A vanilla launch started from inside another csq session must never
    // inherit that session's receipt pointer or `gh` config dir: the pointer
    // would name a receipt that is not this launch's.
    env.remove(launch_isolation::RECEIPT_ENV_VAR);
    env.remove("GH_CONFIG_DIR");
    cmd.env_clear();
    cmd.envs(env);
}

/// The child environment for a swap exec-replace, built BEFORE the source
/// session is torn down (R2 N5).
///
/// The swap tombstones the source handle dir and only then creates the target
/// one, so a failure while constructing the child environment used to destroy
/// the user's session with no target to land in. [`Self::prepare`] runs the
/// full X1 scrub, drops any inherited receipt pointer, and creates the fresh
/// private `GH_CONFIG_DIR` while the session is still intact; [`Self::adopt`]
/// then moves that directory into the target handle dir once it exists. No
/// environment step remains after the tombstone.
#[derive(Debug)]
pub(crate) struct PreparedSwapEnv {
    env: BTreeMap<String, String>,
    staging: PathBuf,
    adopted: bool,
}

impl PreparedSwapEnv {
    /// Builds the environment from the parent's, creating the private `gh`
    /// config dir under a staging directory in `base_dir`. Every failure here
    /// happens before the source handle dir is touched.
    pub(crate) fn prepare(base_dir: &Path) -> Result<Self> {
        let staging = base_dir.join(format!(".swap-env-{}", std::process::id()));
        std::fs::create_dir_all(&staging).map_err(|_| {
            anyhow!("{TAG_ENV_ISOLATION}: could not create the swap's staging directory")
        })?;
        let (mut env, _outcome) = scrub_os_env(std::env::vars_os(), &BTreeSet::new());
        env.remove(launch_isolation::RECEIPT_ENV_VAR);
        env.remove("GH_CONFIG_DIR");
        if isolate_gh_config(&mut env, &staging).is_err() {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(anyhow!(
                "{TAG_ENV_ISOLATION}: could not create the swap's private GH_CONFIG_DIR"
            ));
        }
        Ok(Self {
            env,
            staging,
            adopted: false,
        })
    }

    /// Moves the private `gh` config dir into the target handle dir and returns
    /// the completed child environment.
    ///
    /// The move is best-effort: the tombstone has already happened by the time
    /// this runs, so a rename failure must not destroy the swap. On failure
    /// `GH_CONFIG_DIR` keeps pointing at the staging directory (still a fresh,
    /// private, empty dir) and the failure is logged with a fixed tag; the
    /// staging directory is then left in place because the child uses it.
    pub(crate) fn adopt(mut self, handle_dir: &Path) -> BTreeMap<String, String> {
        if let Some(current) = self.env.get("GH_CONFIG_DIR").map(PathBuf::from) {
            let name = current
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("gh-config-empty"));
            let target = handle_dir.join(name);
            match std::fs::rename(&current, &target) {
                Ok(()) => {
                    if let Some(text) = target.to_str() {
                        self.env.insert("GH_CONFIG_DIR".to_owned(), text.to_owned());
                    }
                    self.adopted = true;
                    let _ = std::fs::remove_dir(&self.staging);
                }
                Err(_) => {
                    tracing::warn!(
                        error_kind = "swap_env_gh_dir_not_adopted",
                        "the swap's private GH_CONFIG_DIR could not be moved into the \
                         target handle dir; the child uses the staging path"
                    );
                    self.adopted = true;
                }
            }
        }
        std::mem::take(&mut self.env)
    }
}

impl Drop for PreparedSwapEnv {
    fn drop(&mut self) {
        // A prepared-but-unused environment (a refusal between preparation and
        // the tombstone) never reached a child: remove its staging directory
        // and the private gh dir with it.
        if !self.adopted {
            let _ = std::fs::remove_dir_all(&self.staging);
        }
    }
}

/// Refuses a `csq swap` requested from a session launched with `--sandbox`
/// (R2 N6, ROOT decision). The swap replaces the process with a NEW CLI
/// invocation whose command line csq builds afresh; the pinned permission mode
/// is not re-applied, so continuing would silently drop the guarantee the
/// session was launched under. Fails closed on a receipt that exists but
/// cannot be read or parsed; a session with no receipt was not launched under
/// X1 and never carried the guarantee.
pub(crate) fn refuse_swap_from_sandbox_session(handle_dir: &Path) -> Result<()> {
    let receipt_path = handle_dir.join(launch_isolation::RECEIPT_FILE);
    let bytes = match std::fs::read(&receipt_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(anyhow!(
                "{TAG_SWAP_SANDBOX_SESSION}: this session's launch receipt could not be \
                 read, so whether it was launched with --sandbox is unknown; csq swap \
                 refuses rather than drop the guarantee. Exit the session and run \
                 `csq run <N>` with the flags you want"
            ));
        }
    };
    #[derive(serde::Deserialize)]
    struct ReceiptSandbox {
        sandbox: String,
    }
    let Ok(receipt) = serde_json::from_slice::<ReceiptSandbox>(&bytes) else {
        return Err(anyhow!(
            "{TAG_SWAP_SANDBOX_SESSION}: this session's launch receipt could not be \
             parsed, so whether it was launched with --sandbox is unknown; csq swap \
             refuses rather than drop the guarantee. Exit the session and run \
             `csq run <N>` with the flags you want"
        ));
    };
    match receipt.sandbox.as_str() {
        "not-requested" => Ok(()),
        "enforced" | "permission-mode-only" => Err(anyhow!(
            "{TAG_SWAP_SANDBOX_SESSION}: this session was launched with --sandbox \
             ({}); csq swap would replace it with a new CLI process that csq does \
             not launch with the pinned permission mode, so the sandbox would be \
             silently dropped. Exit the session and run `csq run <N> --sandbox` \
             instead",
            receipt.sandbox
        )),
        _ => Err(anyhow!(
            "{TAG_SWAP_SANDBOX_SESSION}: this session's launch receipt carries an \
             unrecognised sandbox state, so whether it was launched with --sandbox \
             is unknown; csq swap refuses rather than drop the guarantee. Exit the \
             session and run `csq run <N>` with the flags you want"
        )),
    }
}

/// Refuses `--sandbox` on a non-Claude CLI surface. Codex, Gemini, Kimi and Grok
/// have no Claude permission mode, so `permission-mode-only` would be a claim
/// about a mode csq never set. Over-refusal is the fail-closed direction; the
/// operator can drop the flag and launch.
pub(crate) fn refuse_sandbox_on(surface: &str, options: &X1Options) -> Result<()> {
    if options.sandbox {
        return Err(anyhow!(
            "{TAG_SANDBOX_UNSUPPORTED}: --sandbox applies to Claude Code launches; \
             {surface} has no Claude permission mode (if you meant the CLI's own \
             --sandbox flag, pass it after `--`)"
        ));
    }
    Ok(())
}

/// Refuses `--allow-env` on a surface whose child environment is a fixed
/// allowlist. Gemini's `SpawnPlan` forwards only HOME/PATH/XDG_RUNTIME_DIR plus
/// its own secret, so a key the receipt lists as allowed would never reach the
/// child; the receipt must not overclaim.
pub(crate) fn refuse_allow_env_on(surface: &str, options: &X1Options) -> Result<()> {
    if !options.allow_env.is_empty() {
        return Err(anyhow!(
            "{TAG_ALLOW_ENV_UNSUPPORTED}: {surface} launches use a fixed environment \
             allowlist; --allow-env cannot pass a key through to the child"
        ));
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn account(slot: u16) -> AccountNum {
        AccountNum::try_from(slot).expect("valid slot")
    }

    fn temp_base() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp base")
    }

    fn handle_in(base: &Path) -> PathBuf {
        let handle = base.join("term-4242");
        fs::create_dir_all(&handle).expect("handle dir");
        fs::canonicalize(&handle).expect("canonical handle")
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect()
    }

    fn receipt(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).expect("receipt written")).expect("valid receipt")
    }

    #[test]
    fn plan_writes_no_receipt_and_commit_is_what_launches() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[("HOME", "/home/u"), ("GITHUB_TOKEN", "ghp_deadbeef")]),
        )
        .expect("plan");
        assert!(
            !handle.join(launch_isolation::RECEIPT_FILE).exists(),
            "plan must not write the receipt; commit does"
        );
        assert_eq!(
            plan.env.get(launch_isolation::RECEIPT_ENV_VAR),
            Some(
                &handle
                    .join(launch_isolation::RECEIPT_FILE)
                    .to_string_lossy()
                    .into_owned()
            ),
            "the child environment carries the receipt path"
        );
        assert!(!plan.env.contains_key("GITHUB_TOKEN"), "scrubbed");
        plan.commit().expect("commit");
        let json = receipt(&handle.join(launch_isolation::RECEIPT_FILE));
        assert_eq!(json["receipt_version"], 1);
        assert_eq!(json["account_slot"], 3);
        assert_eq!(json["guard_manifest"], "absent");
        assert_eq!(json["env_scrub_scope"], "env-only");
        assert_eq!(json["sandbox"], "not-requested");
        assert_eq!(json["permission_mode"], "unset");
        assert_eq!(json["scrubbed_env_keys"][0], "GITHUB_TOKEN");
    }

    #[test]
    fn receipt_is_0600_and_lists_names_never_values() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let secret = "ghp_secretvalue123";
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[("GH_TOKEN", secret)]),
        )
        .expect("plan");
        plan.commit().expect("commit");
        let path = handle.join(launch_isolation::RECEIPT_FILE);
        let text = fs::read_to_string(&path).expect("receipt");
        assert!(!text.contains(secret), "receipt must never carry a value");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn an_unwritable_receipt_refuses_before_any_spawn() {
        let base = temp_base();
        let handle = handle_in(base.path());
        // A non-empty DIRECTORY at the receipt path makes the atomic rename fail
        // on every platform, without also denying the `gh` directory creation
        // (a read-only handle dir fails earlier, at env isolation, and would
        // not exercise this refusal).
        let doomed = handle.join(launch_isolation::RECEIPT_FILE);
        fs::create_dir(&doomed).expect("blocking directory");
        fs::write(doomed.join("occupied"), b"x").expect("non-empty");
        let error = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[("HOME", "/home/u")]),
        )
        .expect("plan")
        .commit()
        .expect_err("an unwritable receipt path must refuse");
        assert!(
            error.to_string().contains(TAG_RECEIPT_UNWRITABLE),
            "error names the refusal tag: {error}"
        );
    }

    #[test]
    fn a_matching_manifest_verifies_and_an_empty_one_is_invalid_not_absent() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let guarded = handle.join("settings.json");
        fs::write(&guarded, b"{}").expect("guarded file");
        let digest = launch_isolation::sha256_hex(b"{}");
        fs::write(
            base.path().join(launch_isolation::MANIFEST_FILE),
            format!(
                r#"{{"manifest_version":1,"source":"local","entries":[{{"path":"settings.json","sha256":"{digest}","scope":"handle-dir"}}]}}"#
            ),
        )
        .expect("manifest");
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect("plan");
        plan.commit().expect("verified launch");
        assert_eq!(
            receipt(&handle.join(launch_isolation::RECEIPT_FILE))["guard_manifest"],
            "verified"
        );

        let base = temp_base();
        let handle = handle_in(base.path());
        fs::write(
            base.path().join(launch_isolation::MANIFEST_FILE),
            r#"{"manifest_version":1,"source":"local","entries":[]}"#,
        )
        .expect("manifest");
        let error = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect("plan")
        .commit()
        .expect_err("empty manifest must refuse");
        assert!(error.to_string().contains(TAG_GUARD_INVALID));
    }

    #[test]
    fn a_mismatch_refuses_and_the_receipt_still_records_it() {
        let base = temp_base();
        let handle = handle_in(base.path());
        fs::write(handle.join("settings.json"), b"{}").expect("guarded file");
        fs::write(
            base.path().join(launch_isolation::MANIFEST_FILE),
            r#"{"manifest_version":1,"source":"local","entries":[{"path":"settings.json","sha256":"0000000000000000000000000000000000000000000000000000000000000000","scope":"handle-dir"}]}"#,
        )
        .expect("manifest");
        let error = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect("plan")
        .commit()
        .expect_err("mismatch must refuse");
        assert!(error.to_string().contains(TAG_GUARD_MISMATCH));
        assert_eq!(
            receipt(&handle.join(launch_isolation::RECEIPT_FILE))["guard_manifest"],
            "mismatch",
            "the receipt records the outcome even though the launch was refused"
        );
    }

    #[test]
    fn a_github_token_in_the_parent_never_reaches_the_child_and_gh_config_is_empty() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[
                ("HOME", "/home/u"),
                ("GITHUB_TOKEN", "ghp_deadbeef"),
                ("GH_ENTERPRISE_TOKEN", "unresolved-value"),
                ("GIT_CONFIG_GLOBAL", "/tmp/evil.gitconfig"),
                ("PATH", "/usr/bin:/bin"),
            ]),
        )
        .expect("plan");
        assert!(!plan.env.contains_key("GITHUB_TOKEN"));
        assert!(!plan.env.contains_key("GH_ENTERPRISE_TOKEN"));
        assert!(!plan.env.contains_key("GIT_CONFIG_GLOBAL"));
        let gh = plan.env.get("GH_CONFIG_DIR").expect("gh config dir");
        let gh = Path::new(gh);
        assert!(gh.is_dir(), "GH_CONFIG_DIR exists");
        assert_eq!(
            fs::read_dir(gh).expect("readable").count(),
            0,
            "fresh and empty"
        );
        assert!(gh.starts_with(&handle), "inside the session's handle dir");
    }

    #[test]
    fn an_allowlisted_token_is_kept_and_recorded_unresolved() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let mut options = X1Options::default();
        options.allow_env.insert("GH_ENTERPRISE_TOKEN".to_owned());
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &options,
            &[],
            env(&[("GH_ENTERPRISE_TOKEN", "unresolved-value")]),
        )
        .expect("plan");
        assert_eq!(
            plan.env.get("GH_ENTERPRISE_TOKEN").map(String::as_str),
            Some("unresolved-value")
        );
        plan.commit().expect("commit");
        let json = receipt(&handle.join(launch_isolation::RECEIPT_FILE));
        assert_eq!(json["allowed_env_keys"][0], "GH_ENTERPRISE_TOKEN");
        assert_eq!(json["unresolved_env_keys"][0], "GH_ENTERPRISE_TOKEN");
    }

    #[test]
    fn sandbox_refuses_a_bypass_flag_before_writing_anything() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let options = X1Options {
            sandbox: true,
            allow_env: BTreeSet::new(),
        };
        let error = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &options,
            &["--dangerously-skip-permissions".to_owned()],
            env(&[]),
        )
        .expect_err("conflict must refuse");
        assert!(error.to_string().contains(TAG_SANDBOX_CONFLICT));
        assert!(
            !handle.join(launch_isolation::RECEIPT_FILE).exists(),
            "a refused flag leaves no receipt"
        );
    }

    #[test]
    fn sandbox_records_the_pinned_mode_and_contributes_it_to_the_command() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let options = X1Options {
            sandbox: true,
            allow_env: BTreeSet::new(),
        };
        let plan =
            plan_with_env(base.path(), &handle, account(3), &options, &[], env(&[])).expect("plan");
        assert_eq!(
            plan.sandbox_args(),
            vec!["--permission-mode".to_owned(), "manual".to_owned()]
        );
        plan.commit().expect("commit");
        let json = receipt(&handle.join(launch_isolation::RECEIPT_FILE));
        assert_eq!(json["sandbox"], "permission-mode-only");
        assert_eq!(json["permission_mode"], "manual");
    }

    #[test]
    fn a_non_uuid_identity_uses_the_wide_label_accessor_not_a_fabricated_uuid() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let profiles = serde_json::json!({
            "by_slot": {},
            "by_email": {},
            "by_slot_identity": {"3": "apikey:mm"}
        });
        fs::write(
            csq_core::accounts::profiles::profiles_path(base.path()),
            serde_json::to_vec(&profiles).expect("serialise"),
        )
        .expect("profiles");
        let expected = identity_label_digest("apikey:mm");
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect("plan");
        plan.commit().expect("commit");
        assert_eq!(
            receipt(&handle.join(launch_isolation::RECEIPT_FILE))["account_identity_digest"]
                .as_str(),
            Some(expected.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_to_command_clears_the_parent_and_reinstates_only_the_scrubbed_map() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[
                ("HOME", "/home/u"),
                ("PATH", "/usr/bin:/bin"),
                ("GITHUB_TOKEN", "ghp_deadbeef"),
            ]),
        )
        .expect("plan");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("env");
        apply_to_command(&mut cmd, &plan);
        let output = cmd.output().expect("spawn");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !text.contains("GITHUB_TOKEN"),
            "admin token removed: {text}"
        );
        assert!(
            text.contains(launch_isolation::RECEIPT_ENV_VAR),
            "receipt path exported"
        );
        assert!(text.contains("GH_CONFIG_DIR="), "gh config dir exported");
        assert!(
            text.contains("PATH=/usr/bin:/bin"),
            "ordinary variables preserved"
        );
    }

    #[test]
    fn a_sandbox_on_a_non_claude_surface_refuses_rather_than_pretending() {
        let options = X1Options {
            sandbox: true,
            allow_env: BTreeSet::new(),
        };
        let error = refuse_sandbox_on("codex", &options).expect_err("must refuse");
        assert!(error.to_string().contains(TAG_SANDBOX_UNSUPPORTED));
        assert!(refuse_sandbox_on("codex", &X1Options::default()).is_ok());
    }

    /// R1 C9: a `profiles.json` that EXISTS but cannot be parsed must refuse,
    /// never silently fall back to `slot:<N>` (which would record a fabricated
    /// identity exactly where a guard reads the account's identity).
    #[test]
    fn an_unparseable_identity_store_refuses_instead_of_fabricating_a_slot() {
        let base = temp_base();
        let handle = handle_in(base.path());
        fs::write(
            csq_core::accounts::profiles::profiles_path(base.path()),
            b"{not json",
        )
        .expect("profiles");
        let error = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect_err("an unreadable identity store must refuse");
        assert!(error.to_string().contains(TAG_IDENTITY_UNREADABLE));
        assert!(!handle.join(launch_isolation::RECEIPT_FILE).exists());
    }

    /// A MISSING store is the legacy layout, not an error: `slot:<N>`.
    #[test]
    fn a_missing_identity_store_uses_the_documented_slot_fallback() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect("plan");
        plan.commit().expect("commit");
        assert_eq!(
            receipt(&handle.join(launch_isolation::RECEIPT_FILE))["account_identity_digest"]
                .as_str(),
            Some(identity_label_digest("slot:3").as_str())
        );
    }

    /// R1 S6: the receipt states its identity basis, so a guard knows to compare
    /// the marker and read a difference as "rebound after launch", never as
    /// current identity (an in-place `csq swap` rewrites no receipt).
    #[test]
    fn the_receipt_labels_its_identity_as_launch_instant() {
        let base = temp_base();
        let handle = handle_in(base.path());
        let plan = plan_with_env(
            base.path(),
            &handle,
            account(3),
            &X1Options::default(),
            &[],
            env(&[]),
        )
        .expect("plan");
        plan.commit().expect("commit");
        assert_eq!(
            receipt(&handle.join(launch_isolation::RECEIPT_FILE))["identity_basis"],
            "launch_instant"
        );
    }
}
