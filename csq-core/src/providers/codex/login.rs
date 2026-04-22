//! Codex `csq login --provider codex` orchestrator.
//!
//! Implements spec 07 §7.3.3 for the `Surface::Codex` login. The
//! ordered sequence:
//!
//! 1. `mkdir -p config-<N>/` and `mkdir -p config-<N>/codex-sessions/`.
//! 2. Probe the macOS login keychain for a stale `com.openai.codex`
//!    entry (spec step 6). If present, prompt the user; bail on
//!    decline so we do not proceed with a dual-storage codex-cli
//!    state that `config.toml` cannot retroactively migrate.
//! 3. Write `config-<N>/config.toml` with
//!    `cli_auth_credentials_store = "file"` + `model = "<default>"`.
//!    **MUST happen BEFORE step 4** per INV-P03.
//! 4. Shell out: `CODEX_HOME=config-<N> codex login --device-auth`.
//!    codex-cli drives the device-code flow; csq inherits stdio so
//!    the user sees the code + browser opens.
//! 5. Parse `config-<N>/auth.json` as a [`CodexCredentialFile`].
//!    Relocate to `credentials/codex-<N>.json` + flip to 0o400 via
//!    [`crate::credentials::file::save_canonical_for`]. Delete the
//!    original raw auth.json since the handle dir will symlink to
//!    the canonical from now on.
//! 6. Write the `.csq-account` marker and a best-effort profile
//!    entry (label derived from `account_id`, not `id_token` — spec
//!    forbids decoding id_token JWT claims for data minimisation).
//!
//! Daemon registration (refresher + usage poller) is NOT part of
//! this PR — PR-C3c chains `discover_codex` into the refresher;
//! PR-C4 implements `broker_codex_check`. A freshly-logged-in Codex
//! slot sits idle in `credentials/codex-<N>.json` until those land,
//! which is acceptable because codex-cli's own in-process refresh
//! path still works (INV-P01 only becomes load-bearing when the
//! daemon owns refresh cadence).

use super::keychain::{self, ProbeResult};
use super::surface;
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::credentials::{self, file as cred_file, CredentialFile};
use crate::error::redact_tokens;
use crate::types::AccountNum;
use anyhow::{anyhow, Context, Result};
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitStatus;

/// What the caller (CLI + desktop) wants back after a successful
/// device-auth login.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    /// Human-readable label derived from `tokens.account_id`. Matches
    /// [`discover_codex`](crate::accounts::discovery::discover_codex)'s
    /// label format so post-login listing displays consistently.
    pub label: String,
}

/// User's response to the keychain-residue prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResidueDecision {
    Purge,
    Decline,
}

/// Production entry point. Spawns the real `codex` binary and uses
/// [`std::io::stdin`] / [`std::io::stdout`] for the residue prompt.
///
/// Security (PR-C3b review M2): when stdin is NOT a TTY AND a
/// keychain residue is present, there is no way for the user to
/// answer the y/N prompt — `read_line` returns EOF (`Ok(0)`) which
/// the prompt logic treats as `Decline`. That is fail-closed on the
/// CLI side, and the anyhow error tells the user to re-run in a
/// terminal. The desktop's future Add-Account modal will not use
/// this entry point; it will go through the Tauri command layer
/// which captures the modal response BEFORE calling `perform_with`
/// with a pre-filled reader.
pub fn perform(base_dir: &Path, account: AccountNum) -> Result<LoginOutcome> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    perform_with(
        base_dir,
        account,
        &mut reader,
        &mut writer,
        keychain::probe_residue,
        keychain::purge_residue,
        spawn_codex_device_auth,
    )
}

/// Dependency-injected core. Exposed to unit tests so the
/// write-order, residue-prompt, and keychain-decline paths can be
/// exercised without spawning a real `codex` binary or touching the
/// user's keychain.
pub(crate) fn perform_with<R, W, P, U, S>(
    base_dir: &Path,
    account: AccountNum,
    reader: &mut R,
    writer: &mut W,
    probe_keychain: P,
    purge_keychain: U,
    spawn_codex: S,
) -> Result<LoginOutcome>
where
    R: BufRead,
    W: Write,
    P: FnOnce() -> ProbeResult,
    U: FnOnce() -> std::result::Result<bool, String>,
    S: FnOnce(&Path) -> Result<ExitStatus>,
{
    // Step 1: create config-<N>/ + codex-sessions/.
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("create {}", config_dir.display()))?;
    let sessions_dir = surface::sessions_dir(base_dir, account);
    std::fs::create_dir_all(&sessions_dir)
        .with_context(|| format!("create {}", sessions_dir.display()))?;

    // Step 2: keychain residue probe BEFORE we write anything else.
    // Bail on decline — prevents an in-flight login when codex would
    // otherwise see a stale keychain entry and ignore our pre-seeded
    // `cli_auth_credentials_store = "file"` directive.
    match probe_keychain() {
        ProbeResult::Present => {
            writeln!(
                writer,
                "Found an existing Codex keychain entry (service: com.openai.codex)."
            )?;
            writeln!(
                writer,
                "  codex-cli writes to the keychain by default when this entry exists."
            )?;
            writeln!(
                writer,
                "  csq needs a file-backed auth store. Purge the keychain entry and continue?"
            )?;

            match prompt_yes_no(reader, writer, "Purge keychain entry? [y/N]: ")? {
                ResidueDecision::Purge => match purge_keychain() {
                    Ok(true) => {
                        writeln!(writer, "Purged stale com.openai.codex keychain entry.")?;
                    }
                    Ok(false) => {
                        writeln!(
                            writer,
                            "No keychain entry to purge (vanished between probe and delete)."
                        )?;
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "could not purge keychain entry: {e} — delete it manually with `security delete-generic-password -s com.openai.codex` and retry"
                        ));
                    }
                },
                ResidueDecision::Decline => {
                    return Err(anyhow!(
                        "Codex login aborted — purge the com.openai.codex keychain entry before retrying, or run `security delete-generic-password -s com.openai.codex` yourself"
                    ));
                }
            }
        }
        ProbeResult::Absent | ProbeResult::Unsupported => {}
        ProbeResult::ProbeFailed => {
            // Do not block login — `security` may be unavailable on a
            // misconfigured macOS box that genuinely has no residue.
            // Emit a warning so the user has a breadcrumb if login
            // later fails for a keychain reason.
            writeln!(
                writer,
                "warning: could not probe macOS keychain for codex residue — proceeding"
            )?;
        }
    }

    // Step 3: pre-seed config.toml BEFORE shelling out. INV-P03.
    surface::write_config_toml(base_dir, account, surface::default_model())
        .with_context(|| "pre-seed config-<N>/config.toml failed")?;

    // Step 4: shell out to `codex login --device-auth`.
    writeln!(
        writer,
        "Starting Codex device-auth login for account {}...",
        account
    )?;
    writeln!(
        writer,
        "codex-cli will display a device code and open your browser.",
    )?;
    writer.flush().ok();

    let status = spawn_codex(&config_dir).with_context(|| "spawn `codex login --device-auth`")?;
    if !status.success() {
        return Err(anyhow!(
            "codex login exited with non-zero status — inspect codex-cli output above and retry"
        ));
    }

    // Step 5: parse config-<N>/auth.json and relocate it.
    //
    // Security: `credentials::load` wraps serde_json errors via
    // `CredentialError::Corrupt { reason: e.to_string() }`. serde's
    // type-mismatch messages echo field values (`invalid type: string
    // "<value>", expected …`) — and the file we're parsing is the
    // codex auth.json with live `access_token` / `refresh_token` /
    // `id_token` values. Route the error through `redact_tokens`
    // before any log or user-facing anyhow context so a malformed
    // codex-cli output can never leak a JWT fragment to stderr.
    // Origin: PR-C3b security review H1.
    let written = surface::written_auth_json_path(base_dir, account);
    let creds_from_codex = match credentials::load(&written) {
        Ok(c) => c,
        Err(e) => {
            let redacted = redact_tokens(&e.to_string());
            tracing::warn!(
                account = %account,
                error_kind = "codex_login_auth_json_parse_failed",
                reason = %redacted,
                "codex auth.json could not be parsed after device-auth"
            );
            return Err(anyhow!(
                "could not parse {} after `codex login` — re-run `csq login {} --provider codex`",
                written.display(),
                account
            ));
        }
    };

    // Codex wrote a Codex-shape file (spec 07 §7.3.3 step 4). If not,
    // something external has already corrupted the path — bail rather
    // than try to recover.
    let codex_creds = creds_from_codex
        .codex()
        .ok_or_else(|| anyhow!("auth.json written by codex is not a Codex credential file"))?
        .clone();
    let account_id_hint = codex_creds.tokens.account_id.clone();
    let canonical_creds = CredentialFile::Codex(codex_creds);

    // `save_canonical_for` writes `credentials/codex-<N>.json` under
    // the per-(Surface, AccountNum) mutex, flips it to 0o400, then
    // mirrors to `config-<N>/codex-auth.json`. Exactly what spec
    // §7.3.3 step 4 + INV-P08 prescribe.
    //
    // Security: `save_canonical_for`'s `CredentialError` Display
    // composes a format string that could include a serde reason on
    // the mirror-write path. Redact before user-facing chain for the
    // same reason as the load path above. Origin: PR-C3b security
    // review H1.
    if let Err(e) = cred_file::save_canonical_for(base_dir, account, &canonical_creds) {
        let redacted = redact_tokens(&e.to_string());
        tracing::warn!(
            account = %account,
            error_kind = "codex_login_canonical_save_failed",
            reason = %redacted,
            "could not persist codex canonical credential"
        );
        return Err(anyhow!(
            "could not write credentials/codex-{}.json — check `credentials/` permissions and retry",
            account
        ));
    }

    // Step 5 cleanup: remove the original auth.json codex wrote.
    // The handle dir (PR-C3c) symlinks `auth.json → credentials/codex-<N>.json`
    // directly, and config-<N>/codex-auth.json is the account-level
    // mirror. The raw `auth.json` under config-<N>/ is an artifact of
    // CODEX_HOME=config-<N> during login only.
    //
    // Security (PR-C3b review M1): codex-cli writes auth.json at
    // whatever mode its umask produces (typically 0o644) with live
    // tokens inside. Before unlinking, flip mode to 0o600 so any
    // residue window is owner-only. If `remove_file` then fails
    // (Windows file-lock, exotic fs), best-effort overwrite the file
    // contents with zeros so a future attacker cannot recover tokens
    // off the filesystem, and elevate the log from warn to error so
    // the event is visible in operator telemetry.
    let _ = crate::platform::fs::secure_file(&written);
    if let Err(e) = std::fs::remove_file(&written) {
        if let Ok(meta) = std::fs::metadata(&written) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = std::fs::write(&written, &zeros);
        }
        tracing::error!(
            account = %account,
            error_kind = "codex_login_raw_auth_json_remove_failed",
            error = %e,
            "failed to remove raw auth.json after relocation; content overwritten best-effort"
        );
    }

    // Step 6: mark + profile update.
    markers::write_csq_account(&config_dir, account)
        .with_context(|| format!(".csq-account marker in {}", config_dir.display()))?;

    let label = format_label(account, account_id_hint.as_deref());
    update_profile(base_dir, account, &label)
        .with_context(|| "update profiles.json with the new Codex account entry")?;

    writeln!(writer, "Codex account {} logged in as {}.", account, label)?;

    Ok(LoginOutcome { label })
}

/// Reads a `[yY]` or `[nN]` line (trailing newline stripped) from
/// `reader`, writing the prompt to `writer` first. Empty input
/// defaults to `Decline` — matches Unix-ergonomic "[y/N]" shape
/// where the capital letter is the default.
fn prompt_yes_no<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
) -> Result<ResidueDecision> {
    write!(writer, "{prompt}")?;
    writer.flush()?;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read residue-prompt response from stdin")?;
    let trimmed = line.trim();
    match trimmed {
        "y" | "Y" | "yes" | "Yes" | "YES" => Ok(ResidueDecision::Purge),
        _ => Ok(ResidueDecision::Decline),
    }
}

/// Formats the profiles.json label for a newly-logged-in Codex slot.
/// Uses `account_id` when present (consistent with the discovery path
/// in PR-C3a which falls back to `codex-<N>` when it cannot decode
/// labels). `id_token` is deliberately NOT decoded — spec 07 §7.3.3
/// banner + `CodexTokensFile::fmt` both enforce that id_token stays
/// opaque inside csq.
fn format_label(account: AccountNum, account_id_hint: Option<&str>) -> String {
    match account_id_hint {
        Some(id) if !id.is_empty() => {
            // Keep the label short — account_id is a UUID, so drop the
            // trailing suffix after the first dash-block.
            let prefix = id.split('-').next().unwrap_or(id);
            format!("codex-{}/{}", account, prefix)
        }
        _ => format!("codex-{}", account),
    }
}

/// Writes a Codex profile entry into `profiles.json`. Uses
/// `method = "oauth"` to match the Anthropic convention and stashes
/// `surface = "codex"` under `extra` so desktop UI can disambiguate
/// without reading the credential file.
fn update_profile(
    base_dir: &Path,
    account: AccountNum,
    label: &str,
) -> std::result::Result<(), crate::error::ConfigError> {
    let path = profiles::profiles_path(base_dir);
    let mut file = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "surface".to_string(),
        serde_json::Value::String("codex".to_string()),
    );
    file.set_profile(
        account.get(),
        profiles::AccountProfile {
            email: label.to_string(),
            method: "oauth".to_string(),
            extra,
        },
    );
    profiles::save(&path, &file)
}

/// Production codex-cli spawn. Inherits stdio so the user sees the
/// device code + status output; waits for codex to exit.
///
/// Security (PR-C3b review L1): we strip `CLAUDE_CONFIG_DIR` from
/// the inherited env so a parent shell that has it set (common when
/// running inside another csq-managed terminal) does not leak the
/// Claude-surface state dir into a Codex child. Full `env_clear` +
/// allowlist is PR-C3c's job for the `csq run` launch flow; at
/// login time we just need to defend the one cross-surface bleed
/// that is most likely to be already set.
fn spawn_codex_device_auth(config_dir: &Path) -> Result<ExitStatus> {
    std::process::Command::new(surface::CLI_BINARY)
        .args(["login", "--device-auth"])
        .env(surface::HOME_ENV_VAR, config_dir)
        .env_remove("CLAUDE_CONFIG_DIR")
        .status()
        .with_context(|| {
            format!(
                "spawn `{} login --device-auth` — is codex-cli installed and on PATH?",
                surface::CLI_BINARY
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    // `ExitStatus` has no stable cross-platform constructor; pull the
    // right `ExitStatusExt` per target so PR-C3b's tests compile on
    // both Unix (Ubuntu / macOS CI) and Windows (Windows CI).
    #[cfg(unix)]
    fn fake_success() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(unix)]
    fn fake_failure() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(1 << 8)
    }

    #[cfg(windows)]
    fn fake_success() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn fake_failure() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(1)
    }

    /// Writes a valid Codex auth.json into `config_dir/auth.json`, as
    /// codex-cli would after a successful device-auth login. Mirrors
    /// the shape documented on `CodexCredentialFile`.
    fn stub_codex_auth_json(config_dir: &Path, account_id: &str) {
        let body = serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "account_id": account_id,
                "access_token": "eyJhbGciOiJIUzI1NiJ9.test-at.sig",
                "refresh_token": "rt_test",
                "id_token": "eyJhbGciOiJIUzI1NiJ9.test-id.sig",
            },
            "last_refresh": "2026-04-22T00:00:00Z",
        });
        std::fs::write(
            config_dir.join("auth.json"),
            serde_json::to_string_pretty(&body).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn success_path_writes_canonical_and_mirror_and_profile() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(2);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        let outcome = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |config_dir| {
                // Honour the contract: codex writes auth.json inside CODEX_HOME.
                stub_codex_auth_json(config_dir, "acct-uuid-1234-xyz");
                Ok(fake_success())
            },
        )
        .expect("login should succeed");

        assert!(base.join("credentials/codex-2.json").exists());
        assert!(base.join("config-2/codex-auth.json").exists());
        assert!(base.join("config-2/.csq-account").exists());
        assert!(base.join("config-2/codex-sessions").is_dir());
        // The raw auth.json codex wrote is cleaned up.
        assert!(!base.join("config-2/auth.json").exists());
        // Label carries the account-id prefix.
        assert_eq!(outcome.label, "codex-2/acct");
    }

    #[test]
    fn config_toml_written_before_codex_invocation() {
        // Write-order regression: spec 07 §7.3.3 step 2 MUST precede
        // step 3; a reversed order would let codex-cli fall through
        // to the keychain default.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(3);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();
        let observed = std::cell::Cell::new(false);

        perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |config_dir| {
                // By the time codex runs, config.toml must exist with
                // the `file` auth-store directive.
                let toml = config_dir.join("config.toml");
                assert!(
                    toml.exists(),
                    "config.toml must be written before codex is invoked (INV-P03)"
                );
                let body = std::fs::read_to_string(&toml).unwrap();
                assert!(
                    body.contains("cli_auth_credentials_store = \"file\""),
                    "config.toml must pin file-backed auth store: {body}"
                );
                observed.set(true);
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
        )
        .unwrap();

        assert!(
            observed.get(),
            "codex-spawn hook should have observed config.toml"
        );
    }

    #[test]
    fn keychain_residue_decline_aborts_before_spawn() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(4);

        let mut reader = Cursor::new(b"n\n".to_vec());
        let mut writer = Vec::<u8>::new();
        let spawn_called = std::cell::Cell::new(false);

        let err = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Present,
            || Ok(true),
            |_| {
                spawn_called.set(true);
                Ok(fake_success())
            },
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("aborted"),
            "decline must carry an abort message: {err}"
        );
        assert!(
            !spawn_called.get(),
            "decline must short-circuit BEFORE codex is invoked"
        );
        assert!(
            !base.join("credentials/codex-4.json").exists(),
            "decline must not leave any canonical credential behind"
        );
    }

    #[test]
    fn keychain_residue_accept_purges_then_proceeds() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(5);

        let mut reader = Cursor::new(b"y\n".to_vec());
        let mut writer = Vec::<u8>::new();
        let purged = std::cell::Cell::new(false);

        let outcome = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Present,
            || {
                purged.set(true);
                Ok(true)
            },
            |config_dir| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
        )
        .unwrap();

        assert!(purged.get(), "accept must invoke purge before proceeding");
        assert_eq!(outcome.label, "codex-5/id");
        assert!(base.join("credentials/codex-5.json").exists());
    }

    #[test]
    fn codex_spawn_failure_bubbles_up() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(6);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        let err = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |_| Ok(fake_failure()),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("non-zero"),
            "spawn failure must name exit status: {err}"
        );
        assert!(!base.join("credentials/codex-6.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_is_mode_0400_after_login() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(7);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |config_dir| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
        )
        .unwrap();

        let canonical = base.join("credentials/codex-7.json");
        let mode = std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "canonical must land at 0o400 per INV-P08");
    }

    #[test]
    fn probe_failed_proceeds_with_warning() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(8);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::ProbeFailed,
            || Ok(false),
            |config_dir| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
        )
        .unwrap();

        let out = String::from_utf8_lossy(&writer);
        assert!(
            out.contains("warning"),
            "probe-failed path emits a warning breadcrumb: {out}"
        );
        assert!(base.join("credentials/codex-8.json").exists());
    }

    #[test]
    fn format_label_uses_account_id_prefix_when_available() {
        assert_eq!(
            format_label(acc(9), Some("abc123-xyz-rest")),
            "codex-9/abc123"
        );
        assert_eq!(format_label(acc(9), None), "codex-9");
        assert_eq!(format_label(acc(9), Some("")), "codex-9");
    }

    #[test]
    fn prompt_yes_no_defaults_to_decline_on_blank_input() {
        let mut reader = Cursor::new(b"\n".to_vec());
        let mut writer = Vec::<u8>::new();
        let decision = prompt_yes_no(&mut reader, &mut writer, "go?").unwrap();
        assert_eq!(decision, ResidueDecision::Decline);
    }

    #[test]
    fn prompt_yes_no_accepts_y_variants() {
        for s in ["y\n", "Y\n", "yes\n", "Yes\n", "YES\n"] {
            let mut reader = Cursor::new(s.as_bytes().to_vec());
            let mut writer = Vec::<u8>::new();
            let decision = prompt_yes_no(&mut reader, &mut writer, "go?").unwrap();
            assert_eq!(decision, ResidueDecision::Purge, "input {s:?} should purge");
        }
    }

    #[test]
    fn malformed_auth_json_error_does_not_echo_tokens() {
        // Origin: PR-C3b security review H1. serde_json echoes field
        // values in type-mismatch errors (`invalid type: string
        // "<value>", expected struct …`). If a codex-cli variant
        // writes a malformed auth.json whose `tokens` field is a
        // stringified token instead of a struct, the naive error
        // chain would surface the raw value to the user's terminal.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(7);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        let err = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |config_dir| {
                // Hand-crafted malformed auth.json whose `tokens`
                // field is a refresh-token-shaped string rather than
                // an object. serde will complain, echoing the value.
                let poisoned = r#"{
                    "auth_mode": "chatgpt",
                    "tokens": "rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }"#;
                std::fs::write(config_dir.join("auth.json"), poisoned).unwrap();
                Ok(fake_success())
            },
        )
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            !chain.contains("rt_AAAA"),
            "error chain must not echo the raw refresh-token-shaped value: {chain}"
        );
    }

    #[test]
    fn missing_auth_json_bubbles_up_readable_error() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(1);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        let err = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            // Pretend codex exited 0 but wrote nothing. Simulates the
            // user cancelling out of the device-code page but the
            // codex-cli process still terminating normally.
            |_| Ok(fake_success()),
        )
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("auth.json") || msg.contains("device-auth"),
            "error should hint at the missing auth.json: {msg}"
        );
    }
}
