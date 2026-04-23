//! Desktop-facing Codex login orchestrator.
//!
//! The CLI path in [`crate::providers::codex::login::perform_with`]
//! uses interactive stdin/stdout for the keychain-residue prompt and
//! inherits stdio when spawning `codex login --device-auth`. The
//! desktop modal can't run an interactive TTY — the Tauri commands
//! instead split the flow into two calls:
//!
//! 1. [`start_login`] — inspects preconditions (ToS acknowledgement,
//!    keychain residue) and returns a structured status. No side
//!    effects beyond the keychain probe.
//! 2. [`complete_login`] — given the user's purge decision, writes
//!    `config.toml`, spawns `codex login --device-auth` with stdout
//!    captured, parses the device-code line, invokes an
//!    `on_device_code` callback so the Tauri layer can forward the
//!    code to the Svelte modal as an event, then waits for the
//!    subprocess to exit and relocates the resulting `auth.json`.
//!
//! Both functions are DI-heavy for the same reason the CLI path is:
//! the keychain probe, subprocess spawn, and profiles.json write are
//! each substitutable so tests exercise every branch without live
//! system access.

use super::keychain::ProbeResult;
use super::surface;
use super::tos;
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::credentials::{self, file as cred_file, CredentialFile};
use crate::error::redact_tokens;
use crate::types::AccountNum;
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::path::Path;
use std::process::ExitStatus;

/// Outcome of [`start_login`]. IPC-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartLoginView {
    /// Target account slot, echoed for correlation.
    pub account: u16,
    /// True when the user has NOT acknowledged the current Codex ToS
    /// version. The UI MUST show the disclosure and call
    /// `acknowledge_codex_tos` before proceeding.
    pub tos_required: bool,
    /// Keychain residue state. `"absent"` / `"present"` / `"unsupported"`
    /// (non-macOS platforms) / `"probe_failed"` (spawn failure).
    pub keychain: String,
    /// True when the user must make an explicit decision about the
    /// keychain residue before proceeding — i.e. `keychain == "present"`.
    pub awaiting_keychain_decision: bool,
}

/// Outcome of [`complete_login`]. IPC-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompleteLoginView {
    pub account: u16,
    pub label: String,
}

/// Device-code payload handed to the UI callback while the subprocess
/// is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCodeInfo {
    /// Short alphanumeric code the user types at the verification URL.
    pub user_code: String,
    /// Full verification URL (already URL-encoded).
    pub verification_url: String,
}

/// Starts a Codex login by consulting the ToS marker and the keychain.
/// No filesystem writes happen inside `config-<N>/` — the caller MUST
/// resolve [`StartLoginView::tos_required`] and
/// [`StartLoginView::awaiting_keychain_decision`] before calling
/// [`complete_login`].
///
/// `probe` is factored out for tests; production wiring is
/// [`keychain::probe_residue`].
pub fn start_login<P>(base_dir: &Path, account: AccountNum, probe: P) -> Result<StartLoginView>
where
    P: FnOnce() -> ProbeResult,
{
    if !base_dir.is_dir() {
        return Err(anyhow!(
            "base directory does not exist: {}",
            base_dir.display()
        ));
    }
    let tos_required = !tos::is_acknowledged(base_dir);
    let probe_result = probe();
    let (keychain_label, awaiting_keychain_decision) = match probe_result {
        ProbeResult::Absent => ("absent", false),
        ProbeResult::Present => ("present", true),
        ProbeResult::Unsupported => ("unsupported", false),
        ProbeResult::ProbeFailed => ("probe_failed", false),
    };
    Ok(StartLoginView {
        account: account.get(),
        tos_required,
        keychain: keychain_label.into(),
        awaiting_keychain_decision,
    })
}

/// Completes a Codex login after the desktop modal has resolved the
/// ToS and keychain prompts. Writes `config.toml`, spawns
/// `codex login --device-auth` with stdout piped, forwards any
/// device-code line to `on_device_code`, waits for the subprocess to
/// exit, and relocates `auth.json` to `credentials/codex-<N>.json`.
///
/// DI parameters mirror [`crate::providers::codex::login::perform_with`]:
///
/// * `purge_keychain` — pre-collected user decision; `true` runs
///   [`keychain::purge_residue`] before spawn, `false` is a noop.
/// * `purge` — the purge implementation (test seam).
/// * `spawn_codex` — spawns the subprocess, captures stdout, and
///   must invoke `on_device_code` as soon as the verification URL +
///   code are visible. Returns the eventual [`ExitStatus`].
/// * `on_device_code` — receives the parsed code payload so the
///   Tauri layer can emit a `codex-device-code` event.
pub fn complete_login<U, S, C>(
    base_dir: &Path,
    account: AccountNum,
    purge_keychain: bool,
    purge: U,
    spawn_codex: S,
    mut on_device_code: C,
) -> Result<CompleteLoginView>
where
    U: FnOnce() -> std::result::Result<bool, String>,
    S: FnOnce(&Path, &mut dyn FnMut(DeviceCodeInfo)) -> Result<ExitStatus>,
    C: FnMut(DeviceCodeInfo),
{
    if !base_dir.is_dir() {
        return Err(anyhow!(
            "base directory does not exist: {}",
            base_dir.display()
        ));
    }
    if !tos::is_acknowledged(base_dir) {
        return Err(anyhow!(
            "Codex terms-of-service have not been acknowledged — call acknowledge_codex_tos first"
        ));
    }

    // Step 1: create config-<N>/ + codex-sessions/.
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("create {}", config_dir.display()))?;
    let sessions_dir = surface::sessions_dir(base_dir, account);
    std::fs::create_dir_all(&sessions_dir)
        .with_context(|| format!("create {}", sessions_dir.display()))?;

    // Step 2: honour the user's keychain decision.
    if purge_keychain {
        match purge() {
            Ok(_) => {}
            Err(e) => {
                // Journal 0021 finding M4: the `security` CLI's
                // stderr echoes service names and adjacent keychain
                // bytes on some failure modes — route through
                // `redact_tokens` before surfacing to the caller.
                let redacted = redact_tokens(&e);
                return Err(anyhow!(
                    "could not purge com.openai.codex keychain entry: {redacted} — delete it manually with `security delete-generic-password -s com.openai.codex` and retry"
                ));
            }
        }
    }

    // Step 3: pre-seed config.toml BEFORE shelling out. INV-P03.
    surface::write_config_toml(base_dir, account, surface::default_model())
        .with_context(|| "pre-seed config-<N>/config.toml failed")?;

    // Step 4: shell out via the caller-supplied spawn closure. The
    // closure bridges stdout lines into device-code events.
    let mut forwarder = |info: DeviceCodeInfo| on_device_code(info);
    let status = spawn_codex(&config_dir, &mut forwarder)
        .with_context(|| "spawn `codex login --device-auth`")?;
    if !status.success() {
        return Err(anyhow!(
            "codex login exited with non-zero status — user may have cancelled in the browser"
        ));
    }

    // Step 5: parse config-<N>/auth.json and relocate it. Identical
    // to the CLI path's H1-hardened error routing — a malformed
    // auth.json must not echo tokens to the UI via the anyhow chain.
    let written = surface::written_auth_json_path(base_dir, account);
    let creds_from_codex = match credentials::load(&written) {
        Ok(c) => c,
        Err(e) => {
            let redacted = redact_tokens(&e.to_string());
            tracing::warn!(
                account = %account,
                error_kind = "codex_desktop_login_auth_json_parse_failed",
                reason = %redacted,
                "codex auth.json could not be parsed after device-auth"
            );
            return Err(anyhow!(
                "could not parse {} after `codex login` — retry the Add Account flow",
                written.display()
            ));
        }
    };
    let codex_creds = creds_from_codex
        .codex()
        .ok_or_else(|| anyhow!("auth.json written by codex is not a Codex credential file"))?
        .clone();
    let account_id_hint = codex_creds.tokens.account_id.clone();
    let canonical = CredentialFile::Codex(codex_creds);

    if let Err(e) = cred_file::save_canonical_for(base_dir, account, &canonical) {
        let redacted = redact_tokens(&e.to_string());
        tracing::warn!(
            account = %account,
            error_kind = "codex_desktop_login_canonical_save_failed",
            reason = %redacted,
            "could not persist codex canonical credential"
        );
        // R4 cleanup (journal 0021 finding 15): scrub the raw
        // auth.json before returning. The canonical save failed, so
        // the retry path expects `written` to be absent — if we
        // leave it on disk, live access+refresh tokens sit readable
        // between the failed attempt and the next one.
        scrub_and_remove_written(&written, account, "save_failed");
        return Err(anyhow!(
            "could not write credentials/codex-{}.json — check `credentials/` permissions and retry",
            account
        ));
    }

    // Cleanup: secure_file + unlink the raw auth.json codex wrote.
    scrub_and_remove_written(&written, account, "post_save");

    // Step 6: marker + profile entry.
    markers::write_csq_account(&config_dir, account)
        .with_context(|| format!(".csq-account marker in {}", config_dir.display()))?;

    let label = format_label(account, account_id_hint.as_deref());
    update_profile(base_dir, account, &label)
        .with_context(|| "update profiles.json with the new Codex account entry")?;

    Ok(CompleteLoginView {
        account: account.get(),
        label,
    })
}

/// Scans a single line of `codex login --device-auth` stdout for a
/// device-code + verification URL. Returns `Some(DeviceCodeInfo)`
/// when both pieces land on the same line (codex-cli's observed shape
/// is `Go to: https://... and enter: XXXX-XXXX`) — callers also probe
/// cross-line state via [`ParsedDeviceCode`] below.
pub fn parse_device_code_line(line: &str) -> Option<DeviceCodeInfo> {
    let mut url: Option<String> = None;
    let mut code: Option<String> = None;
    for token in line.split_whitespace() {
        // Strip trailing punctuation a human sentence might wrap around
        // a URL or code ("See https://…, then enter ABCD-EFGH.").
        let trimmed = token.trim_end_matches(|c: char| {
            !c.is_ascii_alphanumeric()
                && c != '/'
                && c != '-'
                && c != '_'
                && c != '='
                && c != '?'
                && c != '&'
                && c != '%'
        });
        if url.is_none() && (trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
            url = Some(trimmed.to_string());
        } else if code.is_none() && is_device_code_shape(trimmed) {
            code = Some(trimmed.to_string());
        }
    }
    match (url, code) {
        (Some(u), Some(c)) => Some(DeviceCodeInfo {
            user_code: c,
            verification_url: u,
        }),
        _ => None,
    }
}

fn is_device_code_shape(token: &str) -> bool {
    // Journal 0021 finding M1: narrow to EXACTLY `XXXX-XXXX` (8
    // alphanumerics with a mandatory single dash in the middle).
    // Pre-C9a allowed 6-16 uppercase/digit chars which matched
    // common help-output tokens like `NOTICE`, `WARNING`, `FATAL7`,
    // `ID-ABCDE` and would false-positive on routine stderr.
    //
    // OpenAI device codes have the observed shape `ABCD-EFGH` —
    // 4 uppercase alphanumerics + '-' + 4 uppercase alphanumerics.
    // Rejecting everything else closes the false-positive surface
    // entirely at negligible cost to future codex-cli shape drift
    // (adding a new code shape would require a deliberate opt-in).
    let bytes = token.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    if bytes[4] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 {
            continue; // the dash
        }
        let c = b as char;
        if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Formats the profiles.json label for a newly-logged-in Codex slot.
/// Mirrors [`crate::providers::codex::login::format_label`] (not
/// re-exported — intentionally duplicated to keep the two call sites
/// independent; a future refactor may unify).
pub(crate) fn format_label(account: AccountNum, account_id_hint: Option<&str>) -> String {
    match account_id_hint {
        Some(id) if !id.is_empty() => {
            let prefix = id.split('-').next().unwrap_or(id);
            format!("codex-{}/{}", account, prefix)
        }
        _ => format!("codex-{}", account),
    }
}

/// Scrubs and removes the raw `auth.json` that codex-cli wrote into
/// `config-<N>/`. Called from two sites: after a successful
/// `save_canonical_for` (expected cleanup) AND from the
/// `save_canonical_for` error branch (R4 cleanup — journal 0021
/// finding 15; without this the live access+refresh tokens persist
/// on disk between failed attempts).
///
/// Best-effort with three layers of defense in this order:
///   1. `secure_file`: chmod 0o600 so only the owner can read.
///   2. `remove_file`: the common case — unlink on APFS/ext4 moves
///      to unused.
///   3. On remove failure: open+truncate+zero-write+fsync to ensure
///      the token bytes are overwritten even if the inode lingers.
///      Uses a fixed 64 KiB zero buffer (codex auth.json is ~8 KiB
///      in practice) instead of `meta.len()` which could race a
///      file-grow between the metadata read and the write. Retry
///      `remove_file` after the zero-write.
///
/// `context` is an operator-readable tag ("post_save" | "save_failed")
/// so the fixed-vocabulary log line distinguishes which call site
/// originated the cleanup.
fn scrub_and_remove_written(written: &Path, account: AccountNum, context: &'static str) {
    use std::io::{Seek, SeekFrom, Write};

    if !written.exists() {
        return;
    }
    let _ = crate::platform::fs::secure_file(written);

    if let Err(remove_err) = std::fs::remove_file(written) {
        // Fallback: truncate + fixed zero-fill + fsync + retry remove.
        // Fixed-size zero buffer avoids the race where `meta.len()`
        // is read before a concurrent write grows the file.
        match std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(written)
        {
            Ok(mut f) => {
                // Write 64 KiB of zeros — comfortably larger than
                // any real auth.json. Errors are swallowed: this is
                // best-effort scrubbing.
                let zeros = [0u8; 64 * 1024];
                let _ = f.write_all(&zeros);
                let _ = f.flush();
                let _ = f.seek(SeekFrom::Start(0));
                let _ = f.sync_all();
            }
            Err(open_err) => {
                tracing::error!(
                    account = %account,
                    error_kind = "codex_desktop_login_raw_auth_json_truncate_failed",
                    context = context,
                    remove_error = %remove_err,
                    open_error = %open_err,
                    "failed to truncate raw auth.json after remove failure"
                );
            }
        }
        // Retry remove after the zero-write — the original
        // `remove_file` failure might have been transient
        // (e.g. EBUSY on a fresh fd).
        if let Err(second_remove_err) = std::fs::remove_file(written) {
            tracing::error!(
                account = %account,
                error_kind = "codex_desktop_login_raw_auth_json_remove_failed",
                context = context,
                first_error = %remove_err,
                second_error = %second_remove_err,
                "failed to remove raw auth.json after zero-fill fallback; \
                 content is zeroed but inode still present"
            );
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

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

    // ── start_login ────────────────────────────────────────────

    #[test]
    fn start_login_requires_tos_when_marker_absent() {
        let dir = TempDir::new().unwrap();
        let view = start_login(dir.path(), acc(2), || ProbeResult::Absent).unwrap();
        assert!(view.tos_required);
        assert_eq!(view.keychain, "absent");
        assert!(!view.awaiting_keychain_decision);
    }

    #[test]
    fn start_login_does_not_require_tos_when_acknowledged() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();
        let view = start_login(dir.path(), acc(2), || ProbeResult::Absent).unwrap();
        assert!(!view.tos_required);
    }

    #[test]
    fn start_login_surfaces_keychain_present_and_decision_required() {
        let dir = TempDir::new().unwrap();
        let view = start_login(dir.path(), acc(3), || ProbeResult::Present).unwrap();
        assert_eq!(view.keychain, "present");
        assert!(view.awaiting_keychain_decision);
    }

    #[test]
    fn start_login_maps_all_probe_variants() {
        let dir = TempDir::new().unwrap();
        for (probe, expected) in [
            (ProbeResult::Absent, "absent"),
            (ProbeResult::Present, "present"),
            (ProbeResult::Unsupported, "unsupported"),
            (ProbeResult::ProbeFailed, "probe_failed"),
        ] {
            let view = start_login(dir.path(), acc(4), || probe).unwrap();
            assert_eq!(view.keychain, expected);
        }
    }

    #[test]
    fn start_login_rejects_missing_base_dir() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");
        let err = start_login(&missing, acc(1), || ProbeResult::Absent).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    // ── complete_login ─────────────────────────────────────────

    #[test]
    fn complete_login_rejects_without_tos_acknowledgement() {
        let dir = TempDir::new().unwrap();
        let err = complete_login(
            dir.path(),
            acc(2),
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("terms-of-service"));
    }

    #[test]
    fn complete_login_success_path_writes_canonical_and_profile() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let purge_called = std::cell::Cell::new(false);
        let view = complete_login(
            dir.path(),
            acc(3),
            false,
            || {
                purge_called.set(true);
                Ok(false)
            },
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "acct-uuid-xyz");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(view.account, 3);
        assert_eq!(view.label, "codex-3/acct");
        assert!(!purge_called.get(), "no purge when purge_keychain=false");
        assert!(dir.path().join("credentials/codex-3.json").exists());
        assert!(dir.path().join("config-3/codex-auth.json").exists());
        assert!(dir.path().join("config-3/.csq-account").exists());
        assert!(dir.path().join("config-3/codex-sessions").is_dir());
    }

    #[test]
    fn complete_login_purges_keychain_when_flag_true() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let purge_called = std::cell::Cell::new(false);
        complete_login(
            dir.path(),
            acc(4),
            true,
            || {
                purge_called.set(true);
                Ok(true)
            },
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        assert!(purge_called.get());
    }

    #[test]
    fn complete_login_honors_purge_failure() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let err = complete_login(
            dir.path(),
            acc(5),
            true,
            || Err("security barked".into()),
            |_, _| panic!("must not spawn after purge failure"),
            |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("could not purge"));
    }

    #[test]
    fn complete_login_bubbles_spawn_nonzero_exit() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let err = complete_login(
            dir.path(),
            acc(6),
            false,
            || Ok(false),
            |_, _| Ok(fake_failure()),
            |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn complete_login_forwards_device_code_from_spawn() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let emitted: RefCell<Vec<DeviceCodeInfo>> = RefCell::new(Vec::new());
        complete_login(
            dir.path(),
            acc(7),
            false,
            || Ok(false),
            |config_dir, on_code| {
                on_code(DeviceCodeInfo {
                    user_code: "ABCD-EFGH".into(),
                    verification_url: "https://chat.openai.com/codex/verify?user_code=ABCD-EFGH"
                        .into(),
                });
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |info| emitted.borrow_mut().push(info),
        )
        .unwrap();

        let calls = emitted.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].user_code, "ABCD-EFGH");
        assert!(calls[0].verification_url.contains("chat.openai.com"));
    }

    #[test]
    fn complete_login_writes_config_toml_before_spawn() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let observed = std::cell::Cell::new(false);
        complete_login(
            dir.path(),
            acc(8),
            false,
            || Ok(false),
            |config_dir, _| {
                let toml = config_dir.join("config.toml");
                assert!(toml.exists(), "config.toml MUST exist before codex runs");
                let body = std::fs::read_to_string(&toml).unwrap();
                assert!(body.contains("cli_auth_credentials_store = \"file\""));
                observed.set(true);
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        assert!(observed.get());
    }

    #[test]
    fn complete_login_redacts_malformed_auth_json_tokens() {
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        let err = complete_login(
            dir.path(),
            acc(9),
            false,
            || Ok(false),
            |config_dir, _| {
                let poisoned = r#"{
                    "auth_mode": "chatgpt",
                    "tokens": "rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }"#;
                std::fs::write(config_dir.join("auth.json"), poisoned).unwrap();
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            !chain.contains("rt_AAAA"),
            "error chain must not echo token fragments: {chain}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn complete_login_canonical_is_mode_0400() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        complete_login(
            dir.path(),
            acc(11),
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        )
        .unwrap();
        let canonical = dir.path().join("credentials/codex-11.json");
        let mode = std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "canonical must land at 0o400 per INV-P08");
    }

    // ── parse_device_code_line ─────────────────────────────────

    #[test]
    fn parse_device_code_line_extracts_url_and_code() {
        let line =
            "Go to https://chat.openai.com/codex/verify?user_code=ABCD-EFGH and enter ABCD-EFGH";
        let info = parse_device_code_line(line).unwrap();
        assert_eq!(info.user_code, "ABCD-EFGH");
        assert!(info.verification_url.contains("chat.openai.com"));
    }

    #[test]
    fn parse_device_code_line_ignores_lines_without_url() {
        assert!(parse_device_code_line("Waiting for user…").is_none());
        assert!(parse_device_code_line("Code: ABCD-EFGH").is_none());
    }

    #[test]
    fn parse_device_code_line_rejects_lowercase_codes() {
        let line = "Visit https://example.com with code abcd-efgh";
        // All-lowercase is not a device-code shape per
        // is_device_code_shape (uppercase/digits only).
        assert!(parse_device_code_line(line).is_none());
    }

    /// Journal 0021 finding M1: narrow `is_device_code_shape` to
    /// exactly `XXXX-XXXX`. The prior 6-16-char predicate would
    /// match routine stderr tokens like `NOTICE`, `WARNING`,
    /// `FATAL7`, `ID-ABCDE`. This test pins the refusal.
    #[test]
    fn parse_device_code_line_rejects_help_output_shapes() {
        // URL + a mixed-case status word — would have matched the
        // pre-fix 6-16 predicate for `FATAL7`, `NOTICE`.
        assert!(parse_device_code_line("See https://foo NOTICE: connection").is_none());
        assert!(parse_device_code_line("https://foo WARNING please").is_none());
        assert!(parse_device_code_line("https://foo FATAL7").is_none());
        // An ID-like token with a dash but wrong segment lengths.
        assert!(parse_device_code_line("Visit https://foo code ID-ABCDE").is_none());
        // No dash.
        assert!(parse_device_code_line("https://foo ABCDEFGH").is_none());
        // Dash in the wrong position.
        assert!(parse_device_code_line("https://foo AB-CDEFGH").is_none());
        // Too long.
        assert!(parse_device_code_line("https://foo ABCDE-FGHIJ").is_none());
    }

    #[test]
    fn is_device_code_shape_accepts_exactly_xxxx_dash_xxxx() {
        assert!(is_device_code_shape("ABCD-EFGH"));
        assert!(is_device_code_shape("1234-5678"));
        assert!(is_device_code_shape("A1B2-C3D4"));
    }

    #[test]
    fn is_device_code_shape_rejects_anything_else() {
        assert!(!is_device_code_shape(""));
        assert!(!is_device_code_shape("ABCD"));
        assert!(!is_device_code_shape("ABCD-"));
        assert!(!is_device_code_shape("-EFGH"));
        assert!(!is_device_code_shape("ABCD-EFG"));
        assert!(!is_device_code_shape("ABCDE-FGHI"));
        assert!(!is_device_code_shape("ABCD_EFGH"));
        assert!(!is_device_code_shape("abcd-efgh"));
        assert!(!is_device_code_shape("ABCD-EFGH-IJKL"));
    }

    #[test]
    fn parse_device_code_line_tolerates_trailing_punctuation_on_url() {
        let line = "See https://chat.openai.com/codex/verify, then enter ABCD-EFGH.";
        let info = parse_device_code_line(line).unwrap();
        assert!(!info.verification_url.ends_with(','));
        assert_eq!(info.user_code, "ABCD-EFGH");
    }

    // ── R4 scrub regression (journal 0021 finding 15) ─────────

    /// If `save_canonical_for` fails AFTER codex has written
    /// `auth.json`, the raw auth.json MUST be removed before the
    /// error returns. Otherwise live access+refresh tokens sit on
    /// disk between the failed attempt and the next retry.
    ///
    /// We simulate save failure by making the `credentials/`
    /// directory read-only before the login runs. The spawn closure
    /// writes a stub auth.json; `credentials::save` then fails on
    /// the atomic rename into the read-only dir; the scrub helper
    /// removes the raw auth.json before the Err returns.
    #[cfg(unix)]
    #[test]
    fn complete_login_scrubs_written_auth_json_when_canonical_save_fails() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        tos::acknowledge(dir.path()).unwrap();

        // Pre-create credentials/ and make it read-only so the
        // atomic_replace inside save_canonical_for fails.
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::set_permissions(
            &creds_dir,
            std::fs::Permissions::from_mode(0o500), // r-x, no write
        )
        .unwrap();

        let account = acc(21);
        let written = surface::written_auth_json_path(dir.path(), account);

        let result = complete_login(
            dir.path(),
            account,
            false,
            || Ok(false),
            |config_dir, _| {
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
            |_| {},
        );

        // Must return Err — the canonical save fails on the
        // read-only dir.
        assert!(
            result.is_err(),
            "expected Err when credentials/ is read-only, got: {result:?}"
        );
        let err_msg = format!("{}", result.unwrap_err());
        // The outward-facing message is operator-readable and does
        // NOT echo tokens — the same guarantee we assert in
        // `complete_login_redacts_malformed_auth_json_tokens`.
        assert!(
            !err_msg.contains("rt_"),
            "no raw refresh prefix may appear in the error: {err_msg}"
        );

        // Restore permissions so TempDir cleanup works.
        std::fs::set_permissions(&creds_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Invariant: the raw auth.json that codex wrote MUST be
        // gone (R4 fix). Pre-fix this file would sit on disk at
        // whatever mode codex-cli wrote, with live tokens in it.
        assert!(
            !written.exists(),
            "raw auth.json at {} must be scrubbed after save_canonical_for failure \
             (journal 0021 finding 15)",
            written.display()
        );
    }
}
