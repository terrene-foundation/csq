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
//! 5. Parse `config-<N>/auth.json` as a `CodexCredentialFile`.
//!    Relocate to `identities/<UUID>/credentials-codex.json` at 0o600 via
//!    [`crate::credentials::file::save_canonical_for`] (M4-12: UUID-keyed write,
//!    numeric `credentials/codex-<N>.json` retired). Delete the original raw
//!    auth.json since the handle dir will symlink to the canonical from now on.
//! 6. Write the `.csq-account` marker and a best-effort profile
//!    entry (label derived from `account_id`, not `id_token` — spec
//!    forbids decoding id_token JWT claims for data minimisation).
//!
//! Daemon registration (refresher + usage poller) is NOT part of
//! this PR — PR-C3c chains `discover_codex` into the refresher;
//! PR-C4 implements `broker_codex_check`. A freshly-logged-in Codex
//! slot sits idle in `identities/<UUID>/credentials-codex.json` until those land,
//! which is acceptable because codex-cli's own in-process refresh
//! path still works (INV-P01 only becomes load-bearing when the
//! daemon owns refresh cadence).

use super::keychain::{self, ProbeResult};
use super::surface;
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::credentials::{self, file as cred_file, CredentialFile};
use crate::daemon::identity_mint;
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

/// RAII guard that secures and removes `config-<N>/auth.json` on drop.
///
/// Codex-cli writes `auth.json` at umask-default permissions (typically
/// 0o644) with live JWT tokens inside. The guard ensures cleanup runs on
/// EVERY exit path from `perform_with` — success AND all error branches —
/// so the token-bearing file never lingers at world-readable permissions.
///
/// # Drop behaviour
///
/// 1. `secure_file` → flip to 0o600 (best-effort; may fail on FAT/network fs).
/// 2. `remove_file` → unlink. On failure, zero-fill the content so tokens
///    cannot be read from a dangling inode, and log at `error` level so the
///    event surfaces in operator telemetry.
///
/// The guard is only armed after `codex login --device-auth` exits 0, i.e.
/// when `auth.json` is expected to exist. It is a no-op when the path does
/// not exist (e.g. the codex spawn itself failed and wrote nothing).
struct AuthJsonCleanupGuard {
    path: std::path::PathBuf,
    slot: u16,
}

impl AuthJsonCleanupGuard {
    fn new(path: std::path::PathBuf, slot: u16) -> Self {
        Self { path, slot }
    }
}

impl Drop for AuthJsonCleanupGuard {
    fn drop(&mut self) {
        // No-op when auth.json is genuinely absent — exists() returns false for
        // missing files AND for dangling symlinks, so we additionally check
        // symlink_metadata to detect a dangling-symlink case where we DO want
        // to unlink the symlink itself.
        if !self.path.exists() && std::fs::symlink_metadata(&self.path).is_err() {
            return;
        }
        // Flip to 0o600 to minimize the residue window before unlink.
        if let Err(e) = crate::platform::fs::secure_file(&self.path) {
            tracing::error!(
                slot = self.slot,
                error_kind = "codex_login_secure_file_failed_in_drop",
                error = %e,
                "could not chmod 0o600 raw auth.json in cleanup; tokens may be world-readable"
            );
        }
        if let Err(e) = std::fs::remove_file(&self.path) {
            if let Ok(meta) = std::fs::metadata(&self.path) {
                // Cap zero-fill to prevent OOM on a corrupted FS reporting
                // gigabytes. auth.json is ~2 KB in practice; 64 KB is generous.
                const MAX_OVERWRITE_BYTES: u64 = 64 * 1024;
                let n = meta.len().min(MAX_OVERWRITE_BYTES) as usize;
                let zeros = vec![0u8; n];
                // O_NOFOLLOW protects against same-user TOCTOU symlink swap.
                #[cfg(unix)]
                {
                    use std::io::Write as _;
                    use std::os::unix::fs::OpenOptionsExt as _;
                    if let Err(we) = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&self.path)
                        .and_then(|mut f| f.write_all(&zeros))
                    {
                        tracing::error!(
                            slot = self.slot,
                            error_kind = "codex_login_zero_fill_failed_in_drop",
                            error = %we,
                            "auth.json could not be overwritten with zeros after unlink failed; \
                             tokens remain on disk"
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    // Windows: no O_NOFOLLOW equivalent; fall back to plain write.
                    if let Err(we) = std::fs::write(&self.path, &zeros) {
                        tracing::error!(
                            slot = self.slot,
                            error_kind = "codex_login_zero_fill_failed_in_drop",
                            error = %we,
                            "auth.json could not be overwritten with zeros after unlink failed; \
                             tokens remain on disk"
                        );
                    }
                }
            }
            tracing::error!(
                slot = self.slot,
                error_kind = "codex_login_raw_auth_json_remove_failed",
                error = %e,
                "failed to remove raw auth.json after relocation; content overwrite attempted"
            );
        }
    }
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
///
/// Also exposed `pub` (was `pub(crate)`) so the CLI handler can pass
/// a custom `spawn_codex` that pipes stdout, parses the verification
/// URL via `desktop_login::parse_device_code_line`, and auto-launches
/// the URL in the user's default browser. Without this, codex-cli
/// inherits stdio and prints the URL to the terminal but never
/// opens it — the user has to copy/paste manually. Round-7 UX fix.
pub fn perform_with<R, W, P, U, S>(
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

    // Task 3: cleanup guard — secures and removes `written` (auth.json)
    // on EVERY exit path after this point, whether the remainder of the
    // function returns Ok or Err. This replaces the success-only cleanup
    // block that previously appeared after `save_canonical_for`. The guard
    // runs its Drop body regardless of how `perform_with` returns.
    //
    // Security (PR-C3b review M1): codex-cli writes auth.json at whatever
    // mode its umask produces (typically 0o644) with live tokens inside.
    // Before unlinking, flip mode to 0o600 so any residue window is
    // owner-only. If `remove_file` then fails (Windows file-lock, exotic
    // fs), best-effort overwrite with zeros so a future attacker cannot
    // recover tokens off the filesystem, and elevate the log level to
    // error so the event is visible in operator telemetry.
    //
    // The guard captures a clone of `written` (a PathBuf) and the slot
    // number for the log tag only (fixed-vocabulary, no path in log body).
    // `_auth_json_guard` (single underscore prefix): Rust keeps the value alive
    // for the full scope but suppresses the unused-variable lint. `let _ = ...`
    // would drop immediately — we need the guard alive through the function.
    let _auth_json_guard = AuthJsonCleanupGuard::new(written.clone(), account.get());

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
            // _auth_json_guard dropped here: cleanup runs on this error exit.
            return Err(anyhow!(
                "could not parse auth.json after `codex login` — re-run `csq login {} --provider codex`",
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

    // IR-L5: filter empty-string hints at the boundary so that
    // `mint_for_codex_login` only ever sees `Some(non_empty)` or `None`.
    // If codex-cli writes `"account_id": ""`, treat it as absent — do not
    // fall through to the empty-string special-case inside the match.
    let account_id_hint = codex_creds
        .tokens
        .account_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned());
    let canonical_creds = CredentialFile::Codex(codex_creds);

    // Task 2: Mint a UUID for this slot when none exists.
    //
    // Root-cause fix for the slot-12 `refresh_token_reused` bug: daemon
    // Pass 0 only mints UUIDs for Anthropic accounts; Codex-only slots
    // (never touched by `csq login N` on the Anthropic surface) have no
    // `by_slot[N]` entry.  `save_canonical_for` is fail-closed without
    // one. We call `mint_for_codex_login` HERE (after parsing auth.json,
    // before save_canonical_for) so the UUID is guaranteed by the time
    // the write is attempted.
    //
    // IR-M5: acquire the lock ONCE here and hold it across both
    // `mint_for_codex_login` and `save_canonical_for` so both writes are
    // atomic from a cross-process perspective. `mint_for_codex_login` now
    // takes `&ProfilesFileLock` as a type-witness (symmetric with
    // `mint_for_login`).
    //
    // CRIT-2: if `save_canonical_for` fails after `mint_for_codex_login`
    // succeeds, roll back the `by_slot[N]` mapping so the next `csq run N`
    // does not enter a partial-mint state. `by_email[synthetic_key]` is
    // preserved so a retry reuses the same UUID (idempotency).
    let mint_lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(_) => {
            tracing::warn!(
                account = %account,
                error_kind = "codex_login_profiles_lock_failed",
                "could not acquire profiles lock for UUID mint — login cannot complete"
            );
            return Err(anyhow!(
                "could not acquire profiles.json lock for Codex slot {} — \
                 check profiles.json permissions",
                account
            ));
        }
    };

    if let Err(e) = identity_mint::mint_for_codex_login(
        &mint_lock,
        base_dir,
        account.get(),
        account_id_hint.as_deref(),
    ) {
        tracing::warn!(
            account = %account,
            error_kind = "codex_login_uuid_mint_failed",
            reason = %e,
            "could not mint UUID for Codex slot — login cannot complete"
        );
        // auth_json_guard dropped here: cleanup runs on this error exit.
        return Err(anyhow!(
            "could not mint identity UUID for Codex slot {} — \
             check profiles.json permissions and disk space",
            account
        ));
    }

    // M4-12: `save_canonical_for` writes `identities/<UUID>/credentials-codex.json`
    // under the per-(Surface, AccountNum) mutex at 0o600 (UUID-keyed write via
    // `save_codex_canonical_for_uuid`). The numeric `credentials/codex-<N>.json`
    // write path and 0o400 flip are retired. The pre-M3-7
    // `config-<N>/codex-auth.json` mirror write is also retired; handle dirs read
    // Codex credentials through their identity-keyed symlink (spec 07 §7.2.2).
    // `save_canonical_for` is fail-closed: absent UUID mapping returns
    // `CredentialError::NoCredentials` (M4-12 Finding 1.1 fix). The mint call
    // above guarantees the UUID exists before we reach here.
    //
    // Security: `save_canonical_for`'s `CredentialError` Display
    // composes a format string that could include a serde reason.
    // Redact before user-facing chain. Origin: PR-C3b security review H1.
    if let Err(e) = cred_file::save_canonical_for(base_dir, account, &canonical_creds) {
        let redacted = redact_tokens(&e.to_string());
        tracing::warn!(
            account = %account,
            error_kind = "codex_login_canonical_save_failed",
            reason = %redacted,
            "could not persist codex canonical credential"
        );
        // CRIT-2: roll back the by_slot mapping written by mint_for_codex_login
        // so the slot is not left in a partial-mint state. by_email is preserved
        // so a retry reuses the same UUID (idempotency). Best-effort — log on
        // failure but propagate the original save error.
        if let Err(rb_err) = profiles::remove_slot_mapping(&mint_lock, base_dir, account.get()) {
            tracing::warn!(
                account = %account,
                error_kind = "codex_login_rollback_failed",
                reason = %redact_tokens(&rb_err.to_string()),
                "could not roll back partial-mint by_slot mapping after save_canonical_for failure"
            );
        }
        // auth_json_guard dropped here: cleanup runs on this error exit.
        return Err(anyhow!(
            "could not write identities/<UUID>/credentials-codex.json for account {} \
             — check `identities/` permissions",
            account
        ));
    }
    // Lock released after save_canonical_for completes (minted + written atomically).
    drop(mint_lock);

    // Clear any stale broker_failed sentinel — the fresh chain just minted by
    // codex-cli supersedes any prior `codex_token_expired` / `refresh_reused` /
    // `codex_token_invalidated` flag. Without this, `csq doctor` reports the
    // pre-login LOGIN-NEEDED status until the daemon's next pre-expiry refresh
    // (~10 days away for fresh codex tokens), which contradicts the just-
    // completed user-visible login. The sentinel's doc string ("on successful
    // refresh or login") already declared this intent.
    crate::refresh::sentinel::clear_broker_failed(base_dir, account);

    // auth_json_guard is dropped at the end of the function (success path).
    // Dropping it here explicitly keeps intent clear; the compiler elides the
    // double-drop because we `std::mem::forget` the guard on the success path
    // if needed — but in fact we WANT the cleanup to run on success too
    // (guard removes the raw auth.json regardless). The guard's Drop body
    // runs when it goes out of scope at the function's closing brace.
    //
    // Do NOT std::mem::forget(auth_json_guard) — we always want cleanup.

    // Step 6: mark + profile update.
    //
    // M4-7 (an internal ticket Phase 4, spec 02 §INV-03 + §2.3.1): the marker
    // content is the slot's identity UUID when a `by_slot` mapping
    // exists. After the `mint_for_codex_login` call above, `by_slot[N]`
    // is guaranteed to be present, so this always takes the UUID branch.
    // The fallback to the legacy decimal slot id is retained for defensive
    // correctness but will not be reached in practice after this fix.
    // The filename `.csq-account` is unchanged per OQ #3.
    match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => markers::write_csq_account(&config_dir, uuid)
            .with_context(|| format!(".csq-account marker in {}", config_dir.display()))?,
        None => markers::write_csq_account_legacy(&config_dir, account)
            .with_context(|| format!(".csq-account marker in {}", config_dir.display()))?,
    }

    let label = format_label(account, account_id_hint.as_deref());
    update_profile(base_dir, account, &label)
        .with_context(|| "update profiles.json with the new Codex account entry")?;

    // M4-2: pair `identities/<UUID>/settings.json` when a UUID mapping exists
    // for this slot. Codex does NOT use `config-<N>/settings.json` (Codex's
    // per-slot config lives in `config-<N>/config.toml`), so the source-of-truth
    // bytes are simply `{}` — an empty JSON object. The pair makes handle-dir
    // materialization see a consistent UUID-first layout for Codex slots that
    // share a slot number with an Anthropic identity (cross-surface UUID reuse).
    //
    // Non-fatal: settings pairing failure does not block login. If no UUID
    // mapping exists (daemon Pass 0 has not run, or no prior Anthropic login
    // on the same slot), the pair is skipped — the daemon's next Pass 0 will
    // mint the UUID and seed the settings file from scratch.
    if let Some(uuid) = profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        let bytes = b"{}";
        if let Err(e) = credentials::save_uuid_settings(base_dir, uuid, bytes) {
            tracing::warn!(
                account = %account,
                error_kind = "codex_uuid_settings_pair_failed",
                "codex finalize_login: could not pair UUID settings.json (non-fatal): {}",
                redact_tokens(&e.to_string())
            );
        } else {
            tracing::debug!(
                account = %account,
                "codex finalize_login: paired UUID settings.json"
            );
        }
    }

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
///
/// SR-M1: the hint is validated for control characters before use. A
/// hint containing bytes < 0x20 (control chars) is treated as absent and
/// the fallback label is used, preventing injection into operator-facing
/// terminal output and `profiles.json`.
fn format_label(account: AccountNum, account_id_hint: Option<&str>) -> String {
    // SR-M1: validate at the label-formatting boundary. The call site in
    // perform_with already filters empty strings, but format_label may be
    // called from other contexts; the guard here is the final defence.
    let valid_hint = account_id_hint.and_then(|id| {
        if id.is_empty() || id.bytes().any(|b| b < 0x20) {
            None
        } else {
            Some(id)
        }
    });
    match valid_hint {
        Some(id) => {
            // Keep the label short — account_id is a UUID, so drop the
            // trailing suffix after the first dash-block.
            let prefix = id.split('-').next().unwrap_or(id);
            format!("codex-{}/{}", account, prefix)
        }
        None => format!("codex-{}", account),
    }
}

/// Codex login `profiles.json` hook — writes `by_slot_identity[N]`.
///
/// **M8 (an internal workspace, an internal ticket Phase 4 → RN1-E):**
/// records the canonical Codex identity-class label for this slot in
/// `profiles.json::by_slot_identity`. The label comes from
/// [`format_label`] (e.g. `"codex-3/abc12345"` when `account_id_hint`
/// is present, `"codex-3"` otherwise).
///
/// ## Channel relationship
///
/// - `by_slot_identity[N]` (written here via `set_slot_identity` — M3)
///   is the non-OAuth identity channel. It is distinct from
///   `by_slot_label[N]` (user-chosen rename) so that a user rename
///   always takes precedence over the backfilled identity.
/// - `get_email` step 1.5 reads this field after checking
///   `by_slot_label` (step 1), so a rename silently wins without any
///   coordination required here.
///
/// ## Lock discipline
///
/// Acquires `ProfilesFileLock` locally before calling `set_slot_identity`.
/// The `_lock` type-witness on `set_slot_identity` (M3) mandates that the
/// caller hold the lock; acquiring it here satisfies that precondition
/// without changing `update_profile`'s signature (widening the signature
/// to accept a lock parameter is a larger refactor deferred to M13+).
///
/// ## Idempotency
///
/// Delegated to `set_slot_identity`: if `by_slot_identity[N]` already
/// equals `label`, the function returns `Ok(())` without touching disk.
fn update_profile(
    base_dir: &Path,
    account: AccountNum,
    label: &str,
) -> std::result::Result<(), crate::error::ConfigError> {
    let lock = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir)?;
    crate::accounts::profiles::set_slot_identity(&lock, base_dir, account.get(), label)
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

    /// M4-12: insert `profiles.json::by_slot[account] = fixture_uuid_for_slot(account)`
    /// so that `save_canonical_for` (now fail-closed) can resolve the UUID-keyed write
    /// path for the given slot. Must be called before any `perform_with` invocation.
    fn provision_uuid_for_account(base: &std::path::Path, account: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(account.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
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

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 2);

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

        // M4-12: numeric path `credentials/codex-2.json` is retired as a write
        // destination. Assert the UUID-keyed identity path instead.
        let uuid2 = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);
        let uuid_codex_path =
            crate::accounts::identity_store::credentials_codex_path_for(base, uuid2);
        assert!(
            uuid_codex_path.exists(),
            "M4-12: identities/<UUID>/credentials-codex.json must exist after login; \
             path: {uuid_codex_path:?}"
        );
        assert!(
            !base.join("credentials/codex-2.json").exists(),
            "M4-12: numeric credentials/codex-2.json must NOT be written post-M4-12"
        );
        // M3-7: config-N/codex-auth.json live mirror is retired (OQ #3 — Codex
        // handle dirs symlink auth.json to identities/<UUID>/credentials-codex.json
        // post-M3-3/M3-4). Codex login no longer materializes the mirror.
        assert!(
            !base.join("config-2/codex-auth.json").exists(),
            "M3-7: config-N/codex-auth.json mirror MUST NOT be written"
        );
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

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 3);

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

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 5);

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
        // M4-12: numeric path retired; assert UUID-keyed path instead.
        let uuid5 = crate::testing::identity_fixtures::fixture_uuid_for_slot(5);
        let uuid_path5 = crate::accounts::identity_store::credentials_codex_path_for(base, uuid5);
        assert!(
            uuid_path5.exists(),
            "M4-12: UUID codex cred must exist; path: {uuid_path5:?}"
        );
        assert!(
            !base.join("credentials/codex-5.json").exists(),
            "M4-12: numeric path must NOT be written"
        );
    }

    /// Regression: a successful `csq login N --provider codex` MUST clear
    /// any pre-existing `broker_failed` sentinel for slot N. Otherwise the
    /// daemon's stale flag persists until the next pre-expiry refresh
    /// (~10 days for a fresh codex chain), and `csq doctor` keeps
    /// reporting LOGIN-NEEDED for a slot the user just logged into.
    /// Origin: 2026-05-22 — slot 12 sentinel from earlier refresh
    /// attempt survived a successful re-login.
    #[test]
    fn login_success_clears_stale_broker_failed_sentinel() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(8);

        provision_uuid_for_account(base, 8);

        // Seed a stale sentinel as if a prior refresh tick had set one.
        crate::refresh::sentinel::set_broker_failed(base, account, "codex_token_invalidated")
            .unwrap();
        assert!(crate::refresh::sentinel::is_broker_failed(base, account));

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
                stub_codex_auth_json(config_dir, "id");
                Ok(fake_success())
            },
        )
        .unwrap();

        assert_eq!(outcome.label, "codex-8/id");
        assert!(
            !crate::refresh::sentinel::is_broker_failed(base, account),
            "successful login MUST clear the stale broker_failed sentinel"
        );
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
        // M4-12: the UUID-keyed `identities/<UUID>/credentials-codex.json` is
        // written at 0o600 (secure_file). The 0o400 flip on the numeric
        // `credentials/codex-<N>.json` is retired alongside the numeric write
        // path (see `save_canonical_for_codex_uuid_path_at_0o600_with_uuid` in
        // file.rs tests). Test updated to assert 0o600 on the UUID path.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(7);

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 7);

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

        let uuid7 = crate::testing::identity_fixtures::fixture_uuid_for_slot(7);
        let uuid_path = crate::accounts::identity_store::credentials_codex_path_for(base, uuid7);
        let mode = std::fs::metadata(&uuid_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "M4-12: UUID-keyed codex canonical must be at 0o600 (numeric 0o400 flip retired)"
        );
        assert!(
            !base.join("credentials/codex-7.json").exists(),
            "M4-12: numeric credentials/codex-7.json must NOT be written post-M4-12"
        );
    }

    #[test]
    fn probe_failed_proceeds_with_warning() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(8);

        // M4-12: provision UUID mapping so save_canonical_for can locate
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 8);

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
        // M4-12: numeric path retired; assert UUID-keyed path instead.
        let uuid8 = crate::testing::identity_fixtures::fixture_uuid_for_slot(8);
        let uuid_path8 = crate::accounts::identity_store::credentials_codex_path_for(base, uuid8);
        assert!(
            uuid_path8.exists(),
            "M4-12: UUID codex cred must exist; path: {uuid_path8:?}"
        );
        assert!(
            !base.join("credentials/codex-8.json").exists(),
            "M4-12: numeric path must NOT be written"
        );
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

    /// M8 acceptance: `update_profile` (called by `perform_with`) writes
    /// `by_slot_identity[N]` when `account_id_hint` is present.
    ///
    /// Arrange: tempdir base with a valid UUID mapping (required for
    /// `save_canonical_for` to succeed in `perform_with`).  Drive
    /// `perform_with` to completion using a stub auth.json that carries
    /// `account_id = "abc12345-some-uuid-tail"`.
    ///
    /// Assert: after login, `profiles.json::by_slot_identity["12"]`
    /// equals `"codex-12/abc12345"` — matching `format_label`'s
    /// first-dash-block prefix logic.
    #[test]
    fn codex_finalize_login_writes_by_slot_identity() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(12);

        // Arrange: provision UUID mapping so save_canonical_for can resolve
        // the UUID-keyed identity write path (fail-closed without mapping).
        provision_uuid_for_account(base, 12);

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
                // account_id = "abc12345-some-uuid-tail"
                // format_label strips to "abc12345" (first dash-block)
                stub_codex_auth_json(config_dir, "abc12345-some-uuid-tail");
                Ok(fake_success())
            },
        )
        .expect("perform_with should succeed");

        // Assert: by_slot_identity["12"] == "codex-12/abc12345"
        let pf = profiles::load(&profiles::profiles_path(base))
            .expect("profiles.json must be readable after login");
        assert_eq!(
            pf.by_slot_identity.get("12").map(|s| s.as_str()),
            Some("codex-12/abc12345"),
            "M8: by_slot_identity[\"12\"] must equal \"codex-12/abc12345\" after codex login \
             with account_id_hint=\"abc12345-some-uuid-tail\"; got: {:?}",
            pf.by_slot_identity.get("12")
        );
    }

    /// M8 acceptance: `update_profile` writes `by_slot_identity[N]` with
    /// the fallback `"codex-{N}"` label when no `account_id_hint` is
    /// available (i.e. `tokens.account_id` is absent or empty in the
    /// auth.json that codex-cli wrote).
    ///
    /// Arrange: auth.json with `account_id = ""` (empty string triggers
    /// the `_ => format!("codex-{}", account)` arm in `format_label`).
    ///
    /// Assert: `by_slot_identity["12"] == "codex-12"`.
    #[test]
    fn codex_finalize_login_writes_by_slot_identity_without_id_token() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(12);

        // Arrange: provision UUID mapping (required for save_canonical_for).
        provision_uuid_for_account(base, 12);

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
                // Empty account_id triggers the fallback arm in format_label.
                stub_codex_auth_json(config_dir, "");
                Ok(fake_success())
            },
        )
        .expect("perform_with should succeed");

        // Assert: by_slot_identity["12"] == "codex-12"
        let pf = profiles::load(&profiles::profiles_path(base))
            .expect("profiles.json must be readable after login");
        assert_eq!(
            pf.by_slot_identity.get("12").map(|s| s.as_str()),
            Some("codex-12"),
            "M8: by_slot_identity[\"12\"] must equal \"codex-12\" when account_id_hint is absent/empty; \
             got: {:?}",
            pf.by_slot_identity.get("12")
        );
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

    /// M4-2 Criterion: `finalize_codex_login` (the close of `perform_with`)
    /// pairs an `identities/<UUID>/settings.json` write when a UUID mapping
    /// exists in `profiles.json::by_slot` for the slot.
    ///
    /// Codex does NOT use `config-<N>/settings.json` (Codex's per-slot
    /// config lives in `config-<N>/config.toml`), so the source bytes are
    /// `{}` — an empty JSON object. The pair is a structural invariant for
    /// handle-dir materialization which expects UUID-first layout uniform
    /// across surfaces.
    ///
    /// Arrange: seed `profiles.json` with a `by_slot["3"] → UUID` mapping so
    /// the codex login's `resolve_slot_to_uuid` succeeds. Drive `perform_with`
    /// to completion via the stub codex auth.json.
    ///
    /// Assert: after login, `identities/<UUID>/settings.json` exists with the
    /// `{}` payload.
    #[test]
    fn finalize_codex_login_writes_uuid_settings() {
        use crate::accounts::identity_store::settings_path_for;
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(3);

        // Arrange: write a profiles.json mapping slot 3 → a deterministic UUID.
        let uuid = IdentityId::from_str("11111111-2222-3333-4444-555555555555").unwrap();
        let mut profiles_file = profiles::ProfilesFile::empty();
        profiles_file.by_slot.insert("3".to_string(), uuid);
        profiles_file
            .by_email
            .insert("codex-pair-test@example.com".to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &profiles_file).unwrap();

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
                stub_codex_auth_json(config_dir, "acct-uuid-7777-zzz");
                Ok(fake_success())
            },
        )
        .expect("codex login should succeed");

        // Sanity: the standard codex login bookkeeping still ran. The label
        // is `codex-<slot>/<first-dash-block>` per `format_label`.
        // M4-12: numeric `credentials/codex-3.json` is retired; assert UUID-keyed path.
        let uuid_cred = crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        assert!(
            uuid_cred.exists(),
            "M4-12: identities/<UUID>/credentials-codex.json must exist after login; \
             path: {uuid_cred:?}"
        );
        assert!(
            !base.join("credentials/codex-3.json").exists(),
            "M4-12: numeric path must NOT be written"
        );
        assert_eq!(outcome.label, "codex-3/acct");

        // M4-2 Assert: identities/<UUID>/settings.json exists with `{}` bytes.
        let uuid_settings = settings_path_for(base, uuid);
        assert!(
            uuid_settings.exists(),
            "M4-2: identities/<UUID>/settings.json must be written by codex finalize_login \
             when by_slot mapping is present; path: {uuid_settings:?}"
        );
        let written = std::fs::read(&uuid_settings).expect("UUID settings readable");
        assert_eq!(
            written.as_slice(),
            b"{}".as_slice(),
            "M4-2: Codex pair-write must seed UUID settings.json with empty JSON object; \
             actual bytes: {written:?}"
        );
    }

    /// M4-7 acceptance: `finalize_codex_login` (the marker-write step of
    /// `perform_with`) emits the slot's identity UUID as the
    /// `.csq-account` marker content when `profiles.json::by_slot`
    /// carries a mapping for the slot. Filename `.csq-account` is
    /// unchanged per OQ #3.
    #[test]
    fn finalize_codex_login_writes_uuid_to_csq_account_marker() {
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(3);

        // Seed profiles.json with a by_slot mapping so resolve_slot_to_uuid
        // returns Some(uuid) inside the codex login flow.
        let uuid = IdentityId::from_str("22222222-3333-4444-5555-666666666666").unwrap();
        let mut profiles_file = profiles::ProfilesFile::empty();
        profiles_file.by_slot.insert("3".to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &profiles_file).unwrap();

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
                stub_codex_auth_json(config_dir, "acct-codex-m47-marker");
                Ok(fake_success())
            },
        )
        .expect("codex login should succeed");

        let config_dir = base.join("config-3");
        assert_eq!(
            crate::accounts::markers::read_csq_account_uuid(&config_dir),
            Some(uuid),
            "M4-7: Codex finalize_login must write UUID content to .csq-account \
             when by_slot maps the slot"
        );
        // Numeric reader (M1-5 contract) returns None for UUID content.
        assert_eq!(
            crate::accounts::markers::read_csq_account(&config_dir),
            None,
            "M4-7: numeric reader rejects UUID-content markers"
        );
    }

    /// M4-9 (release N affordance, an internal ticket Phase 4):
    /// `finalize_codex_login` (and the broader `perform_with` flow) MUST
    /// NOT populate the v1 `profiles.json::accounts[N]` map. The slot's
    /// Codex identity is now carried by `by_slot` + `by_email` +
    /// `identities/<UUID>/identity.json`; the old `extra.surface` Codex
    /// disambiguation tag in the v1 row is retired.
    #[test]
    fn finalize_codex_login_does_not_populate_v1_accounts_map() {
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(4);

        // Seed by_slot so the codex login can resolve UUID for the pair-write.
        let uuid = IdentityId::from_str("33333333-4444-5555-6666-777777777777").unwrap();
        let mut profiles_file = profiles::ProfilesFile::empty();
        profiles_file.by_slot.insert("4".to_string(), uuid);
        // Accounts intentionally empty before the test runs.
        profiles::save(&profiles::profiles_path(base), &profiles_file).unwrap();

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
                stub_codex_auth_json(config_dir, "acct-codex-m4-9-test");
                Ok(fake_success())
            },
        )
        .expect("codex login should succeed");

        // Assert: profiles.json must NOT carry a populated v1 `accounts` key.
        // M4-13: the `accounts` struct field is removed; verify the key is
        // absent from `extra` (or is an empty object if present) — this
        // confirms finalize_login does not write v1 accounts entries.
        let pf = profiles::load(&profiles::profiles_path(base)).unwrap();
        let accounts_in_extra = pf.extra.get("accounts").and_then(|v| v.as_object());
        assert!(
            accounts_in_extra.is_none() || accounts_in_extra.is_some_and(|m| m.is_empty()),
            "M4-9/M4-13: Codex finalize_login MUST NOT populate v1 accounts map; \
             got extra[\"accounts\"]: {:?}",
            pf.extra.get("accounts")
        );
    }

    // ── Task 2: mint_for_codex_login wired into perform_with ─────────────────

    /// Root-cause regression: `perform_with` on a slot with NO prior UUID mapping
    /// (codex-only slot, daemon Pass 0 not yet run) must succeed by calling
    /// `mint_for_codex_login` to provision the UUID before `save_canonical_for`.
    #[test]
    fn perform_with_succeeds_without_prior_uuid_mapping() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(12);

        // CRITICAL: do NOT provision a UUID. This is the regression case —
        // a slot that had no UUID in profiles.json would previously fail with
        // CredentialError::NoCredentials from save_canonical_for.
        assert!(
            profiles::resolve_slot_to_uuid(base, 12).is_none(),
            "pre-condition: slot 12 must have NO UUID before login"
        );

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
                stub_codex_auth_json(config_dir, "acct-regression-fix");
                Ok(fake_success())
            },
        )
        .expect(
            "perform_with must succeed even without a pre-existing UUID mapping \
             (root-cause fix: mint_for_codex_login called before save_canonical_for)",
        );

        // UUID must now exist in profiles.json.
        let uuid = profiles::resolve_slot_to_uuid(base, 12);
        assert!(
            uuid.is_some(),
            "mint_for_codex_login must have written by_slot[12] after login"
        );

        // Canonical credentials-codex.json must exist at the UUID-keyed path.
        let uuid = uuid.unwrap();
        let uuid_cred = crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        assert!(
            uuid_cred.exists(),
            "identities/<UUID>/credentials-codex.json must exist after login; path: {uuid_cred:?}"
        );

        // auth.json must have been cleaned up.
        let auth_json = base.join("config-12/auth.json");
        assert!(
            !auth_json.exists(),
            "auth.json must be removed after successful login"
        );

        assert_eq!(outcome.label, "codex-12/acct");
    }

    // ── Task 2: CRIT-2 rollback regression test ───────────────────────────────

    /// CRIT-2 regression: when `mint_for_codex_login` succeeds (writes
    /// `by_slot[N] = UUID`) but `save_canonical_for` subsequently fails,
    /// the `by_slot[N]` mapping MUST be removed (rolled back) so the slot
    /// is not left in a partial-mint state on the next `csq run N`.
    ///
    /// `by_email[synthetic_key]` MUST be preserved so a retry reuses the
    /// same UUID (idempotency guarantee for the repair path).
    ///
    /// ## Failure mechanism
    ///
    /// We force `save_canonical_for` to fail by pre-creating the target
    /// `identities/<uuid>/credentials-codex.json` as a **directory**.
    /// `atomic_replace` (rename) cannot replace a directory with a file,
    /// so it returns an error. The presence of `identity.json` in the same
    /// directory means `mint_for_codex_login`'s fast-path returns the
    /// pre-seeded UUID without re-minting — confirming that the rollback
    /// code path in `perform_with` (not the mint) is exercised.
    ///
    /// This mechanism is cross-platform: on both Unix and Windows the OS
    /// rejects renaming a regular file over an existing directory.
    #[test]
    fn crit2_rollback_removes_by_slot_when_save_canonical_fails() {
        use crate::accounts::identity_store::{credentials_codex_path_for, identity_json_path_for};
        use crate::accounts::profiles::{load as load_profiles, profiles_path};
        use crate::testing::identity_fixtures::fixture_uuid_for_slot;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(20);
        let slot: u16 = 20;

        // Step 1: seed `by_slot[20] = uuid` AND `by_email[synthetic_key] = uuid`
        // in profiles.json so `mint_for_codex_login` takes the fast path
        // (UUID already mapped + identity.json present → returns UUID without
        // re-minting). We use the same deterministic UUID the helper produces.
        let uuid = fixture_uuid_for_slot(slot);
        let synthetic_key = format!("codex:slot-{slot}");
        let mut profiles_file = profiles::ProfilesFile::empty();
        profiles_file.by_slot.insert(slot.to_string(), uuid);
        profiles_file.by_email.insert(synthetic_key.clone(), uuid);
        profiles::save(&profiles_path(base), &profiles_file).unwrap();

        // Step 2: create `identities/<uuid>/identity.json` so the fast-path
        // `identity_path.exists()` check succeeds (mint returns the UUID
        // immediately without writing anything new).
        let identity_dir = identity_json_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();
        let identity_json_path = identity_json_path_for(base, uuid);
        std::fs::write(&identity_json_path, b"{}").unwrap();

        // Step 3: create the CREDENTIALS TARGET as a directory so
        // `atomic_replace` fails when `save_canonical_for` tries to rename
        // the temp file into place. A directory cannot be replaced by a
        // regular-file rename on any OS (Unix: EISDIR / ENOTDIR; Windows:
        // ERROR_ACCESS_DENIED / ERROR_ALREADY_EXISTS).
        let cred_dir_as_dir = credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(&cred_dir_as_dir).unwrap();

        // Step 4: call perform_with. It MUST fail because save_canonical_for
        // cannot write over the directory.
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        let result = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |config_dir| {
                stub_codex_auth_json(config_dir, "acct-crit2-rollback-test");
                Ok(fake_success())
            },
        );

        // Step 5: assert perform_with returned Err.
        assert!(
            result.is_err(),
            "CRIT-2: perform_with must return Err when save_canonical_for fails"
        );

        // Step 6: assert by_slot[20] is NOT present (rollback worked).
        let pf = load_profiles(&profiles_path(base))
            .expect("profiles.json must be readable after rollback");
        assert!(
            !pf.by_slot.contains_key(&slot.to_string()),
            "CRIT-2: by_slot[{slot}] must be removed by rollback after save_canonical_for \
             failure; profiles.by_slot = {:?}",
            pf.by_slot
        );

        // Step 7: assert by_email[synthetic_key] IS still present (preserved
        // for retry idempotency — the next login attempt reuses the same UUID).
        assert!(
            pf.by_email.contains_key(&synthetic_key),
            "CRIT-2: by_email[\"{synthetic_key}\"] must be preserved after rollback \
             (idempotency); profiles.by_email = {:?}",
            pf.by_email
        );
    }

    // ── Task 3: cleanup-on-error ──────────────────────────────────────────────

    /// Cleanup guard: when auth.json parsing fails (malformed file),
    /// auth.json must be cleaned up (removed) even though the function
    /// returns an error. This verifies that the RAII guard runs on error exits.
    #[test]
    fn auth_json_cleaned_up_on_parse_error() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = acc(9);

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::<u8>::new();

        let result = perform_with(
            base,
            account,
            &mut reader,
            &mut writer,
            || ProbeResult::Absent,
            || Ok(false),
            |config_dir| {
                // Write a syntactically invalid JSON file. credentials::load
                // will fail, causing perform_with to return Err before
                // save_canonical_for is reached. This exercises the cleanup
                // guard on an error exit BEFORE the UUID mint step.
                std::fs::write(config_dir.join("auth.json"), b"not valid json").unwrap();
                Ok(fake_success())
            },
        );

        assert!(
            result.is_err(),
            "perform_with must return Err on malformed auth.json"
        );

        // CRITICAL: auth.json must be cleaned up even though login failed.
        let auth_json = base.join(format!("config-{}/auth.json", account));
        assert!(
            !auth_json.exists(),
            "auth.json must be removed by the cleanup guard on error exit; \
             file still exists at {auth_json:?}"
        );
    }
}
