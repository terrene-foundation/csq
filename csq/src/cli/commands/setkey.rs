//! `csq setkey <provider> --key <KEY>` — set a provider's API key.
//!
//! If `--key` is not provided, reads from the TTY with echo disabled
//! and in non-canonical mode so pastes longer than `MAX_CANON` (1024
//! bytes on Darwin/BSD) are not truncated. MiniMax JWT keys regularly
//! exceed this limit.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::identity_store;
use csq_core::accounts::third_party;
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::platform::secret::{self, SecretError};
use csq_core::providers::catalog::{AuthType, Surface};
use csq_core::providers::gemini::provisioning::{self, ProvisionError};
use csq_core::types::AccountNum;
use csq_core::{http, providers};
use secrecy::SecretString;
use std::io::Read;
use std::path::Path;

/// Maximum acceptable API key length in bytes. Real JWT keys are
/// under 2 KiB; 4096 is generous and bounds interactive input.
const MAX_KEY_LEN: usize = 4096;

/// Exit code when `csq setkey` targets a slot already bound to a non-3P
/// surface — Codex (OAuth device-auth), Anthropic OAuth, or Gemini. Distinct
/// from the default anyhow-mapped `1` so scripts can detect the "wrong
/// provider for this slot — run `csq logout` first" case.
///
/// Formerly `EXIT_CODE_CODEX_SLOT` (FR-CLI-05, Codex only). Generalized to the
/// full OAuth/device-auth surface set once the guard became identity-store-
/// aware — all three refusals share the "logout-to-rebind" remediation, so
/// they share one script-detectable code.
const EXIT_CODE_SLOT_SURFACE_CONFLICT: i32 = 2;

pub fn handle(
    base_dir: &Path,
    provider_id: &str,
    key_arg: Option<&str>,
    slot: Option<AccountNum>,
) -> Result<()> {
    let provider = providers::get_provider(provider_id)
        .ok_or_else(|| anyhow!("unknown provider: {provider_id}"))?;

    // Refuse if the target slot is already bound to a non-3P surface —
    // Codex (OAuth device-auth), Anthropic OAuth (subscription), or Gemini.
    // `csq setkey` overlays 3P env keys (ANTHROPIC_BASE_URL / _AUTH_TOKEN) onto
    // the slot's settings.json; against an OAuth/device-auth slot that silently
    // overrides a live login and orphans the account's `by_slot` mapping (the
    // #995 root cause). The user must `csq logout <N>` first. Identity-store-
    // aware per `account-terminal-separation.md` MUST Rule 4 — keyed on the
    // identity store, not the M4-12-retired legacy credential mirrors.
    if let Some(msg) = check_slot_surface_conflict(base_dir, slot, provider) {
        eprintln!("{}", msg.headline);
        eprintln!("{}", msg.hint);
        std::process::exit(EXIT_CODE_SLOT_SURFACE_CONFLICT);
    }

    // Keyless providers (Ollama) take no user-supplied key. Writing
    // the settings file is enough — CC only needs the base URL, model,
    // and a placeholder auth token (see `default_auth_token`).
    if provider.auth_type == AuthType::None {
        if key_arg.is_some() {
            return Err(anyhow!("provider {provider_id} is keyless — drop --key"));
        }
        return handle_keyless(base_dir, provider, slot);
    }

    let key = match key_arg {
        Some(k) => k.trim().to_string(),
        None => read_key_interactive()?,
    };

    if key.is_empty() {
        return Err(anyhow!("key is empty"));
    }

    // Strip trailing \r from Windows clipboard paste
    let key = key.trim_end_matches('\r').to_string();

    // Apply the same shape gate to BOTH branches (global save + slot
    // bind). The slot bind path already calls this inside
    // bind_provider_to_slot, but the global save path previously
    // wrote the key directly via settings.set_api_key, leaving CRLF
    // and other control bytes free to flow into the validation
    // probe's `Authorization: Bearer {key}` header construction.
    // Security review HIGH-3.
    third_party::validate_key_shape(&key).context("key rejected")?;

    match slot {
        None => {
            // Legacy global save: settings-<provider>.json only.
            let mut settings = providers::settings::load_settings(base_dir, provider_id)?;
            settings.set_api_key(&key)?;
            providers::settings::save_settings(base_dir, &settings)?;
            println!("Set {} key: {}", provider_id, settings.key_fingerprint());
        }
        Some(slot) => {
            third_party::bind_provider_to_slot(base_dir, provider_id, slot, Some(&key), None)
                .with_context(|| format!("failed to bind {provider_id} to slot {slot}"))?;
            println!(
                "Assigned {} key to slot {} (config-{}/settings.json)",
                provider_id, slot, slot
            );
            println!("  Launch with: csq run {}", slot);
        }
    }

    // Best-effort validation probe — report status but never fail the save
    if provider.validation_endpoint.is_some() {
        eprintln!("Validating key...");
        match validate_key(provider, &key) {
            providers::validate::ValidationResult::Valid => {
                eprintln!("  ✓ Valid");
            }
            providers::validate::ValidationResult::Invalid => {
                eprintln!("  ✗ Key rejected by provider (401/403)");
            }
            providers::validate::ValidationResult::Unreachable(msg) => {
                eprintln!("  ⚠ Could not reach provider: {msg}");
            }
            providers::validate::ValidationResult::Unexpected { status, .. } => {
                eprintln!("  ⚠ Unexpected status {status} from provider");
            }
        }
    }

    Ok(())
}

/// `csq setkey gemini --slot N [--vertex-sa-json PATH]`
///
/// Per FR-G-CLI-01..03:
///
/// - **AI Studio API-key mode** — no `--key` flag; the key is read
///   from stdin (TTY hidden, piped) and stored in the
///   platform-native secret vault. The marker file
///   `credentials/gemini-<N>.json` records `auth.mode=api_key`.
///   Plaintext NEVER touches `config-<N>/`, argv, or shell history.
/// - **Vertex SA mode** — `--vertex-sa-json /abs/path/sa.json`.
///   The path is validated (regular file, ≤ 64 KiB, not a symlink)
///   and stored in the marker. The vault is unused.
///
/// `csq setkey gemini` refuses to overwrite a slot already bound to
/// Codex (FR-CLI-05 parity) or Anthropic OAuth — re-binding from
/// another surface requires `csq logout <N>` first.
pub fn handle_gemini(
    base_dir: &Path,
    slot: AccountNum,
    vertex_sa_json: Option<&Path>,
) -> Result<()> {
    refuse_if_slot_bound_to_other_surface(base_dir, slot)?;

    if let Some(sa_path) = vertex_sa_json {
        return provision_vertex(base_dir, slot, sa_path);
    }

    provision_api_key(base_dir, slot)
}

/// FR-CLI-05 parity for Gemini: refuse to clobber a slot that is
/// already bound to Codex (OAuth device-auth) or Anthropic OAuth.
/// The user has to `csq logout <N>` first.
///
/// Identity-store-aware (`account-terminal-separation.md` MUST Rule 4). The
/// prior implementation stat-ed the M4-12-retired legacy mirrors
/// (`credentials/codex-<N>.json`, `credentials/<N>.json`) which a current login
/// no longer writes — so it was blind to every post-A++ Codex / Anthropic slot.
fn refuse_if_slot_bound_to_other_surface(base_dir: &Path, slot: AccountNum) -> Result<()> {
    if identity_store::is_codex_bound_slot_identity_aware(base_dir, slot) {
        return Err(anyhow!(
            "slot {slot} is bound to Codex — run `csq logout {slot}` to rebind to Gemini"
        ));
    }
    if identity_store::is_anthropic_bound_slot(base_dir, slot) {
        return Err(anyhow!(
            "slot {slot} is bound to Claude (Anthropic OAuth) — run `csq logout {slot}` to rebind to Gemini"
        ));
    }
    Ok(())
}

/// AI Studio API-key provisioning. Reads the key interactively (or
/// from a piped stdin), validates shape, writes to the vault, then
/// writes the binding marker. Never touches the vault on validation
/// failure so a bad key cannot leave a stub credential behind.
fn provision_api_key(base_dir: &Path, slot: AccountNum) -> Result<()> {
    let key = read_key_interactive().context("failed to read Gemini API key from stdin")?;
    if key.is_empty() {
        return Err(anyhow!("key is empty"));
    }
    if !key.starts_with("AIza") {
        // AI Studio keys all start with `AIza` per Google's public
        // docs. A non-prefixed key is almost certainly a paste
        // mistake; refuse rather than write a guaranteed-rejected
        // entry to the vault.
        return Err(anyhow!(
            "expected an AI Studio API key (prefix `AIza`); got {} bytes — for Vertex AI, use --vertex-sa-json instead",
            key.len()
        ));
    }

    let vault = secret::open_default_vault().map_err(map_vault_error)?;
    provisioning::provision_api_key_via_vault(
        base_dir,
        slot,
        &SecretString::new(key.clone().into()),
        vault.as_ref(),
    )
    .map_err(map_provision_error)?;

    println!(
        "Provisioned Gemini slot {} (AI Studio API key, fingerprint: {}…{})",
        slot,
        &key[..4.min(key.len())],
        &key[key.len().saturating_sub(4)..]
    );
    println!("  Launch with: csq run {}", slot);
    Ok(())
}

/// Vertex SA provisioning. The path is canonicalised and validated
/// (regular file, ≤ 64 KiB, not a symlink) BEFORE the marker is
/// written so a half-bound state cannot result. The JSON itself is
/// not parsed — gemini-cli does that on first call.
fn provision_vertex(base_dir: &Path, slot: AccountNum, sa_path: &Path) -> Result<()> {
    // Route through core `provision_vertex_sa` (NOT a direct
    // `write_binding`) so the CLI and desktop vertex paths are symmetric
    // and the synchronous `by_slot_identity` write fires for both. The
    // prior direct-`write_binding` shortcut was the FM-7 dual-path trap
    // (verbatim Codex F-C-2 class): wiring the identity write into core
    // would have silently skipped this CLI path. Origin: an internal journal entry D3.
    let canon =
        provisioning::provision_vertex_sa(base_dir, slot, sa_path).map_err(map_provision_error)?;

    println!(
        "Provisioned Gemini slot {} (Vertex SA: {})",
        slot,
        redact_path(&canon)
    );
    println!("  Launch with: csq run {}", slot);
    Ok(())
}

/// Maps a [`SecretError`] to user-actionable text per
/// `rules/tauri-commands.md` §6 (no opaque "vault error" tag).
fn map_vault_error(e: SecretError) -> anyhow::Error {
    match e {
        SecretError::BackendUnavailable { reason } => {
            anyhow!("secret vault unavailable: {reason}")
        }
        SecretError::Locked => anyhow!("secret vault is locked — unlock the OS keychain and retry"),
        SecretError::AuthorizationRequired => {
            anyhow!("secret vault requires authorisation — approve the keychain prompt and retry")
        }
        SecretError::PermissionDenied { reason } => {
            anyhow!("secret vault denied access: {reason}")
        }
        SecretError::Timeout => anyhow!("secret vault timed out — retry shortly"),
        SecretError::InvalidKey { reason } => anyhow!("invalid Gemini key: {reason}"),
        other => anyhow!("vault error ({}): {other}", other.error_kind_tag()),
    }
}

/// Maps a [`ProvisionError`] to user-actionable text. Vault paths
/// inside this enum re-use [`map_vault_error`].
fn map_provision_error(e: ProvisionError) -> anyhow::Error {
    match e {
        ProvisionError::Vault(v) => map_vault_error(v),
        ProvisionError::VertexSaInvalid { path, reason } => {
            anyhow!("--vertex-sa-json {} rejected: {reason}", redact_path(&path))
        }
        ProvisionError::Malformed { path, reason } => {
            anyhow!("binding marker {} is corrupt: {reason}", redact_path(&path))
        }
        ProvisionError::Io { path, source } => {
            anyhow!("provisioning I/O at {}: {source}", redact_path(&path))
        }
        ProvisionError::AtomicReplace { path, reason } => {
            anyhow!("atomic write at {}: {reason}", redact_path(&path))
        }
        ProvisionError::ProfilesIdentity { reason } => anyhow!(
            "Gemini slot provisioned and usable now ({reason}). The recovery \
             label could not be written yet; the daemon repairs it on its \
             next start — no action needed."
        ),
    }
}

/// Two-line refusal message for the slot-surface-conflict guard. Structured so
/// tests can assert the wording without having to re-capture stderr, and so a
/// future desktop-UI consumer can render the two lines in different type
/// weights.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SlotSurfaceConflict {
    headline: String,
    hint: String,
}

/// Returns [`Some`] refusal iff the target slot is bound to a surface a 3P
/// API-key write would clobber — Codex, Anthropic OAuth, or Gemini — UNLESS the
/// requested provider is itself that surface. Returns [`None`] otherwise (the
/// normal write path proceeds, including 3P→3P rebind).
///
/// Identity-store-aware (`account-terminal-separation.md` MUST Rule 4): keyed on
/// the identity store, NOT the M4-12-retired legacy credential mirrors that the
/// prior `is_codex_bound_slot`-marker guard stat-ed (blind to every post-A++
/// login).
///
/// A 3P-bound slot carries only a `settings.json` env block — no OAuth /
/// device-auth binding in the identity store — so none of these predicates
/// fire and re-keying / switching 3P providers proceeds.
///
/// NB the Anthropic branch cannot gate on `provider.surface`: every 3P provider
/// (mm / deepseek / zai / ollama) AND `claude` share `surface: ClaudeCode`
/// (they all speak the Anthropic protocol via a base-URL override), so the
/// presence of an Anthropic OAuth binding is itself the refusal signal — a
/// direct-API key write would override the live subscription token.
fn check_slot_surface_conflict(
    base_dir: &Path,
    slot: Option<AccountNum>,
    provider: &providers::Provider,
) -> Option<SlotSurfaceConflict> {
    let slot = slot?;
    // Delegate the detection to the single source of truth in core (the same
    // check `bind_provider_to_slot` enforces authoritatively), then dress it in
    // the CLI's two-line, action-specific messaging.
    let surface = third_party::conflicting_bound_surface(base_dir, slot, provider)?;
    Some(match surface {
        Surface::Codex => SlotSurfaceConflict {
            headline: format!(
                "Codex slots use OAuth device-auth, not API keys — run `csq login {slot} --provider codex`"
            ),
            hint: format!(
                "(slot {slot} is currently bound to Codex; run `csq logout {slot}` first to rebind to another provider)"
            ),
        },
        Surface::Gemini => SlotSurfaceConflict {
            headline: format!("slot {slot} is bound to Gemini — run `csq logout {slot}` to rebind"),
            hint: format!(
                "(slot {slot} is currently bound to Gemini; run `csq logout {slot}` first, then re-run `csq setkey`)"
            ),
        },
        Surface::ClaudeCode => SlotSurfaceConflict {
            headline: format!(
                "slot {slot} is bound to Claude (Anthropic OAuth) — run `csq logout {slot}` to rebind"
            ),
            hint: format!(
                "(slot {slot} is a Claude subscription/OAuth account; `csq setkey` would override it with an API key — run `csq logout {slot}` first)"
            ),
        },
    })
}

/// Keyless (Ollama) branch: writes the provider settings file (or
/// slot-bound `config-N/settings.json`) with the provider's defaults.
/// No TTY prompt, no validation probe — local providers don't have
/// an auth endpoint to probe.
fn handle_keyless(
    base_dir: &Path,
    provider: &providers::Provider,
    slot: Option<AccountNum>,
) -> Result<()> {
    match slot {
        None => {
            // Round-trip `load_settings` → `save_settings`. When the
            // file is missing, `load_settings` returns the provider
            // defaults (base URL, placeholder auth token, model keys)
            // which we then persist. When it exists, the file is
            // re-saved unchanged — idempotent.
            let settings = providers::settings::load_settings(base_dir, provider.id)?;
            providers::settings::save_settings(base_dir, &settings)?;
            println!(
                "Wrote {} profile ({}).",
                provider.name, provider.settings_filename
            );
            if let Some(base) = provider.default_base_url {
                println!("  Base URL: {}", base);
            }
            println!("  Default model: {}", provider.default_model);
        }
        Some(slot) => {
            third_party::bind_provider_to_slot(base_dir, provider.id, slot, None, None)
                .with_context(|| format!("failed to bind {} to slot {slot}", provider.id))?;
            println!(
                "Assigned {} profile to slot {} (config-{}/settings.json)",
                provider.id, slot, slot
            );
            println!("  Launch with: csq run {}", slot);
        }
    }
    Ok(())
}

/// Sends a validation probe via the shared blocking HTTP client.
///
/// Delegates to `providers::validate::validate_key` with a closure that
/// wraps `csq_core::http::post_json_probe`. The probe logic (endpoint
/// selection, header construction, response classification) is pure
/// and already unit-tested; this function is the thin IO wrapper.
fn validate_key(
    provider: &providers::Provider,
    key: &str,
) -> providers::validate::ValidationResult {
    providers::validate::validate_key(provider, key, |url, headers, body| {
        http::post_json_probe(url, headers, body)
    })
}

/// Reads an API key interactively.
///
/// When stdin is a TTY, the terminal is switched to non-canonical
/// mode with echo disabled so (a) the key is hidden, (b) Enter
/// submits, and (c) pastes larger than `MAX_CANON` (1024 bytes on
/// Darwin/BSD) are not silently truncated by the line-discipline
/// buffer. When stdin is piped, falls back to `read_to_string`.
fn read_key_interactive() -> Result<String> {
    use std::io::Write;

    let stdin = std::io::stdin();

    if !stdin_is_tty() {
        let mut buf = String::new();
        stdin
            .lock()
            .take(MAX_KEY_LEN as u64 + 1)
            .read_to_string(&mut buf)?;
        if buf.len() > MAX_KEY_LEN {
            return Err(anyhow!("key input too large (limit {MAX_KEY_LEN} bytes)"));
        }
        return Ok(buf.trim().to_string());
    }

    eprint!("Enter API key (hidden, paste then Enter): ");
    std::io::stderr().flush().ok();

    let result = read_hidden_line();
    eprintln!();
    result
}

#[cfg(unix)]
fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
}

#[cfg(windows)]
fn stdin_is_tty() -> bool {
    // Windows console detection via GetConsoleMode is only
    // available behind `windows-sys`; assume TTY when running
    // interactively. Piped input on Windows still works via the
    // fallback path below because we treat a failed hidden read
    // as a non-TTY.
    true
}

/// Step signal returned by `handle_key_byte`: either continue reading
/// the next byte or break out of the read loop because the user hit
/// a submit key.
#[derive(Debug, PartialEq, Eq)]
enum KeyInputStep {
    /// Keep reading. The buffer may or may not have been mutated.
    Continue,
    /// Stop reading. The current buffer is the final key.
    Done,
}

/// Pure byte handler for the hidden-key prompt. Extracted out of
/// `read_hidden_line` so the state machine can be unit-tested without
/// putting the TTY into raw mode.
///
/// Recognized bytes:
///
/// * `\n`, `\r` — submit (`Done`)
/// * `0x1b` (ESC) — cancel immediately with `"cancelled"`. ESC is the
///   universal TTY-prompt cancel key and users reach for it when they
///   hit the wrong command. A previous revision pushed ESC into the
///   buffer as data, so `csq setkey mm --slot N` followed by ESC then
///   ENTER silently submitted a 1-byte key `"\x1b"` and left the slot
///   bound to MiniMax with a garbage token. an internal journal entry
/// * `0x04` (Ctrl-D) — cancel if buffer is empty, submit if non-empty
/// * `0x08`, `0x7f` (backspace, DEL) — pop the last byte
/// * `MAX_KEY_LEN` reached — `Err("key input too large")`
/// * anything else — push to the buffer and continue
fn handle_key_byte(byte: u8, key: &mut Vec<u8>) -> Result<KeyInputStep> {
    match byte {
        b'\n' | b'\r' => Ok(KeyInputStep::Done),
        0x1b => Err(anyhow!("cancelled")),
        0x04 => {
            if key.is_empty() {
                Err(anyhow!("cancelled"))
            } else {
                Ok(KeyInputStep::Done)
            }
        }
        0x08 | 0x7f => {
            key.pop();
            Ok(KeyInputStep::Continue)
        }
        b => {
            if key.len() >= MAX_KEY_LEN {
                return Err(anyhow!("key input too large (limit {MAX_KEY_LEN} bytes)"));
            }
            key.push(b);
            Ok(KeyInputStep::Continue)
        }
    }
}

#[cfg(unix)]
fn read_hidden_line() -> Result<String> {
    let fd: i32 = libc::STDIN_FILENO;

    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(anyhow!(
            "tcgetattr failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut modified = original;
    // Disable canonical line buffering (defeats MAX_CANON=1024
    // truncation on Darwin) and echo so the key never appears on
    // screen. Keep ISIG so Ctrl-C still raises SIGINT.
    modified.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHONL);
    modified.c_cc[libc::VMIN] = 1;
    modified.c_cc[libc::VTIME] = 0;

    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &modified) } != 0 {
        return Err(anyhow!(
            "tcsetattr failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    struct TermiosGuard {
        fd: i32,
        original: libc::termios,
    }
    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
    let _guard = TermiosGuard { fd, original };

    let mut key: Vec<u8> = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();

    loop {
        match handle.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => match handle_key_byte(byte[0], &mut key)? {
                KeyInputStep::Continue => {}
                KeyInputStep::Done => break,
            },
            Err(e) => return Err(anyhow!("stdin read failed: {e}")),
        }
    }

    let s = String::from_utf8(key).map_err(|_| anyhow!("key is not valid UTF-8"))?;
    Ok(s.trim().to_string())
}

#[cfg(windows)]
fn read_hidden_line() -> Result<String> {
    // Windows console line buffer is large enough for any real
    // API key (~8 KiB on cmd.exe, effectively unlimited in modern
    // terminals). Echo suppression would require
    // `SetConsoleMode(STD_INPUT_HANDLE, mode & !ENABLE_ECHO_INPUT)`
    // via the windows-sys crate, which is not currently a
    // dependency. Falls back to visible input for now.
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    if buf.len() > MAX_KEY_LEN {
        return Err(anyhow!("key input too large (limit {MAX_KEY_LEN} bytes)"));
    }
    Ok(buf.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Legacy pre-A++ Codex marker (`credentials/codex-<N>.json`). Still a valid
    /// binding signal via the identity-aware predicate's legacy fallback.
    fn codex_bind_legacy(dir: &Path, slot: AccountNum) {
        let creds_dir = dir.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join(format!("codex-{}.json", slot)), b"{}").unwrap();
    }

    /// Current post-M4-12 host shape: `by_slot` → `identities/<uuid>/` with the
    /// given provider + a matching credential file, and NO legacy mirror. This
    /// is the state a real login leaves; the pre-fix legacy-marker guard was
    /// blind to it (the bug this shard fixes).
    fn bind_identity(dir: &Path, slot: u16, provider: &str) {
        use csq_core::accounts::identity_store::{
            credentials_codex_path_for, credentials_path_for, identity_path, IdentityId,
        };
        use csq_core::accounts::profiles::{profiles_path, save, ProfilesFile};
        let uuid = IdentityId::new_v4();
        let idir = identity_path(dir, uuid);
        std::fs::create_dir_all(&idir).unwrap();
        std::fs::write(
            idir.join("identity.json"),
            format!(r#"{{"email":"x","provider":"{provider}","created_at":"t","key_id":null}}"#),
        )
        .unwrap();
        let cred_path = if provider == "codex" {
            credentials_codex_path_for(dir, uuid)
        } else {
            credentials_path_for(dir, uuid)
        };
        std::fs::write(cred_path, b"{}").unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        save(&profiles_path(dir), &pf).unwrap();
    }

    #[test]
    fn refuses_setkey_mm_on_legacy_codex_slot() {
        let dir = TempDir::new().unwrap();
        let slot = acc(4);
        codex_bind_legacy(dir.path(), slot);

        let mm = providers::get_provider("mm").expect("mm is registered");
        let conflict = check_slot_surface_conflict(dir.path(), Some(slot), mm)
            .expect("setkey mm on a Codex-bound slot must return the refusal message");

        assert!(
            conflict
                .headline
                .contains("OAuth device-auth, not API keys"),
            "headline must name the Codex device-auth surface: {}",
            conflict.headline
        );
        assert!(
            conflict.headline.contains("csq login 4 --provider codex"),
            "headline must name the slot + escape hatch: {}",
            conflict.headline
        );
        assert!(
            conflict.hint.contains("csq logout 4"),
            "hint must point at the rebind workflow: {}",
            conflict.hint
        );
    }

    #[test]
    fn refuses_setkey_mm_on_identity_only_codex_slot() {
        // The real-host regression: a current codex slot has NO legacy
        // `credentials/codex-N.json`; the pre-fix guard let this through.
        let dir = TempDir::new().unwrap();
        bind_identity(dir.path(), 9, "codex");
        assert!(
            !dir.path().join("credentials/codex-9.json").exists(),
            "precondition: no legacy marker (post-M4-12 shape)"
        );
        let mm = providers::get_provider("mm").unwrap();
        let conflict = check_slot_surface_conflict(dir.path(), Some(acc(9)), mm)
            .expect("identity-store codex binding must refuse a 3P setkey");
        assert!(conflict.headline.contains("OAuth device-auth"));
    }

    #[test]
    fn refuses_setkey_mm_on_identity_only_anthropic_slot() {
        // THE #995 origin: a 3P key write over an Anthropic OAuth slot silently
        // overrode the subscription token and orphaned by_slot. Now refused.
        let dir = TempDir::new().unwrap();
        bind_identity(dir.path(), 3, "anthropic");
        assert!(
            !dir.path().join("credentials/3.json").exists(),
            "precondition: no legacy mirror (post-M4-12 shape)"
        );
        let mm = providers::get_provider("mm").unwrap();
        let conflict = check_slot_surface_conflict(dir.path(), Some(acc(3)), mm)
            .expect("Anthropic OAuth binding must refuse a 3P setkey");
        assert!(
            conflict.headline.contains("Claude (Anthropic OAuth)"),
            "headline must name the Claude OAuth surface: {}",
            conflict.headline
        );
        assert!(conflict.hint.contains("csq logout 3"));
    }

    #[test]
    fn refuses_setkey_claude_apikey_on_anthropic_oauth_slot() {
        // `claude` (direct-API key) shares surface: ClaudeCode with the 3P
        // providers, so the guard must NOT let it clobber an OAuth slot either —
        // the binding presence, not provider.surface, is the refusal signal.
        let dir = TempDir::new().unwrap();
        bind_identity(dir.path(), 3, "anthropic");
        let claude = providers::get_provider("claude").unwrap();
        assert!(
            check_slot_surface_conflict(dir.path(), Some(acc(3)), claude).is_some(),
            "setkey claude (API key) must refuse to override an Anthropic OAuth slot"
        );
    }

    #[test]
    fn allows_setkey_mm_on_unbound_slot() {
        // Empty base → no OAuth/device-auth binding of any surface → proceeds.
        let dir = TempDir::new().unwrap();
        let mm = providers::get_provider("mm").unwrap();
        assert_eq!(
            check_slot_surface_conflict(dir.path(), Some(acc(4)), mm),
            None
        );
    }

    #[test]
    fn allows_setkey_mm_on_3p_bound_slot() {
        // A 3P-bound slot carries only a settings.json env block — none of the
        // OAuth/device-auth markers — so a 3P→3P rebind must proceed. Model it
        // by binding an identity with a NON-anthropic, NON-codex provider tag
        // (a 3P provider id), which leaves no anthropic/codex credential.
        let dir = TempDir::new().unwrap();
        // A deepseek-bound slot writes settings.json env only (no identity mint),
        // so simply: unbound identity store + a settings.json is the real shape.
        // The guard reads only the identity store / legacy markers → None.
        std::fs::create_dir_all(dir.path().join("config-5")).unwrap();
        std::fs::write(
            dir.path().join("config-5/settings.json"),
            br#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic"}}"#,
        )
        .unwrap();
        let deepseek = providers::get_provider("deepseek").unwrap();
        assert_eq!(
            check_slot_surface_conflict(dir.path(), Some(acc(5)), deepseek),
            None,
            "3P→3P rebind (settings.json env only, no OAuth binding) must proceed"
        );
    }

    #[test]
    fn allows_setkey_without_slot() {
        // Global writes (no --slot) touch no per-slot binding → unaffected.
        let dir = TempDir::new().unwrap();
        codex_bind_legacy(dir.path(), acc(4));
        let mm = providers::get_provider("mm").unwrap();
        assert_eq!(check_slot_surface_conflict(dir.path(), None, mm), None);
    }

    #[test]
    fn allows_codex_provider_on_codex_slot() {
        // A Codex-surface provider is the only thing that may touch a Codex slot.
        let dir = TempDir::new().unwrap();
        let slot = acc(4);
        codex_bind_legacy(dir.path(), slot);
        let codex = providers::get_provider("codex").unwrap();
        assert_eq!(
            check_slot_surface_conflict(dir.path(), Some(slot), codex),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn treats_dangling_legacy_codex_symlink_as_bound() {
        // Origin: PR-C3b security review L2. A dangling `credentials/codex-N.json`
        // symlink must still refuse (fail-toward-refuse); the identity-aware
        // predicate's legacy fallback uses `symlink_metadata`, not `.exists()`.
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let slot = acc(6);
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        symlink(
            dir.path().join("nowhere.json"),
            creds_dir.join("codex-6.json"),
        )
        .unwrap();

        let mm = providers::get_provider("mm").unwrap();
        assert!(
            check_slot_surface_conflict(dir.path(), Some(slot), mm).is_some(),
            "dangling Codex symlink must still refuse setkey"
        );
    }

    fn run_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut key = Vec::new();
        for &b in bytes {
            match handle_key_byte(b, &mut key)? {
                KeyInputStep::Continue => {}
                KeyInputStep::Done => return Ok(key),
            }
        }
        Ok(key)
    }

    #[test]
    fn submits_on_newline() {
        let key = run_bytes(b"hello\n").unwrap();
        assert_eq!(key, b"hello");
    }

    #[test]
    fn submits_on_carriage_return() {
        let key = run_bytes(b"hello\r").unwrap();
        assert_eq!(key, b"hello");
    }

    #[test]
    fn escape_cancels_on_empty_buffer() {
        let err = run_bytes(&[0x1b]).unwrap_err().to_string();
        assert_eq!(err, "cancelled");
    }

    #[test]
    fn escape_cancels_even_with_partial_buffer() {
        // The pre-fix bug: ESC was pushed into the buffer, then ENTER
        // submitted "\x1b" as the key. This test asserts the new
        // contract: ESC unconditionally cancels, regardless of what
        // the user already typed.
        let err = run_bytes(b"partial\x1b").unwrap_err().to_string();
        assert_eq!(err, "cancelled");
    }

    #[test]
    fn ctrl_d_on_empty_cancels() {
        let err = run_bytes(&[0x04]).unwrap_err().to_string();
        assert_eq!(err, "cancelled");
    }

    #[test]
    fn ctrl_d_on_nonempty_submits() {
        let key = run_bytes(&[b'a', b'b', 0x04]).unwrap();
        assert_eq!(key, b"ab");
    }

    #[test]
    fn backspace_pops_last_byte() {
        let key = run_bytes(&[b'a', b'b', 0x08, b'c', b'\n']).unwrap();
        assert_eq!(key, b"ac");
    }

    #[test]
    fn del_pops_last_byte() {
        let key = run_bytes(&[b'a', b'b', 0x7f, b'c', b'\n']).unwrap();
        assert_eq!(key, b"ac");
    }

    #[test]
    fn overflow_returns_error() {
        let mut key = vec![b'x'; MAX_KEY_LEN];
        let err = handle_key_byte(b'y', &mut key).unwrap_err().to_string();
        assert!(err.contains("too large"), "got: {err}");
    }

    #[test]
    fn non_special_bytes_accumulate() {
        let key = run_bytes(b"sk-ant-oat01-test\n").unwrap();
        assert_eq!(key, b"sk-ant-oat01-test");
    }
}
