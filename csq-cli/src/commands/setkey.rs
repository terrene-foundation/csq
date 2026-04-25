//! `csq setkey <provider> --key <KEY>` — set a provider's API key.
//!
//! If `--key` is not provided, reads from the TTY with echo disabled
//! and in non-canonical mode so pastes longer than `MAX_CANON` (1024
//! bytes on Darwin/BSD) are not truncated. MiniMax JWT keys regularly
//! exceed this limit.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::third_party;
use csq_core::credentials::file as cred_file;
use csq_core::platform::secret::{self, SecretError, SlotKey};
use csq_core::providers::catalog::{AuthType, Surface};
use csq_core::providers::gemini::provisioning::{self, AuthMode, GeminiBinding, ProvisionError};
use csq_core::providers::gemini::SURFACE_GEMINI;
use csq_core::types::AccountNum;
use csq_core::{http, providers};
use secrecy::SecretString;
use std::io::Read;
use std::path::Path;

/// Maximum acceptable API key length in bytes. Real JWT keys are
/// under 2 KiB; 4096 is generous and bounds interactive input.
const MAX_KEY_LEN: usize = 4096;

/// FR-CLI-05 exit code: `csq setkey` targets a slot already bound to
/// Codex (OAuth device-auth). Distinct from the default anyhow-mapped
/// `1` so scripts can detect the "wrong provider for this slot" case.
const EXIT_CODE_CODEX_SLOT: i32 = 2;

pub fn handle(
    base_dir: &Path,
    provider_id: &str,
    key_arg: Option<&str>,
    slot: Option<AccountNum>,
) -> Result<()> {
    let provider = providers::get_provider(provider_id)
        .ok_or_else(|| anyhow!("unknown provider: {provider_id}"))?;

    // FR-CLI-05: refuse if the target slot is already bound to Codex.
    // `csq setkey` writes an API-key-backed provider into a slot's
    // settings.json / canonical file; overwriting a Codex-bound slot
    // would leave `credentials/codex-<N>.json` orphaned AND destroy
    // a live OAuth session the user probably still wants.
    if let Some(msg) = check_codex_slot_conflict(base_dir, slot, provider) {
        eprintln!("{}", msg.headline);
        eprintln!("{}", msg.hint);
        std::process::exit(EXIT_CODE_CODEX_SLOT);
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
fn refuse_if_slot_bound_to_other_surface(base_dir: &Path, slot: AccountNum) -> Result<()> {
    if is_codex_bound_slot(base_dir, slot) {
        return Err(anyhow!(
            "slot {slot} is bound to Codex — run `csq logout {slot}` to rebind to Gemini"
        ));
    }
    let anthropic_canonical = cred_file::canonical_path_for(base_dir, slot, Surface::ClaudeCode);
    if std::fs::symlink_metadata(&anthropic_canonical).is_ok() {
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
    let slot_key = SlotKey {
        surface: SURFACE_GEMINI,
        account: slot,
    };
    vault
        .set(slot_key, &SecretString::new(key.clone().into()))
        .map_err(map_vault_error)?;

    let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
    if let Err(e) = provisioning::write_binding(base_dir, slot, &binding) {
        // Marker write failed — roll back the vault entry so the
        // operator can retry without a half-bound state.
        let _ = vault.delete(slot_key);
        return Err(map_provision_error(e));
    }

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
    let canon = provisioning::validate_vertex_sa_path(sa_path).map_err(map_provision_error)?;
    let binding = GeminiBinding::new(
        AuthMode::VertexSa {
            path: canon.clone(),
        },
        "auto",
    );
    provisioning::write_binding(base_dir, slot, &binding).map_err(map_provision_error)?;

    println!(
        "Provisioned Gemini slot {} (Vertex SA: {})",
        slot,
        canon.display()
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
            anyhow!("--vertex-sa-json {} rejected: {reason}", path.display())
        }
        ProvisionError::Malformed { path, reason } => {
            anyhow!("binding marker {} is corrupt: {reason}", path.display())
        }
        ProvisionError::Io { path, source } => {
            anyhow!("provisioning I/O at {}: {source}", path.display())
        }
        ProvisionError::AtomicReplace { path, reason } => {
            anyhow!("atomic write at {}: {reason}", path.display())
        }
    }
}

/// Whether slot `N` is currently backed by a Codex canonical
/// credential file. Uses [`std::fs::symlink_metadata`] rather than
/// [`Path::exists`] so a dangling symlink at the canonical path is
/// detected as "bound" — refusing a setkey against it is the safer
/// posture because the dangling link can later be repaired back to a
/// valid Codex credential. A pure filesystem check that does not
/// read the file or parse its contents. Origin: PR-C3b security
/// review L2.
fn is_codex_bound_slot(base_dir: &Path, slot: AccountNum) -> bool {
    let path = cred_file::canonical_path_for(base_dir, slot, Surface::Codex);
    std::fs::symlink_metadata(&path).is_ok()
}

/// Two-line refusal message for the FR-CLI-05 guard. Structured so
/// tests can assert the wording without having to re-capture stderr,
/// and so a future desktop-UI consumer can render the two lines in
/// different type weights.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CodexSlotConflict {
    headline: String,
    hint: String,
}

/// Returns [`Some`] with the FR-CLI-05 refusal message iff the target
/// slot is bound to Codex AND the requested provider is not itself
/// Codex (the only provider that should ever touch a Codex slot).
/// Returns [`None`] otherwise — the normal write path proceeds.
fn check_codex_slot_conflict(
    base_dir: &Path,
    slot: Option<AccountNum>,
    provider: &providers::Provider,
) -> Option<CodexSlotConflict> {
    let slot = slot?;
    if !is_codex_bound_slot(base_dir, slot) {
        return None;
    }
    if provider.surface == Surface::Codex {
        return None;
    }
    Some(CodexSlotConflict {
        headline: format!(
            "Codex slots use OAuth device-auth, not API keys — run `csq login {slot} --provider codex`"
        ),
        hint: format!(
            "(slot {slot} is currently bound to Codex; run `csq logout {slot}` first to rebind to another provider)"
        ),
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
///   bound to MiniMax with a garbage token. Journal 0058.
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

    #[test]
    fn is_codex_bound_slot_detects_canonical_file() {
        let dir = TempDir::new().unwrap();
        let slot = acc(4);
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();

        // Before any Codex file exists, the slot is not Codex-bound.
        assert!(!is_codex_bound_slot(dir.path(), slot));

        // `credentials/codex-4.json` → slot is Codex-bound.
        std::fs::write(creds_dir.join("codex-4.json"), b"{}").unwrap();
        assert!(is_codex_bound_slot(dir.path(), slot));
    }

    #[test]
    fn is_codex_bound_slot_ignores_anthropic_canonical() {
        let dir = TempDir::new().unwrap();
        let slot = acc(5);
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();

        // Only `<N>.json` — Anthropic shape — exists. Not Codex-bound.
        std::fs::write(creds_dir.join("5.json"), b"{}").unwrap();
        assert!(!is_codex_bound_slot(dir.path(), slot));
    }

    fn codex_bind(dir: &Path, slot: AccountNum) {
        let creds_dir = dir.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join(format!("codex-{}.json", slot)), b"{}").unwrap();
    }

    #[test]
    fn fr_cli_05_refuses_setkey_mm_on_codex_slot() {
        let dir = TempDir::new().unwrap();
        let slot = acc(4);
        codex_bind(dir.path(), slot);

        let mm = providers::get_provider("mm").expect("mm is registered");
        let conflict = check_codex_slot_conflict(dir.path(), Some(slot), mm).expect(
            "setkey mm on a Codex-bound slot must return the refusal message per FR-CLI-05",
        );

        assert!(
            conflict
                .headline
                .contains("OAuth device-auth, not API keys"),
            "headline must use FR-CLI-05 wording: {}",
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
    fn fr_cli_05_allows_setkey_mm_on_anthropic_slot() {
        let dir = TempDir::new().unwrap();
        let mm = providers::get_provider("mm").unwrap();
        assert_eq!(
            check_codex_slot_conflict(dir.path(), Some(acc(4)), mm),
            None,
            "no codex canonical → setkey proceeds"
        );
    }

    #[test]
    fn fr_cli_05_allows_setkey_without_slot() {
        // Global writes (no --slot) do not touch any canonical
        // credential file and are therefore unaffected by FR-CLI-05.
        let dir = TempDir::new().unwrap();
        codex_bind(dir.path(), acc(4));
        let mm = providers::get_provider("mm").unwrap();
        assert_eq!(check_codex_slot_conflict(dir.path(), None, mm), None);
    }

    #[test]
    fn fr_cli_05_allows_codex_provider_on_codex_slot() {
        // A hypothetical future `setkey codex` for an OAI API-key
        // (non-subscription) path would itself be a Codex-surface
        // write — it must not be blocked by FR-CLI-05.
        let dir = TempDir::new().unwrap();
        let slot = acc(4);
        codex_bind(dir.path(), slot);
        let codex = providers::get_provider("codex").unwrap();
        assert_eq!(
            check_codex_slot_conflict(dir.path(), Some(slot), codex),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn fr_cli_05_treats_dangling_symlink_as_bound() {
        // Origin: PR-C3b security review L2. `Path::exists` follows
        // symlinks; a dangling `credentials/codex-N.json` symlink
        // would report not-bound and let setkey proceed. The guard
        // now uses `symlink_metadata` so the dangling-link case
        // refuses — the user can repair the link and retry.
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

        assert!(is_codex_bound_slot(dir.path(), slot));
        let mm = providers::get_provider("mm").unwrap();
        assert!(
            check_codex_slot_conflict(dir.path(), Some(slot), mm).is_some(),
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
