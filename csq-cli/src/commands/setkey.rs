//! `csq setkey <provider> --key <KEY>` — set a provider's API key.
//!
//! If `--key` is not provided, reads from the TTY with echo disabled
//! and in non-canonical mode so pastes longer than `MAX_CANON` (1024
//! bytes on Darwin/BSD) are not truncated. MiniMax JWT keys regularly
//! exceed this limit.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::third_party;
use csq_core::providers::catalog::AuthType;
use csq_core::types::AccountNum;
use csq_core::{http, providers};
use std::io::Read;
use std::path::Path;

/// Maximum acceptable API key length in bytes. Real JWT keys are
/// under 2 KiB; 4096 is generous and bounds interactive input.
const MAX_KEY_LEN: usize = 4096;

pub fn handle(
    base_dir: &Path,
    provider_id: &str,
    key_arg: Option<&str>,
    slot: Option<AccountNum>,
) -> Result<()> {
    let provider = providers::get_provider(provider_id)
        .ok_or_else(|| anyhow!("unknown provider: {provider_id}"))?;

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
            third_party::bind_provider_to_slot(base_dir, provider_id, slot, Some(&key))
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
            third_party::bind_provider_to_slot(base_dir, provider.id, slot, None)
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
