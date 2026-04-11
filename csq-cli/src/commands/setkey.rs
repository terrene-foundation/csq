//! `csq setkey <provider> --key <KEY>` — set a provider's API key.
//!
//! If `--key` is not provided, reads from stdin (keeps the key out of
//! shell history).

use anyhow::{anyhow, Result};
use csq_core::{http, providers};
use std::io::Read;
use std::path::Path;

/// Maximum acceptable API key length in bytes. Real keys are <200 chars;
/// 4096 is generous and prevents stdin OOM attacks.
const MAX_KEY_LEN: u64 = 4096;

pub fn handle(base_dir: &Path, provider_id: &str, key_arg: Option<&str>) -> Result<()> {
    let provider = providers::get_provider(provider_id)
        .ok_or_else(|| anyhow!("unknown provider: {provider_id}"))?;

    let key = match key_arg {
        Some(k) => k.trim().to_string(),
        None => read_key_from_stdin()?,
    };

    if key.is_empty() {
        return Err(anyhow!("key is empty"));
    }

    // Strip \r for Windows clipboard paste
    let key = key.trim_end_matches('\r').to_string();

    let mut settings = providers::settings::load_settings(base_dir, provider_id)?;
    settings.set_api_key(&key)?;
    providers::settings::save_settings(base_dir, &settings)?;

    println!("Set {} key: {}", provider_id, settings.key_fingerprint());

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

/// Reads an API key from stdin with a hard size limit.
///
/// Caps at `MAX_KEY_LEN` bytes to prevent OOM on accidental `cat huge.bin | csq setkey`.
fn read_key_from_stdin() -> Result<String> {
    eprintln!("Enter API key (paste, then Ctrl-D):");
    let mut buf = String::new();
    std::io::stdin()
        .take(MAX_KEY_LEN)
        .read_to_string(&mut buf)?;
    if buf.len() as u64 >= MAX_KEY_LEN {
        return Err(anyhow!("key input too large (limit {} bytes)", MAX_KEY_LEN));
    }
    Ok(buf.trim().to_string())
}
