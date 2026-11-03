//! Vault-backed bridge secrets: the Telegram bot token and the attestation
//! origin key.
//!
//! Both live in [`crate::platform::secret`] (the platform keychain, or the
//! Linux file backend), never in the config JSON. Reads return
//! [`SecretString`] for the token (callers must `expose_secret()` at the HTTP
//! call site and never format it); the origin key is returned as fixed bytes so
//! it cannot be accidentally formatted.
//!
//! # Naming
//!
//! The keys are built through [`NamedKey::bridge`], which renders the native
//! names `csq.bridge.telegram-bot` and `csq.bridge.origin`. The bridge
//! deliberately does NOT use `csq.pool.*`: that namespace carries its own
//! contract and a dated exception (`security.md` §6), and a bridge credential
//! must not be read as inheriting them.
//!
//! # No secrets in errors
//!
//! Stored values are decoded inside this module and every failure becomes a
//! fixed-reason [`SecretError::InvalidKey`] — never the value, never the
//! upstream error text (`security.md` MUST-2). The bot token is the most
//! sensitive string in the bridge: Telegram embeds it in the request URL path,
//! so any error that echoed a URL would leak it.

use crate::platform::secret::{open_default_vault, NamedKey, Vault};
use secrecy::{ExposeSecret, SecretString};

/// Re-exported so callers that name a bridge secret error do not also have to
/// reach into `platform::secret` (the daemon ingest matches
/// `SecretError::NamedNotFound` to distinguish "not provisioned yet").
pub use crate::platform::secret::SecretError;

/// Bridge native-key kind for the Telegram bot token (`csq.bridge.telegram-bot`).
const BOT_TOKEN_KIND: &str = "telegram-bot";

/// Bridge native-key kind for the attestation origin key
/// (`csq.bridge.origin`).
const ORIGIN_KEY_KIND: &str = "origin";

/// Raw byte length of the origin key.
pub const ORIGIN_KEY_BYTES: usize = 32;

/// Longest bot token accepted (Telegram's own are well under half this).
const MAX_BOT_TOKEN_BYTES: usize = 256;

/// Shortest secret half of a bot token Telegram issues today.
const MIN_BOT_TOKEN_SECRET: usize = 30;

fn invalid(reason: &'static str) -> SecretError {
    SecretError::InvalidKey {
        reason: reason.to_owned(),
    }
}

/// Structural check for `<bot_id>:<secret>` before a token is stored or used.
///
/// Telegram bot tokens are `<decimal bot id>:<35-char [A-Za-z0-9_-] secret>`.
/// This refuses whitespace, control characters and a second `:`, which is what
/// a copy-paste accident or an injected newline looks like. It never includes
/// the candidate in a message.
pub fn validate_bot_token_shape(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_BOT_TOKEN_BYTES {
        return false;
    }
    if token.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let Some((bot_id, secret)) = token.split_once(':') else {
        return false;
    };
    if secret.contains(':') {
        return false;
    }
    !bot_id.is_empty()
        && bot_id.len() <= 20
        && bot_id.bytes().all(|b| b.is_ascii_digit())
        && secret.len() >= MIN_BOT_TOKEN_SECRET
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Reads the bot token, refusing a value whose shape Telegram could not have
/// issued (a truncated paste is not a credential).
pub fn load_bot_token() -> Result<SecretString, SecretError> {
    let vault = open_default_vault()?;
    load_bot_token_from(vault.as_ref())
}

pub(crate) fn load_bot_token_from(vault: &dyn Vault) -> Result<SecretString, SecretError> {
    let token = vault.get_named(&NamedKey::bridge(BOT_TOKEN_KIND)?)?;
    if !validate_bot_token_shape(token.expose_secret()) {
        return Err(invalid("stored bot token has invalid shape"));
    }
    Ok(token)
}

/// Stores the bot token, refusing a malformed value before it reaches the
/// vault.
pub fn store_bot_token(token: &SecretString) -> Result<(), SecretError> {
    let vault = open_default_vault()?;
    store_bot_token_in(vault.as_ref(), token)
}

pub(crate) fn store_bot_token_in(
    vault: &dyn Vault,
    token: &SecretString,
) -> Result<(), SecretError> {
    if !validate_bot_token_shape(token.expose_secret()) {
        return Err(invalid("refusing to store a malformed bot token"));
    }
    vault.set_named(&NamedKey::bridge(BOT_TOKEN_KIND)?, token)
}

/// Removes the bot token. Idempotent, so `rotate` works when no token is
/// stored.
pub fn clear_bot_token() -> Result<(), SecretError> {
    let vault = open_default_vault()?;
    clear_bot_token_in(vault.as_ref())
}

pub(crate) fn clear_bot_token_in(vault: &dyn Vault) -> Result<(), SecretError> {
    match vault.delete_named(&NamedKey::bridge(BOT_TOKEN_KIND)?) {
        Ok(()) | Err(SecretError::NamedNotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Whether a bot token is stored, without materialising the value.
pub fn bot_token_present() -> Result<bool, SecretError> {
    let vault = open_default_vault()?;
    vault.contains_named(&NamedKey::bridge(BOT_TOKEN_KIND)?)
}

/// Reads the 32-byte attestation origin key.
pub fn load_origin_key() -> Result<[u8; ORIGIN_KEY_BYTES], SecretError> {
    let vault = open_default_vault()?;
    load_origin_key_from(vault.as_ref())
}

pub(crate) fn load_origin_key_from(
    vault: &dyn Vault,
) -> Result<[u8; ORIGIN_KEY_BYTES], SecretError> {
    let stored = vault.get_named(&NamedKey::bridge(ORIGIN_KEY_KIND)?)?;
    decode_fixed_hex(
        stored.expose_secret(),
        "stored origin key has invalid shape",
    )
}

/// Stores the 32-byte attestation origin key.
pub fn store_origin_key(key: &[u8; ORIGIN_KEY_BYTES]) -> Result<(), SecretError> {
    let vault = open_default_vault()?;
    store_origin_key_in(vault.as_ref(), key)
}

pub(crate) fn store_origin_key_in(
    vault: &dyn Vault,
    key: &[u8; ORIGIN_KEY_BYTES],
) -> Result<(), SecretError> {
    vault.set_named(
        &NamedKey::bridge(ORIGIN_KEY_KIND)?,
        &SecretString::from(hex::encode(key)),
    )
}

/// Returns the origin key, generating and storing one on first use.
///
/// The origin key is the only thing that lets a delivery be attributed to the
/// owner; it is created locally on the owner's machine and never leaves it.
pub fn ensure_origin_key() -> Result<[u8; ORIGIN_KEY_BYTES], SecretError> {
    let vault = open_default_vault()?;
    match load_origin_key_from(vault.as_ref()) {
        Ok(key) => Ok(key),
        Err(SecretError::NamedNotFound) => {
            let key = generate_key_bytes()?;
            store_origin_key_in(vault.as_ref(), &key)?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Generates `ORIGIN_KEY_BYTES` from the OS CSPRNG.
pub fn generate_key_bytes() -> Result<[u8; ORIGIN_KEY_BYTES], SecretError> {
    let mut bytes = [0u8; ORIGIN_KEY_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|_| invalid("secure random source unavailable"))?;
    Ok(bytes)
}

fn decode_fixed_hex(
    text: &str,
    reason: &'static str,
) -> Result<[u8; ORIGIN_KEY_BYTES], SecretError> {
    let mut out = [0u8; ORIGIN_KEY_BYTES];
    if text.len() != ORIGIN_KEY_BYTES * 2 {
        return Err(invalid(reason));
    }
    hex::decode_to_slice(text, &mut out).map_err(|_| invalid(reason))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::secret::in_memory::InMemoryVault;

    fn token(secret: &str) -> SecretString {
        SecretString::from(format!("123456789:{secret}"))
    }

    #[test]
    fn bot_token_round_trip() {
        let vault = InMemoryVault::new();
        let value = token(&"A".repeat(35));
        store_bot_token_in(&vault, &value).expect("store");
        let loaded = load_bot_token_from(&vault).expect("load");
        assert_eq!(loaded.expose_secret(), value.expose_secret());
        assert!(vault
            .contains_named(&NamedKey::bridge(BOT_TOKEN_KIND).unwrap())
            .unwrap());
    }

    #[test]
    fn malformed_stored_token_is_refused_without_echoing_it() {
        let vault = InMemoryVault::new();
        // Plant a value that a shape check must reject, bypassing the store guard.
        vault
            .set_named(
                &NamedKey::bridge(BOT_TOKEN_KIND).unwrap(),
                &SecretString::from("NOT-A-TELEGRAM-TOKEN-SENTINEL"),
            )
            .expect("plant");
        let error = load_bot_token_from(&vault).expect_err("must refuse");
        assert_eq!(error.error_kind_tag(), "vault_invalid_key");
        assert!(
            !error.to_string().contains("NOT-A-TELEGRAM-TOKEN-SENTINEL"),
            "error text must not echo the stored value"
        );
    }

    #[test]
    fn malformed_token_is_refused_before_the_vault() {
        let vault = InMemoryVault::new();
        let bad = SecretString::from("no-colon-here");
        assert!(store_bot_token_in(&vault, &bad).is_err());
        assert!(!vault
            .contains_named(&NamedKey::bridge(BOT_TOKEN_KIND).unwrap())
            .unwrap());
    }

    #[test]
    fn origin_key_round_trip_and_shape_guard() {
        let vault = InMemoryVault::new();
        let key = [7u8; ORIGIN_KEY_BYTES];
        store_origin_key_in(&vault, &key).expect("store");
        assert_eq!(load_origin_key_from(&vault).expect("load"), key);
        vault
            .set_named(
                &NamedKey::bridge(ORIGIN_KEY_KIND).unwrap(),
                &SecretString::from("abcd"),
            )
            .expect("plant");
        let error = load_origin_key_from(&vault).expect_err("short key refused");
        assert_eq!(error.error_kind_tag(), "vault_invalid_key");
    }

    #[test]
    fn clear_is_idempotent() {
        let vault = InMemoryVault::new();
        clear_bot_token_in(&vault).expect("absent is fine");
        store_bot_token_in(&vault, &token(&"B".repeat(35))).expect("store");
        clear_bot_token_in(&vault).expect("delete");
        assert!(!vault
            .contains_named(&NamedKey::bridge(BOT_TOKEN_KIND).unwrap())
            .unwrap());
    }

    #[test]
    fn generated_material_is_32_bytes() {
        let key = generate_key_bytes().expect("csprng");
        assert_eq!(key.len(), ORIGIN_KEY_BYTES);
        assert_ne!(key, [0u8; ORIGIN_KEY_BYTES]);
    }
}
