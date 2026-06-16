//! `csq rmkey <provider>` — remove a provider's settings file.

use anyhow::{anyhow, Result};
use csq_core::providers;
use std::path::Path;

pub fn handle(base_dir: &Path, provider: &str) -> Result<()> {
    if providers::get_provider(provider).is_none() {
        return Err(anyhow!("unknown provider: {provider}"));
    }

    match providers::settings::remove_settings(base_dir, provider)? {
        true => {
            println!("Removed key for {provider}.");
            Ok(())
        }
        false => {
            println!("No key configured for {provider}.");
            Ok(())
        }
    }
}
