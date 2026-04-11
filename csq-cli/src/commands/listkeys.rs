//! `csq listkeys` — list configured provider keys.

use anyhow::Result;
use csq_core::providers;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct KeyEntry {
    provider_id: String,
    name: String,
    fingerprint: String,
    model: String,
    file: String,
}

pub fn handle(base_dir: &Path, json: bool) -> Result<()> {
    let configured = providers::settings::list_configured(base_dir);

    let entries: Vec<KeyEntry> = configured
        .iter()
        .map(|s| {
            let provider = providers::get_provider(&s.provider_id);
            KeyEntry {
                provider_id: s.provider_id.clone(),
                name: provider.map(|p| p.name).unwrap_or(&s.provider_id).to_string(),
                fingerprint: s.key_fingerprint(),
                model: s.get_model().unwrap_or("(default)").to_string(),
                file: providers::settings::settings_path(base_dir, &s.provider_id)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(unknown)".into()),
            }
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No provider keys configured.");
        println!();
        println!("Run `csq setkey mm --key <KEY>` to add a MiniMax key, for example.");
        return Ok(());
    }

    println!();
    println!("Configured provider keys:");
    println!();

    for e in &entries {
        println!("  {} ({})", e.name, e.provider_id);
        println!("    Key:    {}", e.fingerprint);
        println!("    Model:  {}", e.model);
        println!("    File:   {}", e.file);
        println!();
    }

    Ok(())
}
