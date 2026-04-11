//! `csq models list [provider]` — list models. `csq models switch <provider> <model>` — switch.

use anyhow::{anyhow, Result};
use csq_core::providers::{self, ModelCatalog};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct ModelEntry {
    provider_id: String,
    provider_name: String,
    model_id: String,
    model_name: String,
}

pub fn handle_list(_base_dir: &Path, provider_filter: &str, json: bool) -> Result<()> {
    let catalog = ModelCatalog::default_catalog();

    if json {
        let mut entries = Vec::new();
        let providers_list: Vec<_> = if provider_filter == "all" {
            providers::PROVIDERS.iter().collect()
        } else {
            let p = providers::get_provider(provider_filter)
                .ok_or_else(|| anyhow!("unknown provider: {provider_filter}"))?;
            vec![p]
        };

        for provider in providers_list {
            for m in catalog.by_provider(provider.id) {
                entries.push(ModelEntry {
                    provider_id: provider.id.to_string(),
                    provider_name: provider.name.to_string(),
                    model_id: m.id.to_string(),
                    model_name: m.name.to_string(),
                });
            }
            if provider.id == "ollama" {
                for name in providers::ollama::get_ollama_models() {
                    entries.push(ModelEntry {
                        provider_id: "ollama".into(),
                        provider_name: "Ollama".into(),
                        model_id: name.clone(),
                        model_name: name,
                    });
                }
            }
        }

        println!("{}", serde_json::to_string(&entries)?);
        return Ok(());
    }

    println!();

    if provider_filter == "all" {
        for provider in providers::PROVIDERS {
            let models: Vec<_> = catalog.by_provider(provider.id).into_iter().collect();
            if models.is_empty() && provider.id != "ollama" {
                continue;
            }
            println!("{} ({})", provider.name, provider.id);
            for m in &models {
                println!("  {} — {}", m.id, m.name);
            }
            if provider.id == "ollama" {
                let live = providers::ollama::get_ollama_models();
                if live.is_empty() && models.is_empty() {
                    println!("  (ollama not installed or no models)");
                } else {
                    for name in &live {
                        println!("  {name}");
                    }
                }
            }
            println!();
        }
    } else {
        let provider = providers::get_provider(provider_filter)
            .ok_or_else(|| anyhow!("unknown provider: {provider_filter}"))?;

        println!("{} ({})", provider.name, provider.id);
        let models = catalog.by_provider(provider.id);
        for m in &models {
            println!("  {} — {}", m.id, m.name);
        }
        if provider.id == "ollama" {
            for name in providers::ollama::get_ollama_models() {
                println!("  {name}");
            }
        }
        println!();
    }

    Ok(())
}

pub fn handle_switch(base_dir: &Path, provider_id: &str, model_query: &str) -> Result<()> {
    // Verify provider exists
    providers::get_provider(provider_id)
        .ok_or_else(|| anyhow!("unknown provider: {provider_id}"))?;

    // Resolve model
    let catalog = ModelCatalog::default_catalog();
    let model = catalog.find(model_query).ok_or_else(|| {
        let suggestion = catalog
            .suggest(model_query)
            .map(|m| format!(" (did you mean {}?)", m.id))
            .unwrap_or_default();
        anyhow!("unknown model: {model_query}{suggestion}")
    })?;

    if model.provider != provider_id {
        return Err(anyhow!(
            "model {} belongs to provider {}, not {}",
            model.id, model.provider, provider_id
        ));
    }

    // Load, update, save
    let mut settings = providers::settings::load_settings(base_dir, provider_id)?;
    settings.set_model(&model.id);
    providers::settings::save_settings(base_dir, &settings)?;

    println!(
        "Switched {} model to {} ({})",
        provider_id, model.id, model.name
    );
    Ok(())
}

// Kept for backward compat with the old single-arg CLI entry
#[allow(dead_code)]
pub fn handle(base_dir: &Path, provider_filter: &str) -> Result<()> {
    handle_list(base_dir, provider_filter, false)
}
