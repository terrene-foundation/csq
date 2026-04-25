//! `csq models list [provider]` — list models. `csq models switch <provider> <model>` — switch.

use anyhow::{anyhow, Result};
use csq_core::providers::catalog::ModelConfigTarget;
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

pub fn handle_switch(
    base_dir: &Path,
    provider_id: &str,
    model_query: &str,
    slot: Option<csq_core::types::AccountNum>,
    pull_if_missing: bool,
    force: bool,
) -> Result<()> {
    let provider = providers::get_provider(provider_id)
        .ok_or_else(|| anyhow!("unknown provider: {provider_id}"))?;

    // Resolve the target model id. Three strategies by provider:
    //
    // - **Ollama** — the "catalog" is whatever the user has pulled
    //   locally. Accept any non-empty id verbatim; when
    //   `pull_if_missing` is set, fetch via `ollama pull`.
    // - **Codex** — FR-CLI-04: the Codex default ships in the
    //   catalog, but users can switch to any gpt-*/o*/codex-* model
    //   OpenAI exposes on their subscription. Accept catalog
    //   matches silently; accept non-catalog ids ONLY when `--force`
    //   is set, because uncached models risk shipping a model id
    //   the user's plan doesn't accept.
    // - **Keyed providers (Claude / MiniMax / Z.AI)** — keep the
    //   curated catalog so a typo can't brick the slot.
    let model_id: String = if provider_id == "ollama" {
        let trimmed = model_query.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("model id must not be empty"));
        }
        if pull_if_missing {
            ensure_ollama_model_pulled(trimmed)?;
        }
        trimmed.to_string()
    } else if provider_id == "codex" {
        resolve_codex_model(model_query, force)?
    } else {
        let catalog = ModelCatalog::default_catalog();
        let m = catalog.find(model_query).ok_or_else(|| {
            let suggestion = catalog
                .suggest(model_query)
                .map(|m| format!(" (did you mean {}?)", m.id))
                .unwrap_or_default();
            anyhow!("unknown model: {model_query}{suggestion}")
        })?;
        if m.provider != provider_id {
            return Err(anyhow!(
                "model {} belongs to provider {}, not {}",
                m.id,
                m.provider,
                provider_id
            ));
        }
        m.id.clone()
    };

    // INV-P06 write-path dispatch by `ModelConfigTarget`.
    //
    // - EnvInSettingsJson → `config-<N>/settings.json` `env.ANTHROPIC_MODEL`
    //   (and all MODEL_KEYS siblings), or the global profile when no slot.
    // - TomlModelKey → `config-<N>/config.toml` `model = "..."` via
    //   `providers::codex::surface::write_config_toml`. No global
    //   profile path for Codex — the model is a per-slot config.toml
    //   concept and the provider has no settings-codex.json file.
    match provider.model_config {
        ModelConfigTarget::EnvInSettingsJson => {
            if let Some(slot_num) = slot {
                write_slot_model(base_dir, slot_num, &model_id)?;
                println!(
                    "Switched {} model on slot {} to {}",
                    provider_id, slot_num, model_id
                );
            } else {
                let mut settings = providers::settings::load_settings(base_dir, provider_id)?;
                settings.set_model(&model_id);
                providers::settings::save_settings(base_dir, &settings)?;
                let display_name = ModelCatalog::default_catalog()
                    .find(&model_id)
                    .map(|m| format!(" ({})", m.name))
                    .unwrap_or_default();
                println!(
                    "Switched {} model to {}{}",
                    provider_id, model_id, display_name
                );
            }
        }
        ModelConfigTarget::TomlModelKey => {
            let slot_num = slot.ok_or_else(|| {
                anyhow!(
                    "--slot is required for {provider_id} — model lives in \
                     config-<slot>/config.toml, there is no global profile"
                )
            })?;
            providers::codex::surface::write_config_toml(base_dir, slot_num, &model_id)
                .map_err(|e| anyhow!("failed to write config.toml for slot {slot_num}: {e}"))?;
            println!(
                "Switched {} model on slot {} to {}",
                provider_id, slot_num, model_id
            );
        }
        ModelConfigTarget::GeminiSettingsModelName => {
            // PR-G1 stub: the Gemini model writer lands in PR-G4
            // (csq-cli surface dispatch). Refuse with a clear error
            // so a user who runs `csq models switch gemini-2.5-pro`
            // before PR-G4 ships gets an actionable message instead
            // of silent no-op or a panic.
            return Err(anyhow!(
                "{provider_id} model switching requires PR-G4 (csq-cli Gemini surface dispatch); \
                 not yet implemented in this build"
            ));
        }
    }

    Ok(())
}

/// Resolves a user-supplied Codex model query to a concrete model id.
///
/// Catalog match wins; otherwise `--force` must be set to accept an
/// arbitrary OpenAI model id. Empty input is always rejected. This
/// mirrors the Ollama "user space" model for catalog-less providers
/// while keeping the default path (catalog hit) typo-resistant.
fn resolve_codex_model(query: &str, force: bool) -> Result<String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("model id must not be empty"));
    }

    // Catalog hit is the happy path for csq-curated models.
    let catalog = ModelCatalog::default_catalog();
    if let Some(m) = catalog.find(trimmed) {
        if m.provider == "codex" {
            return Ok(m.id.clone());
        }
    }

    // Also accept the provider's own `default_model` literal — it's
    // always a valid Codex id even if ModelCatalog hasn't enumerated it.
    if let Some(p) = providers::get_provider("codex") {
        if trimmed == p.default_model {
            return Ok(trimmed.to_string());
        }
    }

    if force {
        return Ok(trimmed.to_string());
    }

    Err(anyhow!(
        "uncached codex model `{trimmed}` — pass `--force` to accept an \
         arbitrary OpenAI model id (csq does not validate it against your \
         ChatGPT subscription entitlements)"
    ))
}

/// Rewrites every `ANTHROPIC_*_MODEL` key in
/// `<base_dir>/config-<slot>/settings.json` to `model_id`, atomic
/// temp-file + rename via the shared platform helpers. The file
/// must already exist (slot must be bound via `csq setkey` first).
fn write_slot_model(
    base_dir: &Path,
    slot: csq_core::types::AccountNum,
    model_id: &str,
) -> Result<()> {
    use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
    use csq_core::session::merge::MODEL_KEYS;
    use serde_json::Value;

    let settings_path = base_dir
        .join(format!("config-{}", slot))
        .join("settings.json");
    let content = std::fs::read_to_string(&settings_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!("slot {slot} is not bound — run `csq setkey <provider> --slot {slot}` first")
        } else {
            anyhow!("read {}: {e}", settings_path.display())
        }
    })?;
    let mut value: Value = serde_json::from_str(&content)
        .map_err(|e| anyhow!("{} is not valid JSON: {e}", settings_path.display()))?;

    let env = value
        .as_object_mut()
        .and_then(|o| o.get_mut("env"))
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            anyhow!(
                "{} has no `env` object — can't set model",
                settings_path.display()
            )
        })?;
    for key in MODEL_KEYS {
        env.insert((*key).to_string(), Value::String(model_id.to_string()));
    }

    let json = serde_json::to_string_pretty(&value)?;
    let tmp = unique_tmp_path(&settings_path);
    std::fs::write(&tmp, json.as_bytes())?;
    // Slot settings.json may carry an ANTHROPIC_AUTH_TOKEN — match
    // the bind/unbind paths and secure the file before publish.
    secure_file(&tmp).map_err(|e| anyhow!("secure_file: {e}"))?;
    atomic_replace(&tmp, &settings_path).map_err(|e| anyhow!("atomic replace: {e}"))?;
    Ok(())
}

/// Ensures `model` is in the output of `ollama list`. If missing,
/// runs `ollama pull <model>` with inherited stdio so the user
/// sees the pull progress in the terminal.
///
/// Returns `Ok(())` when the model is (or becomes) locally available.
/// Returns `Err` when:
///   - `ollama` is not installed (exec failure)
///   - the pull command exits non-zero
///
/// No network fetch happens when the model is already present.
/// Pure function: given a user's requested model id and the
/// locally-installed list, decide whether we need to pull.
///
/// - Exact match → already present.
/// - Query has no `:tag` AND any installed model's bare name
///   matches the query → already present (user typed `gemma4`,
///   we have `gemma4:latest`).
/// - Query has a `:tag` → require exact match. A user asking
///   for `gemma4:13b` must get `gemma4:13b`; `gemma4:4b`
///   installed does NOT satisfy it (different weights, CC
///   would fail at inference time).
pub(crate) fn model_is_installed(query: &str, installed: &[String]) -> bool {
    if installed.iter().any(|m| m == query) {
        return true;
    }
    if !query.contains(':') {
        return installed.iter().any(|m| {
            let m_bare = m.split(':').next().unwrap_or(m);
            m_bare == query
        });
    }
    false
}

fn ensure_ollama_model_pulled(model: &str) -> Result<()> {
    use std::process::Command;

    // Pre-check the ollama binary exists before invoking it
    // indirectly. Fails with an actionable message instead of
    // the confusing "No such file or directory" surfaced by a
    // plain `Command::status()` on a missing binary.
    if Command::new("ollama")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return Err(anyhow!(
            "ollama is not installed. Install from https://ollama.com \
             (or pass `--pull-if-missing=false` to skip the fetch)"
        ));
    }

    let installed = csq_core::providers::ollama::get_ollama_models();
    if model_is_installed(model, &installed) {
        return Ok(());
    }

    eprintln!("Model {model} not found locally — running `ollama pull {model}`...");
    let status = Command::new("ollama")
        .arg("pull")
        .arg(model)
        .status()
        .map_err(|e| {
            anyhow!("failed to run `ollama pull`: {e}. Is Ollama installed and on PATH?")
        })?;
    if !status.success() {
        return Err(anyhow!(
            "`ollama pull {model}` exited with {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

// Kept for backward compat with the old single-arg CLI entry
#[allow(dead_code)]
pub fn handle(base_dir: &Path, provider_filter: &str) -> Result<()> {
    handle_list(base_dir, provider_filter, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::accounts::third_party::bind_provider_to_slot;
    use csq_core::types::AccountNum;
    use serde_json::Value;
    use tempfile::TempDir;

    // ── Ollama-specific paths ───────────────────────────────

    #[test]
    fn switch_ollama_global_accepts_any_model_id() {
        // Pre-alpha.21, passing a non-catalog model id to the
        // global ollama profile (e.g. a user-pulled `qwen3:latest`)
        // failed with "unknown model". Now it must succeed since
        // the Ollama model space is user-defined.
        let dir = TempDir::new().unwrap();
        // `pull_if_missing = false` so the test never calls the
        // `ollama` binary (may not exist on CI).
        handle_switch(dir.path(), "ollama", "qwen3:latest", None, false, false).unwrap();

        let path = dir.path().join("settings-ollama.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v.pointer("/env/ANTHROPIC_MODEL").and_then(|x| x.as_str()),
            Some("qwen3:latest")
        );
    }

    #[test]
    fn switch_ollama_slot_writes_config_dir_not_global() {
        // Slot-bound ollama: model must land in
        // `config-N/settings.json`, NOT in the global profile.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();
        bind_provider_to_slot(dir.path(), "ollama", slot, None, None).unwrap();

        handle_switch(
            dir.path(),
            "ollama",
            "gpt-oss:20b",
            Some(slot),
            false,
            false,
        )
        .unwrap();

        // Slot's settings.json carries the new model across every
        // MODEL_KEYS entry.
        let slot_path = dir.path().join("config-5/settings.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&slot_path).unwrap()).unwrap();
        for key in csq_core::session::merge::MODEL_KEYS {
            assert_eq!(
                v.pointer(&format!("/env/{}", key)).and_then(|x| x.as_str()),
                Some("gpt-oss:20b"),
                "{key} should reflect the switched model"
            );
        }
        // Global profile must NOT have been touched.
        let global = dir.path().join("settings-ollama.json");
        assert!(
            !global.exists(),
            "slot switch must not touch the global profile"
        );
    }

    #[test]
    fn switch_ollama_slot_errors_when_not_bound() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();
        let err = handle_switch(dir.path(), "ollama", "gemma4", Some(slot), false, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not bound"), "got: {err}");
    }

    #[test]
    fn switch_ollama_empty_model_rejected() {
        let dir = TempDir::new().unwrap();
        let err = handle_switch(dir.path(), "ollama", "   ", None, false, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    // ── Keyed provider paths (catalog still enforced) ───────

    #[test]
    fn switch_claude_still_uses_catalog() {
        let dir = TempDir::new().unwrap();
        handle_switch(dir.path(), "claude", "opus", None, false, false).unwrap();

        let path = dir.path().join("settings.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let model = v
            .pointer("/env/ANTHROPIC_MODEL")
            .and_then(|x| x.as_str())
            .unwrap();
        assert!(model.starts_with("claude-opus-4-"), "got: {model}");
    }

    #[test]
    fn switch_claude_rejects_unknown_model() {
        let dir = TempDir::new().unwrap();
        let err = handle_switch(
            dir.path(),
            "claude",
            "nonexistent-model",
            None,
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown model"), "got: {err}");
    }

    // ── model_is_installed (bare-name vs tagged match) ──────

    #[test]
    fn model_is_installed_exact_match() {
        let installed = vec!["gemma4:latest".to_string(), "llama3:8b".to_string()];
        assert!(model_is_installed("gemma4:latest", &installed));
        assert!(model_is_installed("llama3:8b", &installed));
    }

    #[test]
    fn model_is_installed_bare_name_matches_latest_tag() {
        // User types `gemma4` — should match installed `gemma4:latest`.
        let installed = vec!["gemma4:latest".to_string()];
        assert!(model_is_installed("gemma4", &installed));
    }

    #[test]
    fn model_is_installed_bare_name_matches_any_tag() {
        // `gemma4:4b` installed, user asks for `gemma4` (bare).
        // Bare-name match accepts any tag of the same family.
        let installed = vec!["gemma4:4b".to_string()];
        assert!(model_is_installed("gemma4", &installed));
    }

    #[test]
    fn model_is_installed_tagged_query_requires_exact_match() {
        // H3 regression: user asks for `gemma4:13b` but only
        // `gemma4:4b` is installed. Must NOT treat as present —
        // different weights, CC would fail at inference.
        let installed = vec!["gemma4:4b".to_string()];
        assert!(!model_is_installed("gemma4:13b", &installed));
    }

    #[test]
    fn model_is_installed_no_match_when_family_missing() {
        let installed = vec!["llama3:8b".to_string()];
        assert!(!model_is_installed("gemma4", &installed));
        assert!(!model_is_installed("gemma4:latest", &installed));
    }

    #[test]
    fn model_is_installed_empty_list() {
        let installed: Vec<String> = Vec::new();
        assert!(!model_is_installed("anything", &installed));
    }

    #[test]
    fn switch_keyed_slot_retargets_config_dir() {
        // MM slot switch — same slot semantics as Ollama slot
        // switch, but the catalog lookup still fires because
        // MM's model space is curated.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None).unwrap();

        handle_switch(dir.path(), "mm", "m2", Some(slot), false, false).unwrap();

        let slot_path = dir.path().join("config-7/settings.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&slot_path).unwrap()).unwrap();
        let model = v
            .pointer("/env/ANTHROPIC_MODEL")
            .and_then(|x| x.as_str())
            .unwrap();
        assert!(
            model.contains("MiniMax"),
            "alias `m2` should resolve to the catalog's MiniMax id, got: {model}"
        );
    }

    // ── PR-C7 Codex TomlModelKey dispatch ──────────────────

    #[test]
    fn switch_codex_default_model_writes_config_toml_on_slot() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(4u16).unwrap();
        std::fs::create_dir_all(dir.path().join(format!("config-{slot}"))).unwrap();
        let default = csq_core::providers::get_provider("codex")
            .unwrap()
            .default_model;
        handle_switch(dir.path(), "codex", default, Some(slot), false, false).unwrap();

        let toml =
            std::fs::read_to_string(dir.path().join(format!("config-{slot}/config.toml"))).unwrap();
        assert!(
            toml.contains(&format!("model = \"{default}\"")),
            "expected model line for {default}, got: {toml}"
        );
        assert!(
            toml.contains("cli_auth_credentials_store = \"file\""),
            "expected cli_auth_credentials_store directive, got: {toml}"
        );
    }

    #[test]
    fn switch_codex_arbitrary_model_requires_force() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();
        std::fs::create_dir_all(dir.path().join(format!("config-{slot}"))).unwrap();

        let err = handle_switch(
            dir.path(),
            "codex",
            "gpt-5-turbo-ultra-plus",
            Some(slot),
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--force"), "got: {err}");
        assert!(err.contains("uncached"), "got: {err}");
    }

    #[test]
    fn switch_codex_arbitrary_model_accepted_with_force() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();
        std::fs::create_dir_all(dir.path().join(format!("config-{slot}"))).unwrap();

        handle_switch(
            dir.path(),
            "codex",
            "gpt-5-turbo-ultra-plus",
            Some(slot),
            false,
            true,
        )
        .unwrap();

        let toml =
            std::fs::read_to_string(dir.path().join(format!("config-{slot}/config.toml"))).unwrap();
        assert!(
            toml.contains("model = \"gpt-5-turbo-ultra-plus\""),
            "got: {toml}"
        );
    }

    #[test]
    fn switch_codex_requires_slot() {
        let dir = TempDir::new().unwrap();
        let default = csq_core::providers::get_provider("codex")
            .unwrap()
            .default_model;
        let err = handle_switch(dir.path(), "codex", default, None, false, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--slot is required"), "got: {err}");
    }

    #[test]
    fn switch_codex_empty_model_rejected() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(8u16).unwrap();
        std::fs::create_dir_all(dir.path().join(format!("config-{slot}"))).unwrap();
        let err = handle_switch(dir.path(), "codex", "   ", Some(slot), false, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn switch_codex_rewrite_preserves_auth_store_directive() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();
        std::fs::create_dir_all(dir.path().join(format!("config-{slot}"))).unwrap();

        let default = csq_core::providers::get_provider("codex")
            .unwrap()
            .default_model;
        handle_switch(dir.path(), "codex", default, Some(slot), false, false).unwrap();
        handle_switch(
            dir.path(),
            "codex",
            "gpt-6-preview",
            Some(slot),
            false,
            true,
        )
        .unwrap();

        let toml =
            std::fs::read_to_string(dir.path().join(format!("config-{slot}/config.toml"))).unwrap();
        assert!(
            toml.contains("cli_auth_credentials_store = \"file\""),
            "got: {toml}"
        );
        assert!(toml.contains("model = \"gpt-6-preview\""), "got: {toml}");
    }
}
