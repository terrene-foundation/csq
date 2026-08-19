//! `csq models list [provider]` — list models. `csq models switch <provider> <model>` — switch.
//!
//! `--json` drives coverage from [`csq_core::providers::registry`] — THE canonical
//! union of the wrapped-provider catalog and the native-CLI table — so every id
//! `registry::known_ids()` reports is listable, not just the subset that happens
//! to carry curated [`ModelCatalog`] rows. Dispatch keys off
//! [`ProviderDescriptor::kind`] (`Wrapped` vs `Native`), never a per-id `if
//! provider_id == "grok"` chain: a native descriptor has no catalog entries by
//! construction, so it always reports its `default_model`; a wrapped descriptor
//! (Codex today) with zero catalog rows falls back to the same synthesized-default
//! row rather than an empty array. Ollama's live-pulled-model enumeration is the
//! one kept id-check — it is a genuine runtime-vs-static distinction, not a
//! provider-identity branch (`agents.md` "PRIMARY METHODOLOGICAL DIRECTIVE").

use anyhow::{anyhow, Result};
use csq_core::providers::catalog::ModelConfigTarget;
use csq_core::providers::registry::{self, ProviderDescriptor};
use csq_core::providers::{self, ModelCatalog, ProviderKind};
use csq_core::sdk::{self, Envelope, SdkError, SdkErrorCode, SCHEMA_MODELS_V1};
use serde::Serialize;
use std::path::Path;

/// One model row. Mirrors [`csq_core::providers::ModelInfo`]'s full shape
/// (`context_window` / `output_limit` / `aliases`, previously dropped by the
/// old id/name-only `ModelEntry`) plus the provider identity and
/// [`Self::is_default`].
#[derive(Debug, Serialize)]
struct ModelEntry {
    provider_id: String,
    provider_name: String,
    model_id: String,
    model_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_limit: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
    /// `true` iff this row is NOT a curated [`ModelCatalog`] entry — it is the
    /// provider's [`ProviderDescriptor::default_model`], synthesized because no
    /// catalog rows exist for this provider (every native vendor CLI; a wrapped
    /// provider like Codex whose model space csq does not curate). A host
    /// building a model picker uses this to distinguish "csq vouches for this
    /// row's specs" from "this is just the provider's current default, no
    /// context/output data available."
    is_default: bool,
}

/// The `csq.models.v1` success payload.
#[derive(Serialize)]
struct ModelsPayload {
    models: Vec<ModelEntry>,
}

/// A row synthesized from `d.default_model` — never a bare-empty substitute.
/// `default_model` is empty only for a native descriptor whose vendor CLI picks
/// its own model with no fixed csq-visible default (doc'd on
/// [`csq_core::providers::native::NativeCli::default_model`]); that case still
/// reports one row with an explicit "vendor-selected" placeholder rather than
/// silently contributing zero entries.
fn default_entry(d: &ProviderDescriptor) -> ModelEntry {
    let (model_id, model_name) = if d.default_model.is_empty() {
        (
            "(vendor-selected)".to_string(),
            format!("{} picks its model automatically", d.name),
        )
    } else {
        (d.default_model.to_string(), d.default_model.to_string())
    };
    ModelEntry {
        provider_id: d.id.to_string(),
        provider_name: d.name.to_string(),
        model_id,
        model_name,
        context_window: None,
        output_limit: None,
        aliases: Vec::new(),
        is_default: true,
    }
}

/// This provider's curated [`ModelCatalog`] rows, mapped to [`ModelEntry`].
fn catalog_entries(d: &ProviderDescriptor, catalog: &ModelCatalog) -> Vec<ModelEntry> {
    catalog
        .by_provider(d.id)
        .into_iter()
        .map(|m| ModelEntry {
            provider_id: d.id.to_string(),
            provider_name: d.name.to_string(),
            model_id: m.id.clone(),
            model_name: m.name.clone(),
            context_window: m.context_window,
            output_limit: m.output_limit,
            aliases: m.aliases.clone(),
            is_default: false,
        })
        .collect()
}

/// Ollama's model space is whatever the user has pulled locally — queried live,
/// never curated. Kept as an explicit id check (not a `kind` branch): this is a
/// runtime-vs-static distinction orthogonal to wrapped/native classification.
fn ollama_live_entries(d: &ProviderDescriptor) -> Vec<ModelEntry> {
    providers::ollama::get_ollama_models()
        .into_iter()
        .map(|name| ModelEntry {
            provider_id: d.id.to_string(),
            provider_name: d.name.to_string(),
            model_id: name.clone(),
            model_name: name,
            context_window: None,
            output_limit: None,
            aliases: Vec::new(),
            is_default: false,
        })
        .collect()
}

/// Every listable row for one provider. Dispatch is on [`ProviderDescriptor::kind`]:
/// a [`ProviderKind::Native`] descriptor has no [`ModelCatalog`] rows by
/// construction (the catalog only covers `catalog::PROVIDERS` ids), so it always
/// reports [`default_entry`]. A [`ProviderKind::Wrapped`] descriptor reports its
/// catalog rows (plus Ollama's live rows); if that combined set is empty — Codex
/// today, whose model space csq does not curate — it falls back to
/// [`default_entry`] rather than an empty array.
fn entries_for(d: &ProviderDescriptor, catalog: &ModelCatalog) -> Vec<ModelEntry> {
    match d.kind {
        ProviderKind::Native => vec![default_entry(d)],
        ProviderKind::Wrapped => {
            let mut entries = catalog_entries(d, catalog);
            if d.id == "ollama" {
                entries.extend(ollama_live_entries(d));
            }
            if entries.is_empty() {
                entries.push(default_entry(d));
            }
            entries
        }
    }
}

/// The fallible core of the `--json` path: resolve `provider_filter` against
/// [`registry`] and build every listable row. Returns [`SdkError`] (never bails
/// via `anyhow`) so the caller can wrap it directly in a failure envelope — the
/// same shape as `exec::run_exec`. Split out from [`handle_list`] so it can be
/// unit-tested without going through [`sdk::emit`] + `std::process::exit`.
fn list_models_json(
    provider_filter: &str,
    catalog: &ModelCatalog,
) -> Result<Vec<ModelEntry>, SdkError> {
    let descriptors: Vec<ProviderDescriptor> = if provider_filter == "all" {
        registry::all()
    } else {
        match registry::lookup(provider_filter) {
            Some(d) => vec![d],
            None => {
                let known: Vec<String> = registry::known_ids()
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                return Err(SdkError::trusted(
                    SdkErrorCode::ProviderNotFound,
                    format!("unknown provider: {provider_filter}"),
                )
                .with_known(known));
            }
        }
    };

    Ok(descriptors
        .iter()
        .flat_map(|d| entries_for(d, catalog))
        .collect())
}

pub fn handle_list(_base_dir: &Path, provider_filter: &str, json: bool) -> Result<()> {
    let catalog = ModelCatalog::default_catalog();

    if json {
        let code = match list_models_json(provider_filter, &catalog) {
            Ok(models) => sdk::emit(&Envelope::success(
                SCHEMA_MODELS_V1,
                None,
                ModelsPayload { models },
            ))?,
            Err(err) => sdk::emit(&Envelope::<ModelsPayload>::failure(
                SCHEMA_MODELS_V1,
                None,
                err,
            ))?,
        };
        std::process::exit(code);
    }

    println!();

    let descriptors: Vec<ProviderDescriptor> = if provider_filter == "all" {
        registry::all()
    } else {
        vec![registry::lookup(provider_filter)
            .ok_or_else(|| anyhow!("unknown provider: {provider_filter}"))?]
    };

    for d in &descriptors {
        let models = entries_for(d, &catalog);
        if provider_filter == "all" && models.is_empty() {
            continue;
        }
        println!("{} ({})", d.name, d.id);
        for m in &models {
            if m.is_default {
                println!("  {} — {} (default)", m.model_id, m.model_name);
            } else {
                println!("  {} — {}", m.model_id, m.model_name);
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
    } else if provider_id == "gemini" && model_query.trim().eq_ignore_ascii_case("auto") {
        // FR-G-CLI-04 special: `auto` is intentionally NOT in the
        // catalog (it instructs gemini-cli to pick rather than
        // pinning). Short-circuit before the catalog lookup so the
        // suggestion fallback ("did you mean claude-opus...") does
        // not surface a misleading rejection.
        "auto".to_string()
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
            // Explicit user choice → `Some`: written as the per-slot `model`
            // key (takes precedence over any user-global `model`, preserved
            // across launch re-merges). This is the ONLY path that writes a
            // model; login/spawn/reconciler pass `None`.
            providers::codex::surface::write_config_toml(base_dir, slot_num, Some(&model_id))
                .map_err(|e| anyhow!("failed to write config.toml for slot {slot_num}: {e}"))?;
            println!(
                "Switched {} model on slot {} to {}",
                provider_id, slot_num, model_id
            );
        }
        ModelConfigTarget::GeminiSettingsModelName => {
            // FR-G-CLI-04: Gemini model lives in `binding.model_name`
            // inside `credentials/gemini-<N>.json`. The settings
            // reassertion writer (`reassert_settings_drift`) writes
            // it into `<handle_dir>/.gemini/settings.json` on every
            // spawn, so the next `csq run <slot>` picks up the new
            // model with no extra glue.
            let slot_num = slot.ok_or_else(|| {
                anyhow!(
                    "--slot is required for {provider_id} — model lives \
                     in the per-slot binding marker, there is no global profile"
                )
            })?;
            // Resolve `auto` first (not in catalog); for everything
            // else the catalog hit above already pinned the
            // canonical `gemini-*` id. Validate that the resolved
            // id is a Gemini model.
            let resolved = resolve_gemini_model(model_query, &model_id)?;
            write_gemini_model_to_binding(base_dir, slot_num, &resolved)?;
            if resolved.ends_with("-preview") {
                eprintln!(
                    "warning: preview tier may silently downgrade — csq will flag the actual served model after the first call"
                );
            }
            println!(
                "Switched {} model on slot {} to {}",
                provider_id, slot_num, resolved
            );
        }
    }

    Ok(())
}

/// Resolves a Gemini model query to a concrete model id (or the
/// literal `"auto"`). The catalog has already been consulted by
/// the caller for non-`auto` ids; this helper just adds the
/// `auto` literal which is intentionally NOT in the catalog
/// (it instructs gemini-cli to pick rather than pinning).
///
/// Returns the resolved id (one of: `auto`, `gemini-2.5-pro`,
/// `gemini-2.5-flash`, `gemini-2.5-flash-lite`,
/// `gemini-3-pro-preview`). Refuses anything else.
fn resolve_gemini_model(query: &str, catalog_resolved: &str) -> Result<String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("model id must not be empty"));
    }
    if trimmed.eq_ignore_ascii_case("auto") {
        return Ok("auto".to_string());
    }
    // Catalog already produced a canonical id (catalog `find` is
    // case-insensitive). Pin the gemini-* prefix so a non-gemini
    // model id passed in does not slip through the GeminiSettings
    // dispatch path.
    if !catalog_resolved.starts_with("gemini-") {
        return Err(anyhow!(
            "`{trimmed}` does not resolve to a Gemini model — supported: \
             auto, pro, flash, flash-lite, 3-pro-preview, or a concrete \
             `gemini-*` id"
        ));
    }
    Ok(catalog_resolved.to_string())
}

/// Atomically updates `model_name` inside the slot's Gemini
/// binding marker. The drift detector picks up the new value on
/// the next `csq run <slot>` spawn.
fn write_gemini_model_to_binding(
    base_dir: &Path,
    slot: csq_core::types::AccountNum,
    model: &str,
) -> Result<()> {
    use csq_core::providers::gemini::provisioning::{set_model_name, ProvisionError};
    set_model_name(base_dir, slot, model).map_err(|e| {
        // `read_binding` inside `set_model_name` returns `ProvisionError::Io`
        // with `ErrorKind::NotFound` when the marker is absent — translate to
        // the actionable "run setkey first" message. All other errors (write
        // failures, malformed marker) map to the generic update failure.
        match &e {
            ProvisionError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                anyhow!(
                    "slot {slot} has no Gemini binding — run `csq setkey gemini --slot {slot}` (API key / Vertex SA) or `csq login {slot} --provider gemini` (Code Assist OAuth) first ({})",
                    e.error_kind_tag()
                )
            }
            _ => anyhow!("failed to update Gemini binding for slot {slot}: {e}"),
        }
    })
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

/// Rewrites every `ANTHROPIC_*_MODEL` key in the slot's settings.json to
/// `model_id`, atomic temp-file + rename via the shared platform helpers.
/// The file must already exist (slot must be bound via `csq setkey` first).
/// M2-7: thin wrapper over the shared UUID-routing chokepoint in csq-core.
///
/// Both CLI and desktop use `csq_core::session::write_slot_model_with_uuid_routing`
/// so the UUID resolution logic has a single source of truth.
/// See `csq-core/src/session/settings.rs` for the implementation and
/// `internal-design-docs § M2-7`.
fn write_slot_model(
    base_dir: &Path,
    slot: csq_core::types::AccountNum,
    model_id: &str,
) -> Result<()> {
    csq_core::session::write_slot_model_with_uuid_routing(base_dir, slot, model_id)
        .map_err(|e| anyhow::anyhow!("{e}"))
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

    // ── JSON registry-union coverage (GH an internal ticket, closes an internal ticket) ──────────

    /// The regression this module was built to fix: `csq models list --json
    /// grok` used to fail `Error: unknown provider: grok` (rc=1) — `grok` is
    /// native-only and absent from `catalog::PROVIDERS`. It must now resolve
    /// and report a default row.
    #[test]
    fn json_list_grok_resolves_and_returns_default_entry() {
        let catalog = ModelCatalog::default_catalog();
        let entries = list_models_json("grok", &catalog).expect("grok must resolve");
        assert_eq!(
            entries.len(),
            1,
            "grok has no catalog rows — one default row"
        );
        assert_eq!(entries[0].provider_id, "grok");
        assert_eq!(entries[0].model_id, "grok-4.5");
        assert!(entries[0].is_default, "grok's row is a synthesized default");
        assert!(entries[0].context_window.is_none());
    }

    /// The second regression: `csq models list --json codex` returned a bare
    /// `[]` (rc=0) with no indication why — `ModelCatalog` has zero Codex
    /// rows. It must now report the provider's default model instead of an
    /// empty array.
    #[test]
    fn json_list_codex_is_never_a_bare_empty_array() {
        let catalog = ModelCatalog::default_catalog();
        let entries = list_models_json("codex", &catalog).expect("codex must resolve");
        assert!(!entries.is_empty(), "codex must not report a bare []");
        assert!(
            entries.iter().all(|e| e.is_default),
            "every codex row is a synthesized default (no curated catalog rows)"
        );
        assert_eq!(entries[0].provider_id, "codex");
    }

    /// The third regression: `csq models list --json kimi` dropped
    /// `context_window` / `output_limit` / `aliases` — the old `ModelEntry`
    /// carried only id/name pairs. Kimi K3's 1,048,576-token window (and its
    /// `k3` alias) must survive into the JSON row.
    #[test]
    fn json_list_kimi_preserves_context_window_output_limit_and_aliases() {
        let catalog = ModelCatalog::default_catalog();
        let entries = list_models_json("kimi", &catalog).expect("kimi must resolve");
        let k3 = entries
            .iter()
            .find(|e| e.model_id == "kimi-k3[1m]")
            .expect("kimi-k3[1m] row present");
        assert_eq!(k3.context_window, Some(1_048_576));
        assert_eq!(k3.output_limit, Some(8_192));
        assert!(k3.aliases.contains(&"k3".to_string()));
        assert!(
            !k3.is_default,
            "a genuine catalog row, not a synthesized default"
        );
    }

    /// Every id `registry::known_ids()` reports MUST be listable — asserted
    /// over the WHOLE set, not a sample (`autonomous-execution.md`
    /// "sampling" is not this rule, but the spirit applies: a partial check
    /// would have missed exactly the grok/codex gaps this module fixes).
    #[test]
    fn json_list_all_covers_every_known_id() {
        let catalog = ModelCatalog::default_catalog();
        let entries = list_models_json("all", &catalog).expect("`all` never fails");
        let covered: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.provider_id.as_str()).collect();
        for id in registry::known_ids() {
            assert!(
                covered.contains(id),
                "provider `{id}` from registry::known_ids() has no row in `models list --json all`"
            );
        }
    }

    /// An unknown `--json` provider filter must return a typed
    /// `provider_not_found` error carrying the full known-id set — never a
    /// bare `anyhow!` string (the pre-fix behavior).
    #[test]
    fn json_list_unknown_provider_returns_typed_error_with_known_ids() {
        let catalog = ModelCatalog::default_catalog();
        let err =
            list_models_json("nosuchprovider", &catalog).expect_err("bogus id must not resolve");
        assert_eq!(err.code, SdkErrorCode::ProviderNotFound);
        let known = err.known.expect("known ids must be attached");
        assert!(known.contains(&"grok".to_string()));
        assert!(known.contains(&"claude".to_string()));
        assert!(known.contains(&"codex".to_string()));
    }

    /// Dispatch is keyed off `ProviderDescriptor::kind`, not a per-id string
    /// chain: EVERY native descriptor (not just grok) reports a
    /// default-marked row with no catalog lookup, driven purely by `kind ==
    /// ProviderKind::Native`.
    #[test]
    fn entries_for_dispatches_every_native_descriptor_by_kind_not_id() {
        let catalog = ModelCatalog::default_catalog();
        for d in registry::all() {
            if d.kind != ProviderKind::Native {
                continue;
            }
            let entries = entries_for(&d, &catalog);
            assert_eq!(
                entries.len(),
                1,
                "{}: native providers report exactly one row",
                d.id
            );
            assert!(
                entries[0].is_default,
                "{}: native row is a default row",
                d.id
            );
        }
    }

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

        handle_switch(dir.path(), "mm", "m3", Some(slot), false, false).unwrap();

        let slot_path = dir.path().join("config-7/settings.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&slot_path).unwrap()).unwrap();
        let model = v
            .pointer("/env/ANTHROPIC_MODEL")
            .and_then(|x| x.as_str())
            .unwrap();
        assert!(
            model.contains("MiniMax"),
            "alias `m3` should resolve to the catalog's MiniMax id, got: {model}"
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

    // ── Gemini paths (PR-G4b — FR-G-CLI-04) ───────────────

    /// Provisions a fresh Gemini binding marker so the model-switch
    /// path has something to update. Mirrors what
    /// `csq setkey gemini --slot N` writes (vault entry omitted —
    /// the writer never touches the vault).
    fn provision_gemini_marker(base: &std::path::Path, slot: u16, model: &str) {
        use csq_core::providers::gemini::provisioning::{write_binding, AuthMode, GeminiBinding};
        let n = AccountNum::try_from(slot).unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, model);
        write_binding(base, n, &binding).unwrap();
    }

    fn read_gemini_model(base: &std::path::Path, slot: u16) -> String {
        use csq_core::providers::gemini::provisioning::read_binding;
        let n = AccountNum::try_from(slot).unwrap();
        read_binding(base, n).unwrap().model_name
    }

    /// Switching by alias (`pro`) writes `gemini-2.5-pro` into
    /// the binding marker. Atomic write — verifies the next read
    /// observes the change in full.
    #[test]
    fn switch_gemini_alias_pro_writes_canonical_id_to_marker() {
        let dir = TempDir::new().unwrap();
        provision_gemini_marker(dir.path(), 4, "auto");
        handle_switch(
            dir.path(),
            "gemini",
            "pro",
            Some(AccountNum::try_from(4u16).unwrap()),
            false,
            false,
        )
        .unwrap();
        assert_eq!(read_gemini_model(dir.path(), 4), "gemini-2.5-pro");
    }

    /// `auto` is intentionally NOT in the catalog (it tells gemini-cli
    /// to pick rather than pinning). The model-switch path must accept
    /// it as a literal AND write it verbatim to the binding.
    #[test]
    fn switch_gemini_auto_writes_literal_auto_to_marker() {
        let dir = TempDir::new().unwrap();
        provision_gemini_marker(dir.path(), 4, "gemini-2.5-pro");
        handle_switch(
            dir.path(),
            "gemini",
            "auto",
            Some(AccountNum::try_from(4u16).unwrap()),
            false,
            false,
        )
        .unwrap();
        assert_eq!(read_gemini_model(dir.path(), 4), "auto");
    }

    /// Concrete `gemini-2.5-flash-lite` round-trips through the
    /// catalog and lands in the marker unchanged.
    #[test]
    fn switch_gemini_concrete_flash_lite_writes_to_marker() {
        let dir = TempDir::new().unwrap();
        provision_gemini_marker(dir.path(), 7, "auto");
        handle_switch(
            dir.path(),
            "gemini",
            "gemini-2.5-flash-lite",
            Some(AccountNum::try_from(7u16).unwrap()),
            false,
            false,
        )
        .unwrap();
        assert_eq!(read_gemini_model(dir.path(), 7), "gemini-2.5-flash-lite");
    }

    /// Preview-tier id (`gemini-3-pro-preview`) is accepted; the CLI
    /// surface emits a stderr warning, but the binding marker still
    /// records the request verbatim.
    #[test]
    fn switch_gemini_preview_model_accepted_and_recorded() {
        let dir = TempDir::new().unwrap();
        provision_gemini_marker(dir.path(), 8, "auto");
        handle_switch(
            dir.path(),
            "gemini",
            "3-pro-preview",
            Some(AccountNum::try_from(8u16).unwrap()),
            false,
            false,
        )
        .unwrap();
        assert_eq!(read_gemini_model(dir.path(), 8), "gemini-3-pro-preview");
    }

    /// Unknown model id is refused with a `did you mean` suggestion
    /// (catalog-driven via the existing `suggest` helper).
    #[test]
    fn switch_gemini_unknown_model_rejected() {
        let dir = TempDir::new().unwrap();
        provision_gemini_marker(dir.path(), 4, "auto");
        let err = handle_switch(
            dir.path(),
            "gemini",
            "gemini-9000-overdrive",
            Some(AccountNum::try_from(4u16).unwrap()),
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown model"), "got: {err}");
    }

    /// `--slot` is mandatory for Gemini — no global Gemini profile
    /// exists. Refuse with an actionable error.
    #[test]
    fn switch_gemini_without_slot_refused() {
        let dir = TempDir::new().unwrap();
        let err = handle_switch(dir.path(), "gemini", "pro", None, false, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--slot is required"), "got: {err}");
    }

    /// Slot with no Gemini binding marker refuses cleanly — points
    /// the user at `csq setkey gemini --slot N` instead of writing
    /// a half-bound state.
    #[test]
    fn switch_gemini_unprovisioned_slot_refused() {
        let dir = TempDir::new().unwrap();
        let err = handle_switch(
            dir.path(),
            "gemini",
            "pro",
            Some(AccountNum::try_from(9u16).unwrap()),
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("csq setkey gemini --slot 9"), "got: {err}");
    }

    /// FR-G-CLI-04: marker write is atomic. Concrete check — the
    /// existing marker survives if the writer ever crashed mid-
    /// rename. Simulates the post-condition: the marker file always
    /// has 0o600 permissions and contains the new model.
    #[cfg(unix)]
    #[test]
    fn switch_gemini_marker_remains_0o600_after_update() {
        use csq_core::providers::gemini::provisioning::binding_path;
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        provision_gemini_marker(dir.path(), 4, "auto");
        handle_switch(
            dir.path(),
            "gemini",
            "flash",
            Some(AccountNum::try_from(4u16).unwrap()),
            false,
            false,
        )
        .unwrap();
        let path = binding_path(dir.path(), AccountNum::try_from(4u16).unwrap());
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "marker must stay 0o600 after model switch"
        );
    }

    // ── §5a regression helper (inline; csq-cli cannot reach pub(crate)) ──
    //
    // Mirrors `csq_core::platform::fs::assert_no_tmp_leak_on_readonly_parent`.
    // Origin: security.md §5a, an internal journal entry B2, /redteam round 3 (2026-05-09).
    #[cfg(unix)]
    fn assert_no_tmp_leak_on_readonly_parent_inline<F, E>(dir: &std::path::Path, op: F)
    where
        F: FnOnce() -> Result<(), E>,
        E: std::fmt::Debug,
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = op();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            result.is_err(),
            "op must fail under read-only parent; got Ok"
        );
        let leaked: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
    }

    /// §5a regression — site 9 (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `write_slot_model` fails after
    /// the tmp file would have been created (settings dir read-only →
    /// write fails), no `.tmp.` file must remain.
    ///
    /// The slot's settings.json may carry an ANTHROPIC_AUTH_TOKEN;
    /// partial-failure must not leave it at umask 0o644.
    #[cfg(unix)]
    #[test]
    fn write_slot_model_partial_failure_cleans_tmp_file() {
        // Arrange: bind an Ollama slot so config-N/settings.json exists
        // with the required `env` object.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        bind_provider_to_slot(dir.path(), "ollama", slot, None, None).unwrap();

        // Confirm the happy path works.
        write_slot_model(dir.path(), slot, "llama3.2:latest").unwrap();

        // Act + Assert: read-only config dir → write fails → no tmp leak.
        let config_dir = dir.path().join(format!("config-{}", slot));
        assert_no_tmp_leak_on_readonly_parent_inline(&config_dir, || {
            write_slot_model(dir.path(), slot, "llama3.2:latest")
        });
    }

    // ── M2-7 Phase 2 reader routing ────────────────────────────────────────

    /// M2-7 (Phase 2 READER routing): when `identities/<UUID>/settings.json`
    /// is present for a slot, `write_slot_model` MUST read from and write to
    /// the UUID-canonical path — not the legacy `config-N/settings.json`.
    ///
    /// Pins the Phase 2 reader-switchover contract: the UUID path is the
    /// authoritative settings location once Phase 2 materialization runs.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn models_command_resolves_settings_from_uuid_when_present() {
        use csq_core::accounts::identity_store::settings_path_for;
        use csq_core::credentials::write_uuid_settings;
        use csq_core::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: use coexisting_fixture to set up both the legacy config-N/ and
        // the identities/<UUID>/ layouts with consistent profiles.json mapping.
        // Slot 4 is the one under test; coexisting_fixture(4) creates slots 1–4.
        let slot_num: u16 = 4;
        let slot = AccountNum::try_from(slot_num).unwrap();
        let dir = coexisting_fixture(slot_num);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(slot_num);

        // Write legacy config-N/settings.json with a sentinel "legacy-model" value
        // so we can verify it is NOT overwritten when the UUID path is present.
        let legacy_settings_path = base
            .join(format!("config-{slot_num}"))
            .join("settings.json");
        std::fs::write(
            &legacy_settings_path,
            r#"{"env":{"ANTHROPIC_MODEL":"legacy-model","CLAUDE_MODEL":"legacy-model"}}"#,
        )
        .unwrap();

        // Write identities/<UUID>/settings.json with a sentinel "uuid-model" value.
        // This is the Phase 2 canonical path that write_slot_model must use.
        let uuid_settings_path = settings_path_for(base, uuid);
        write_uuid_settings(
            base,
            uuid,
            br#"{"env":{"ANTHROPIC_MODEL":"uuid-model","CLAUDE_MODEL":"uuid-model"}}"#,
        )
        .unwrap();

        // Act: switch model via write_slot_model (the CLI chokepoint).
        write_slot_model(base, slot, "switched-model").unwrap();

        // Assert: UUID settings.json has the new model (routing went through UUID path).
        let uuid_content = std::fs::read_to_string(&uuid_settings_path).unwrap();
        let uuid_val: Value = serde_json::from_str(&uuid_content).unwrap();
        for key in csq_core::session::merge::MODEL_KEYS {
            assert_eq!(
                uuid_val
                    .pointer(&format!("/env/{key}"))
                    .and_then(|x| x.as_str()),
                Some("switched-model"),
                "UUID settings.json must have the switched model for {key}"
            );
        }

        // Assert: legacy settings.json is NOT updated (routing sourced from UUID).
        let legacy_content = std::fs::read_to_string(&legacy_settings_path).unwrap();
        let legacy_val: Value = serde_json::from_str(&legacy_content).unwrap();
        assert_eq!(
            legacy_val
                .pointer("/env/ANTHROPIC_MODEL")
                .and_then(|x| x.as_str()),
            Some("legacy-model"),
            "legacy config-N/settings.json must NOT be updated when UUID path is present"
        );
    }
}
