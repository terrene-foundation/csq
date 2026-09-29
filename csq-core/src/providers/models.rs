//! Owned model catalogue types, lookup, and bounded Claude selector policy.
//! Bundled defaults and runtime metadata snapshots come from `model_manifest`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCatalog {
    pub models: Vec<ModelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub context_window: Option<u64>,
    pub output_limit: Option<u64>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Maps a DeepSeek Flash API model to its Claude Code context selector.
///
/// The API catalogue keeps the bare ID, but explicit Claude Code settings
/// selections require `[1m]` to retain the full context window. Only the known
/// DeepSeek Anthropic endpoint is eligible: a same-named Ollama/proxy model is
/// not evidence that this provider-specific annotation applies. Unknown model
/// names, custom selectors and unrelated providers are preserved byte-for-byte.
/// This is a write-time conversion, not a migration of existing settings.
pub fn claude_code_model_selector<'a>(model_id: &'a str, base_url: Option<&str>) -> &'a str {
    let Some(endpoint) = base_url.and_then(|value| url::Url::parse(value).ok()) else {
        return model_id;
    };
    if endpoint.scheme() != "https"
        || endpoint.host_str() != Some("api.deepseek.com")
        || endpoint.port_or_known_default() != Some(443)
        || endpoint.path().trim_end_matches('/') != "/anthropic"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return model_id;
    }
    let bare = model_id.strip_suffix("[1m]").unwrap_or(model_id);
    if [
        "deepseek-flash",
        "deepseek-v4-flash",
        "deepseek-v4-flash-vision-exp",
    ]
    .iter()
    .any(|known| bare.eq_ignore_ascii_case(known))
    {
        "deepseek-flash[1m]"
    } else {
        model_id
    }
}

impl ModelCatalog {
    /// Returns model metadata from the validated bundled manifest.
    /// Runtime callers should load `ModelManifest` with their explicit base dir.
    pub fn default_catalog() -> Self {
        super::model_manifest::ModelManifest::bundled().catalog()
    }

    /// Strips deployment-specific suffixes a model id can carry, for LOOKUP
    /// only — the stored catalog id is never rewritten.
    ///
    /// Two shapes occur in real slot settings:
    ///   * Vertex pins a version: `claude-opus-4-8@default` (also `@20260115`).
    ///   * CC annotates a window: `glm-5.2[1m]` (see `native::model`, which
    ///     strips the same annotation for the raw-API path).
    ///
    /// Both defeated exact matching, so `find` returned `None` for every Vertex
    /// slot and the statusline lost `ctx_window_true` — falling back to CC's own
    /// ~200k assumption. That is the defect an internal ticket fixed for DeepSeek, still live
    /// on the Vertex path until this normalisation.
    fn normalize_for_lookup(query: &str) -> &str {
        let base = match query.find('[') {
            Some(i) => &query[..i],
            None => query,
        };
        let base = match base.find('@') {
            Some(i) => &base[..i],
            None => base,
        };
        base.trim()
    }

    /// Finds a model by ID or alias.
    ///
    /// Exact match is tried FIRST, so a catalog id that legitimately contains
    /// `@` or `[` still wins over its own normalised form; normalisation is a
    /// fallback, never a rewrite.
    pub fn find(&self, query: &str) -> Option<&ModelInfo> {
        let q = query.to_lowercase();
        let exact = self
            .models
            .iter()
            .find(|m| m.id.to_lowercase() == q || m.aliases.iter().any(|a| a.to_lowercase() == q));
        if exact.is_some() {
            return exact;
        }
        let n = Self::normalize_for_lookup(&q);
        if n == q {
            return None;
        }
        self.models
            .iter()
            .find(|m| m.id.to_lowercase() == n || m.aliases.iter().any(|a| a.to_lowercase() == n))
    }

    /// Returns all models for a specific provider.
    pub fn by_provider(&self, provider: &str) -> Vec<&ModelInfo> {
        self.models
            .iter()
            .filter(|m| m.provider == provider)
            .collect()
    }

    /// Suggests the closest match for a model query (Levenshtein-ish).
    pub fn suggest(&self, query: &str) -> Option<&ModelInfo> {
        let q = query.to_lowercase();
        self.models.iter().min_by_key(|m| {
            // Simple scoring: prefer prefix matches, then substring matches
            if m.id.to_lowercase().starts_with(&q) {
                0
            } else if m.id.to_lowercase().contains(&q) {
                1
            } else if m.aliases.iter().any(|a| a.to_lowercase().contains(&q)) {
                2
            } else {
                3
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_has_models() {
        let cat = ModelCatalog::default_catalog();
        assert!(!cat.models.is_empty());
        assert!(cat.find("claude-opus-4-8").is_some());
        // Vertex slot 19's pin: the [1m] annotation must still resolve to the
        // 1M window, or the statusline over-reports context use 5x.
        let opus55 = cat
            .find("claude-opus-5-5[1m]")
            .expect("opus 5.5 in catalog");
        assert_eq!(opus55.id, "claude-opus-5-5");
        assert_eq!(opus55.context_window, Some(1_000_000));

        // Vertex pins a version suffix in the slot's ANTHROPIC_MODEL. Before
        // normalisation this returned None, so `ctx_window_true` was None for
        // EVERY Vertex slot and the statusline silently fell back to CC's ~200k
        // assumption (the an internal ticket defect, on a different provider).
        assert_eq!(
            cat.find("claude-opus-4-8@default").map(|m| m.id.as_str()),
            Some("claude-opus-4-8"),
            "Vertex @version suffix must not defeat catalog lookup"
        );
        assert_eq!(
            cat.find("claude-opus-4-8@20260115").map(|m| m.id.as_str()),
            Some("claude-opus-4-8"),
            "a numeric Vertex version pin resolves the same way"
        );
        // CC's window annotation, the shape native::model already strips.
        assert_eq!(
            cat.find("claude-opus-4-8[1m]").map(|m| m.id.as_str()),
            Some("claude-opus-4-8")
        );
        // Aliases normalise too.
        assert_eq!(
            cat.find("opus@default").map(|m| m.id.as_str()),
            Some("claude-opus-4-8")
        );
        // Case-insensitive, as before.
        assert_eq!(
            cat.find("CLAUDE-OPUS-4-8@DEFAULT").map(|m| m.id.as_str()),
            Some("claude-opus-4-8")
        );
        // A genuinely unknown model stays unknown — normalisation must not
        // manufacture a match.
        assert!(cat.find("claude-opus-5@default").is_none());
        assert!(cat.find("no-such-model").is_none());
    }

    #[test]
    fn find_by_id() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("claude-opus-4-8").unwrap();
        assert_eq!(m.provider, "claude");
    }

    #[test]
    fn find_by_alias() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("opus").unwrap();
        assert_eq!(m.id, "claude-opus-4-8");
    }

    #[test]
    fn find_case_insensitive() {
        let cat = ModelCatalog::default_catalog();
        assert!(cat.find("OPUS").is_some());
        assert!(cat.find("Claude-Opus-4-8").is_some());
    }

    #[test]
    fn find_unknown_returns_none() {
        let cat = ModelCatalog::default_catalog();
        assert!(cat.find("nonexistent-model").is_none());
    }

    #[test]
    fn by_provider_filters_correctly() {
        let cat = ModelCatalog::default_catalog();
        let claude = cat.by_provider("claude");
        assert!(claude.iter().all(|m| m.provider == "claude"));
        assert!(claude.len() >= 3);

        let mm = cat.by_provider("mm");
        assert!(mm.iter().all(|m| m.provider == "mm"));
    }

    #[test]
    fn deepseek_v41_claude_selector_annotates_only_known_flash_ids() {
        for endpoint in [
            "https://api.deepseek.com/anthropic",
            "https://api.deepseek.com/anthropic/",
            "https://API.DEEPSEEK.COM:443/anthropic",
        ] {
            for model in [
                "deepseek-flash",
                "deepseek-v4-flash",
                "deepseek-v4-flash-vision-exp",
                "DEEPSEEK-FLASH",
                "deepseek-flash[1m]",
                "deepseek-v4-flash[1m]",
                "deepseek-v4-flash-vision-exp[1m]",
            ] {
                let selector = claude_code_model_selector(model, Some(endpoint));
                assert_eq!(selector, "deepseek-flash[1m]", "{model} at {endpoint}");
                assert_eq!(
                    claude_code_model_selector(selector, Some(endpoint)),
                    selector
                );
                assert_eq!(
                    ModelCatalog::default_catalog().find(selector).unwrap().id,
                    "deepseek-flash"
                );
            }
        }
    }

    #[test]
    fn deepseek_v41_claude_selector_preserves_other_endpoints_and_custom_models() {
        for endpoint in [
            None,
            Some("not a URL"),
            Some("http://localhost:11434"),
            Some("http://127.0.0.1:11434/anthropic"),
            Some("https://api.deepseek.com.evil.example/anthropic"),
            Some("https://proxy.example/deepseek/anthropic"),
            Some("http://api.deepseek.com/anthropic"),
            Some("https://api.deepseek.com:8443/anthropic"),
            Some("https://api.deepseek.com/v1"),
            Some("https://user@api.deepseek.com/anthropic"),
            Some("https://api.deepseek.com/anthropic?provider=other"),
            Some("https://api.deepseek.com/anthropic#other"),
        ] {
            assert_eq!(
                claude_code_model_selector("deepseek-flash", endpoint),
                "deepseek-flash",
                "endpoint {endpoint:?}"
            );
        }
        for model in [
            "deepseek-v4-pro",
            "deepseek-v4-pro[1m]",
            "custom-model",
            "deepseek-flash[200k]",
            "deepseek-v4.1-flash",
            " deepseek-flash ",
            "",
        ] {
            assert_eq!(
                claude_code_model_selector(model, Some("https://api.deepseek.com/anthropic")),
                model
            );
        }
    }

    #[test]
    fn deepseek_v41_flash_is_the_single_canonical_flash_entry() {
        let cat = ModelCatalog::default_catalog();
        let models = cat.by_provider("deepseek");
        assert_eq!(
            models.len(),
            2,
            "Pro remains distinct; aliases are not models"
        );
        let flash = models.iter().find(|m| m.id == "deepseek-flash").unwrap();
        assert_eq!(flash.name, "DeepSeek V4.1 Flash");
        assert_eq!(flash.context_window, Some(1_000_000));
        assert_eq!(flash.output_limit, Some(384_000));
        assert_eq!(cat.find("ds-pro").unwrap().id, "deepseek-v4-pro");
        assert_eq!(cat.find("ds-pro").unwrap().name, "DeepSeek V4 Pro");
        assert!(
            cat.find("deepseek-v4.1-flash").is_none(),
            "not a published API id"
        );
    }

    #[test]
    fn deepseek_v41_flash_legacy_and_version_aliases_resolve_canonically() {
        let cat = ModelCatalog::default_catalog();
        for query in [
            "deepseek-flash",
            "deepseek-v4-flash",
            "deepseek-v4-flash-vision-exp",
            "ds-flash",
            "v4-flash",
            "4.1",
            "v4.1",
            "v4.1-flash",
            "DEEPSEEK-FLASH",
            "deepseek-v4-flash[1m]",
            "deepseek-flash[1m]",
            "deepseek-flash@default",
        ] {
            let model = cat.find(query).unwrap_or_else(|| panic!("missing {query}"));
            assert_eq!(model.id, "deepseek-flash", "lookup {query}");
            assert_eq!(model.provider, "deepseek", "lookup {query}");
            assert_eq!(model.context_window, Some(1_000_000), "lookup {query}");
        }
    }

    #[test]
    fn deepseek_v41_switch_alias_is_unambiguous_across_providers() {
        let cat = ModelCatalog::default_catalog();
        for query in ["4.1", "v4.1", "v4.1-flash"] {
            let matches: Vec<_> = cat
                .models
                .iter()
                .filter(|model| {
                    model.id.eq_ignore_ascii_case(query)
                        || model
                            .aliases
                            .iter()
                            .any(|alias| alias.eq_ignore_ascii_case(query))
                })
                .collect();
            assert_eq!(matches.len(), 1, "ambiguous switch alias {query}");
            assert_eq!(matches[0].id, "deepseek-flash");
        }
    }

    #[test]
    fn deepseek_v41_catalog_serialization_exposes_canonical_identity_and_legacy_aliases() {
        let cat = ModelCatalog::default_catalog();
        let json = serde_json::to_value(cat.by_provider("deepseek")).unwrap();
        let flash = json
            .as_array()
            .unwrap()
            .iter()
            .find(|model| model["id"] == "deepseek-flash")
            .unwrap();
        assert_eq!(flash["name"], "DeepSeek V4.1 Flash");
        assert_eq!(flash["context_window"], 1_000_000);
        assert_eq!(flash["output_limit"], 384_000);
        let aliases = flash["aliases"].as_array().unwrap();
        assert!(aliases.iter().any(|alias| alias == "deepseek-v4-flash"));
        assert!(aliases
            .iter()
            .any(|alias| alias == "deepseek-v4-flash-vision-exp"));
    }

    #[test]
    fn deepseek_v4_pro_context_window_is_1m() {
        // DeepSeek V4 Pro is a 1M-token context model (maintainer-confirmed 2026-07-05);
        // a stale 128k value under-states the true window (and would drive a wrong
        // context-% once the statusline consumes the catalog window).
        let cat = ModelCatalog::default_catalog();
        let m = cat
            .find("deepseek-v4-pro")
            .expect("deepseek-v4-pro in catalog");
        assert_eq!(m.context_window, Some(1_000_000));
        // aliases still resolve to the 1M entry.
        assert_eq!(cat.find("ds-pro").unwrap().context_window, Some(1_000_000));
    }

    /// Pins Claude Opus 4.8's window, mirroring the deepseek/kimi tests.
    ///
    /// This test is the actual fix. The value it guards was wrong for multiple
    /// releases and nothing noticed, because the Claude entries were the only
    /// ones in this catalog with no window assertion — so a stale literal could
    /// ride through version renames indefinitely. The number below is the
    /// maintainer-supplied figure for Opus 4.8 (2026-09-02).
    #[test]
    fn claude_opus_4_8_context_window_is_1m() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("claude-opus-4-8").expect("opus 4.8 in catalog");
        assert_eq!(m.context_window, Some(1_000_000));
        // Reached the same way the statusline reaches it: via the alias, and
        // via the Vertex-suffixed form a slot's settings.json actually holds.
        assert_eq!(cat.find("opus").unwrap().context_window, Some(1_000_000));
        assert_eq!(
            cat.find("claude-opus-4-8@default").unwrap().context_window,
            Some(1_000_000),
            "the statusline resolves the Vertex-pinned id; it must see the true window"
        );
        // The CC `[1m]` window annotation is what slot 19's settings.json holds
        // TODAY (`claude-opus-4-8[1m]`); `@default` above is the older Vertex
        // pin. Both must resolve, or the statusline silently falls back to CC's
        // ~200k assumption and over-reports context use by 5x on a 1M model.
        assert_eq!(
            cat.find("claude-opus-4-8[1m]").unwrap().context_window,
            Some(1_000_000),
            "the [1m] annotation a Vertex slot actually carries must resolve too"
        );
    }

    /// Every Claude entry's window AND output limit, pinned against the live
    /// Models API.
    ///
    /// `claude_opus_4_8_context_window_is_1m` fixed ONE literal and said so:
    /// "STILL STALE, deliberately not guessed: claude-sonnet-5,
    /// claude-sonnet-4-6 and claude-haiku-4-5-20251001 remain at 200_000."
    /// They are no longer guesses. Measured 2026-09-09 via
    /// `GET https://api.anthropic.com/v1/models/{id}`:
    ///
    ///   claude-opus-4-8            max_input_tokens=1000000  max_tokens=128000
    ///   claude-sonnet-5            max_input_tokens=1000000  max_tokens=128000
    ///   claude-sonnet-4-6          max_input_tokens=1000000  max_tokens=128000
    ///   claude-haiku-4-5-20251001  max_input_tokens= 200000  max_tokens= 64000
    ///
    /// Haiku's 200_000 was already RIGHT — and had no test. That is precisely
    /// the state Opus 4.8 was in before it rotted through three version bumps,
    /// so it is pinned here for the same reason, not because it changed.
    ///
    /// `context_window` is the operator-visible one: statusline.rs resolves it
    /// into `ctx_window_true`, and a 5x-low figure over-reports context use
    /// (the an internal ticket shape). `output_limit` is surfaced by `csq models --json`
    /// only — wrong rather than dangerous, but wrong by 15x on Sonnet.
    #[test]
    fn claude_windows_and_output_limits_match_the_models_api() {
        let cat = ModelCatalog::default_catalog();
        for (id, ctx, out) in [
            ("claude-opus-4-8", 1_000_000u64, 128_000u64),
            ("claude-sonnet-5", 1_000_000, 128_000),
            ("claude-sonnet-4-6", 1_000_000, 128_000),
            ("claude-haiku-4-5-20251001", 200_000, 64_000),
        ] {
            let m = cat
                .find(id)
                .unwrap_or_else(|| panic!("{id} missing from catalog"));
            assert_eq!(m.context_window, Some(ctx), "{id} context_window");
            assert_eq!(m.output_limit, Some(out), "{id} output_limit");
        }
        // The aliases the statusline and `csq models` actually reach these by.
        assert_eq!(cat.find("sonnet").unwrap().context_window, Some(1_000_000));
        assert_eq!(cat.find("haiku").unwrap().context_window, Some(200_000));
    }

    #[test]
    fn kimi_k3_context_window_is_1m() {
        // Kimi K3 is a 1,048,576-token context model (maintainer-confirmed);
        // mirrors the deepseek-v4-pro context-window regression above. Canonical
        // id is the 1M-context `kimi-k3[1m]` form.
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("kimi-k3[1m]").expect("kimi-k3[1m] in catalog");
        assert_eq!(m.context_window, Some(1_048_576));
        assert_eq!(m.provider, "kimi");
        // aliases still resolve to the same entry — bare `k3` and the legacy
        // bare `kimi-k3` form both point at the 1M variant.
        assert_eq!(cat.find("k3").unwrap().context_window, Some(1_048_576));
        assert_eq!(cat.find("kimi-k3").unwrap().context_window, Some(1_048_576));
    }

    #[test]
    fn serialization_round_trip() {
        let cat = ModelCatalog::default_catalog();
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: ModelCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat.models.len(), parsed.models.len());
    }
    /// Pins DeepSeek's PUBLISHED specs so a future edit cannot quietly revert
    /// them. Verified 2026-08-01 against DeepSeek's Models & Pricing table
    /// (verbatim rows): `CONTEXT LENGTH` = "1M" and `MAX OUTPUT` =
    /// "MAXIMUM: 384K" for BOTH `deepseek-v4-flash` and `deepseek-v4-pro`.
    ///
    /// csq previously carried flash at 128k context and both models at 8_192
    /// output. The flash context error was BEHAVIOURAL: `context_window` feeds
    /// the statusline's context-% recompute, so a flash slot over-reported
    /// usage ~8x — the same defect the v4-pro entry documents having fixed,
    /// which flash never received.
    #[test]
    fn deepseek_v4_specs_match_the_published_table() {
        let cat = ModelCatalog::default_catalog();
        let get = |id: &str| {
            cat.find(id)
                .unwrap_or_else(|| panic!("{id} missing from the default catalog"))
        };

        for id in ["deepseek-v4-flash", "deepseek-v4-pro"] {
            let m = get(id);
            assert_eq!(
                m.context_window,
                Some(1_000_000),
                "{id}: published CONTEXT LENGTH is 1M"
            );
            assert_eq!(
                m.output_limit,
                Some(384_000),
                "{id}: published MAX OUTPUT is 384K"
            );
        }
    }
}
