//! Model catalog — embedded list of models across providers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCatalog {
    pub models: Vec<ModelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub context_window: Option<u64>,
    pub output_limit: Option<u64>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl ModelCatalog {
    /// Returns the embedded default catalog.
    pub fn default_catalog() -> Self {
        Self {
            models: vec![
                // Claude
                ModelInfo {
                    id: "claude-opus-4-8".into(),
                    name: "Claude Opus 4.8".into(),
                    provider: "claude".into(),
                    // 1M, not the 200_000 this carried since v2.0. That literal
                    // was correct when it was written and then rode forward
                    // untouched across 4.6 -> 4.7 -> 4.8: every version bump
                    // renamed `id`/`name`/`aliases` only (4a3b8e0b), and every
                    // later commit that DID touch a context_window was for a
                    // different provider (Sonnet 5, Kimi, DeepSeek, Gemini).
                    // Nothing failed, because — unlike deepseek-v4-pro and
                    // kimi-k3 — no test pinned a Claude window. See
                    // `claude_opus_4_8_context_window_is_1m` below, which is the
                    // part that stops this rotting again.
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["opus".into(), "opus-4-8".into(), "opus-4-7".into()],
                },
                ModelInfo {
                    id: "claude-sonnet-5".into(),
                    name: "Claude Sonnet 5".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(8_192),
                    aliases: vec!["sonnet".into(), "sonnet-5".into()],
                },
                ModelInfo {
                    id: "claude-sonnet-4-6".into(),
                    name: "Claude Sonnet 4.6".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(8_192),
                    aliases: vec!["sonnet-4-6".into()],
                },
                ModelInfo {
                    id: "claude-haiku-4-5-20251001".into(),
                    name: "Claude Haiku 4.5".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(4_096),
                    aliases: vec!["haiku".into(), "haiku-4-5".into()],
                },
                // MiniMax
                ModelInfo {
                    id: "MiniMax-M3".into(),
                    name: "MiniMax M3".into(),
                    provider: "mm".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["m3".into(), "minimax-m3".into(), "mm-m3".into()],
                },
                // Z.AI — `glm-5.3[1m]` is the 1M-context variant (Z.AI docs:
                // append the `[1m]` suffix to enable the 1,000,000-token window).
                // Bracket-free aliases (`glm`, `glm-5.3`) let `csq models switch`
                // resolve it without shell-quoting the `[1m]` glob. `glm-5.2` is
                // kept as an alias (not dropped): Z.AI's `/v1/messages` endpoint
                // aliases `glm-5.2` requests to `glm-5.3` server-side (verified
                // live 2026-08-15 — response echoes `"model":"glm-5.3"` for a
                // `glm-5.2` request), and existing slot `settings-zai.json` files
                // already pin the bracketed `glm-5.2[1m]` id and are not rewritten
                // by this change (`account-terminal-separation.md` — no migration
                // sweep of already-materialized slot files).
                ModelInfo {
                    id: "glm-5.3[1m]".into(),
                    name: "GLM 5.3 (1M context)".into(),
                    provider: "zai".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec![
                        "glm".into(),
                        "glm-5.3".into(),
                        "glm-5".into(),
                        "glm-5.2".into(),
                    ],
                },
                // Gemini — static list per FR-G-UI-02 / ADR-G08.
                // `auto` is handled as a literal in the
                // `models switch gemini` branch, NOT as a catalog
                // entry — it instructs gemini-cli to pick rather
                // than pinning a specific id.
                ModelInfo {
                    id: "gemini-2.5-pro".into(),
                    name: "Gemini 2.5 Pro".into(),
                    provider: "gemini".into(),
                    context_window: Some(2_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["pro".into(), "2.5-pro".into()],
                },
                ModelInfo {
                    id: "gemini-2.5-flash".into(),
                    name: "Gemini 2.5 Flash".into(),
                    provider: "gemini".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["flash".into(), "2.5-flash".into()],
                },
                ModelInfo {
                    id: "gemini-2.5-flash-lite".into(),
                    name: "Gemini 2.5 Flash Lite".into(),
                    provider: "gemini".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["flash-lite".into(), "2.5-flash-lite".into()],
                },
                ModelInfo {
                    id: "gemini-3-pro-preview".into(),
                    name: "Gemini 3 Pro (preview)".into(),
                    provider: "gemini".into(),
                    context_window: Some(2_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["3-pro-preview".into(), "3-pro".into()],
                },
                // DeepSeek — Anthropic-API-compatible models exposed via
                // https://api.deepseek.com/anthropic. Tier mapping per
                // DeepSeek docs: pro for opus/sonnet workloads, flash
                // for haiku/subagent/cheap-fast workloads.
                ModelInfo {
                    id: "deepseek-v4-pro".into(),
                    name: "DeepSeek V4 Pro".into(),
                    provider: "deepseek".into(),
                    // DeepSeek V4 Pro ships a 1M-token context window (maintainer-confirmed
                    // 2026-07-05). CONSUMED by the statusline context-% recompute: the CLI
                    // (`statusline.rs`) resolves this window from the slot's settings.json
                    // model id (`providers::settings::model_id_for_slot`) and sets
                    // `StatuslineContext::ctx_window_true`, so `format.rs` recomputes the %
                    // against 1M instead of trusting CC's ~200k assumption for the
                    // Anthropic-compatible endpoint (which rendered 177k → 89% instead of ~18%).
                    context_window: Some(1_000_000),
                    // 384K, not 8_192. Verified 2026-08-01 against DeepSeek's
                    // published Models & Pricing table, `MAX OUTPUT` row:
                    // "MAXIMUM: 384K" for BOTH v4-pro and v4-flash. The old
                    // 8_192 predates V4 and was never revised.
                    output_limit: Some(384_000),
                    aliases: vec!["ds-pro".into(), "deepseek-pro".into(), "v4-pro".into()],
                },
                ModelInfo {
                    id: "deepseek-v4-flash".into(),
                    name: "DeepSeek V4 Flash".into(),
                    provider: "deepseek".into(),
                    // DeepSeek publishes `MODEL VERSION: DeepSeek-V4-Flash-0731`
                    // for this id — the dated snapshot is the VERSION, not a
                    // separate API model, so `deepseek-v4-flash` is the id to
                    // call for it. (Maintainer asked for "0731" specifically;
                    // this is that model.)
                    //
                    // 1M context, NOT 128k. Verified 2026-08-01 against the
                    // published Models & Pricing table: `CONTEXT LENGTH` is
                    // "1M" for both v4-flash and v4-pro.
                    //
                    // This one is BEHAVIOURAL, not just record-keeping.
                    // `context_window` is consumed by the statusline's
                    // context-% recompute (`statusline.rs:146` ->
                    // `StatuslineContext::ctx_window_true`). At 128k a flash
                    // slot over-reported usage ~8x — the identical bug the
                    // v4-pro entry above documents having fixed ("rendered
                    // 177k -> 89% instead of ~18%"). Pro got the correction;
                    // flash was left behind.
                    context_window: Some(1_000_000),
                    output_limit: Some(384_000),
                    aliases: vec![
                        "ds-flash".into(),
                        "deepseek-flash".into(),
                        "v4-flash".into(),
                    ],
                },
                // Kimi (Moonshot AI) — Anthropic-API-compatible model exposed via
                // https://api.kimi.com/coding (subscription). 1M-token context window
                // (maintainer-confirmed), matching the catalog default_model. The
                // canonical id is `kimi-k3[1m]` (the 1M-context variant); the bare
                // `kimi-k3` form is kept as an alias so older references still
                // resolve to the same 1M entry — Kimi's coding endpoint exposes
                // the 1M variant as the only K3 SKU.
                ModelInfo {
                    id: "kimi-k3[1m]".into(),
                    name: "Kimi K3".into(),
                    provider: "kimi".into(),
                    context_window: Some(1_048_576),
                    output_limit: Some(8_192),
                    aliases: vec!["k3".into(), "kimi-k3".into()],
                },
            ],
        }
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
