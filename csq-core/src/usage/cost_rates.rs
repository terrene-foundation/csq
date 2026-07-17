//! Static per-model cost rate table per an internal journal entry D3.
//!
//! Rates from public pricing pages as of 2026-05-06. Updated when providers
//! announce changes — this is the SOLE source of truth for cost estimation in
//! Phase B' v1. Per D3, v1 uses the slot's CURRENT configured model for every
//! turn (approximation); v2 (per-turn jsonl scan) will pick up actual model
//! per turn.
//!
//! Rates are USD per 1M tokens. `Unknown` is used when no rate exists for a
//! model name — caller renders cost as `n/a` rather than guessing.

/// Cost rate for one model. `input`/`output` fields are USD per 1,000,000
/// tokens. `cache_eligible` marks whether this model's prompt-cache tokens
/// should be billed with the Anthropic multipliers ([`CACHE_WRITE_INPUT_MULTIPLIER`]
/// / [`CACHE_READ_INPUT_MULTIPLIER`]) — true ONLY for the Anthropic Claude
/// family, where those prices are exact. Deriving cache-eligibility from the
/// matched rate ROW (not a separate model-name check) keeps a single source of
/// truth: a model that matches no rate row is billed nothing (rate + cache),
/// and a non-Claude row can never be cache-billed. #992.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostRate {
    pub input_per_1m_usd: f64,
    pub output_per_1m_usd: f64,
    /// See the struct doc. `true` only for Anthropic Claude rows.
    pub cache_eligible: bool,
}

impl CostRate {
    /// A non-cache-eligible rate (every provider except Anthropic Claude).
    pub const fn new(input: f64, output: f64) -> Self {
        Self {
            input_per_1m_usd: input,
            output_per_1m_usd: output,
            cache_eligible: false,
        }
    }

    /// A cache-eligible rate — `cache_eligible = true` so prompt-cache tokens
    /// are billed at [`CACHE_WRITE_INPUT_MULTIPLIER`] /
    /// [`CACHE_READ_INPUT_MULTIPLIER`] of the base input rate. Used for models
    /// whose cache pricing is verified — currently all Anthropic Claude models
    /// (mirrors `Vec::with_capacity`: names the behavior, not the provider, so a
    /// future cache-eligible provider reuses it without a new constructor).
    pub const fn with_cache(input: f64, output: f64) -> Self {
        Self {
            input_per_1m_usd: input,
            output_per_1m_usd: output,
            cache_eligible: true,
        }
    }

    /// Estimate the cost in USD for a session with the given token counts.
    ///
    /// Bills `input_tokens` + `output_tokens` only. For a cache-aware estimate
    /// use [`Self::estimate_usd_with_cache`]; this method is retained as the
    /// zero-cache case (`estimate_usd_with_cache(i, o, 0, 0) == estimate_usd(i, o)`).
    pub fn estimate_usd(&self, input_tokens: u64, output_tokens: u64) -> f64 {
        let i = (input_tokens as f64) * self.input_per_1m_usd / 1_000_000.0;
        let o = (output_tokens as f64) * self.output_per_1m_usd / 1_000_000.0;
        i + o
    }

    /// Estimate the cost in USD including prompt-cache tokens (#992).
    ///
    /// Cache-write (`cache_creation_input_tokens`) and cache-read
    /// (`cache_read_input_tokens`) are billed as multiples of the base input
    /// rate per [`CACHE_WRITE_INPUT_MULTIPLIER`] / [`CACHE_READ_INPUT_MULTIPLIER`].
    /// With zero cache tokens this returns exactly [`Self::estimate_usd`] — so
    /// existing cost numbers do not regress for sessions with no cache activity.
    pub fn estimate_usd_with_cache(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        cache_creation_tokens: u64,
        cache_read_tokens: u64,
    ) -> f64 {
        let base = self.estimate_usd(input_tokens, output_tokens);
        let write =
            (cache_creation_tokens as f64) * self.input_per_1m_usd * CACHE_WRITE_INPUT_MULTIPLIER
                / 1_000_000.0;
        let read = (cache_read_tokens as f64) * self.input_per_1m_usd * CACHE_READ_INPUT_MULTIPLIER
            / 1_000_000.0;
        base + write + read
    }
}

/// Prompt-cache cost multipliers relative to the base input rate (#992).
///
/// These are Anthropic's published prompt-caching multipliers (5-minute TTL):
/// a cache WRITE costs 1.25× the base input rate; a cache READ (hit) costs
/// 0.10× the base input rate. They are billed relative to each model's already
/// verified input rate rather than stored as separate per-model columns.
///
/// **Application:** these multipliers are applied ONLY to rates whose
/// [`CostRate::cache_eligible`] is `true` — the Anthropic Claude family, where
/// they are exact. Every other provider ([`CostRate::cache_eligible`] `== false`)
/// bills cache at $0 (unchanged) — their cache pricing differs materially
/// (OpenAI charges no cache-write surcharge; Gemini's context caching is
/// duration-based; DeepSeek's Anthropic-compatible cache-hit is only in the
/// same ballpark), so applying Claude's rates would emit directionally wrong
/// dollar figures, and csq does not guess (the module's fail-loud contract).
/// Per-provider cache rates are the #992 follow-up. For a Claude slot, billing
/// cache at these multipliers is far closer to true cost than the prior
/// "cache = $0" model, since cache-read volume routinely dwarfs fresh input on
/// long coding sessions (a session commonly reads millions of cached tokens
/// against a few thousand fresh input tokens).
///
/// NOTE (known pre-existing limitation, not #992): cache-eligibility is keyed on
/// the matched rate ROW, and [`rate_for_model`] itself is provider-blind — a
/// locally-run model whose name coincidentally contains a Claude rate pattern
/// (e.g. an Ollama pull literally named `claude-sonnet-local`) would match a
/// Claude row and be billed at Claude base+cache rates. That mis-attribution
/// predates #992 (it already applied to base input/output billing) and is a
/// `rate_for_model` provider-awareness gap, tracked separately.
pub const CACHE_WRITE_INPUT_MULTIPLIER: f64 = 1.25;
/// See [`CACHE_WRITE_INPUT_MULTIPLIER`]. Cache-read (hit) multiplier.
pub const CACHE_READ_INPUT_MULTIPLIER: f64 = 0.10;

/// Looks up the cost rate for a model name. Returns `None` if the name is
/// unrecognized — caller renders `n/a` rather than guessing a rate.
///
/// Matching is case-insensitive substring on the model family. The static
/// table covers the canonical model families; if a provider ships a new
/// minor (e.g. `deepseek-chat-2`), this returns `None` until the table is
/// updated. That's the explicit fail-loud signal.
pub fn rate_for_model(model: &str) -> Option<CostRate> {
    let lc = model.to_lowercase();
    for (pat, rate) in MODEL_RATES {
        if lc.contains(pat) {
            return Some(*rate);
        }
    }
    None
}

/// Static rate table. Patterns match against the model name lowercase
/// (substring contains). Order matters — most specific first.
///
/// **Rates as of 2026-05-06.** When a provider announces a price change
/// or a new model lands, update this table and bump `RATES_AS_OF`.
const MODEL_RATES: &[(&str, CostRate)] = &[
    // ── Anthropic Claude (pay-per-token API) ───────────────────────────
    // Subscription users see no cost; this fires for direct-API-key slots.
    ("claude-opus-4-7", CostRate::with_cache(15.00, 75.00)),
    ("claude-opus-4-6", CostRate::with_cache(15.00, 75.00)),
    ("claude-opus", CostRate::with_cache(15.00, 75.00)),
    ("claude-sonnet-4-7", CostRate::with_cache(3.00, 15.00)),
    ("claude-sonnet-4-6", CostRate::with_cache(3.00, 15.00)),
    ("claude-sonnet", CostRate::with_cache(3.00, 15.00)),
    ("claude-haiku-4-5", CostRate::with_cache(1.00, 5.00)),
    ("claude-haiku", CostRate::with_cache(1.00, 5.00)),
    // ── OpenAI / Codex (pay-per-token API) ─────────────────────────────
    ("gpt-5-codex", CostRate::new(1.25, 10.00)),
    ("gpt-5", CostRate::new(1.25, 10.00)),
    // ── Google Gemini AI Studio ────────────────────────────────────────
    ("gemini-2.5-pro", CostRate::new(1.25, 5.00)),
    ("gemini-2.5-flash", CostRate::new(0.075, 0.30)),
    ("gemini-2.0-flash", CostRate::new(0.075, 0.30)),
    ("gemini-1.5-pro", CostRate::new(1.25, 5.00)),
    // ── DeepSeek (Anthropic-API-compatible, api.deepseek.com/anthropic) ─
    // V4 lineup (released 2026-04-24), which is what csq's catalog configures
    // 3P DeepSeek slots with (`providers::catalog` default_model
    // `deepseek-v4-pro`, haiku/subagent `deepseek-v4-flash`). Rates are the
    // cache-MISS input price + output price. DeepSeek is non-Anthropic, so
    // its rate row is `cache_eligible == false` and its cache tokens are billed at $0
    // (its cache-hit pricing is not yet verified — #992). The former 75%-off promo became the
    // permanent official price on 2026-05-31. The legacy `deepseek-chat` /
    // `deepseek-reasoner` aliases route to V4 Flash pricing (both deprecating
    // 2026-07-24). Verified against DeepSeek pricing docs 2026-07-07.
    //
    // `deepseek-coder` was REMOVED: it is not part of the V4 lineup and has no
    // verifiable current rate, so it correctly renders `n/a` rather than a
    // guessed price (the fail-loud contract in this module's header).
    ("deepseek-v4-pro", CostRate::new(0.435, 0.87)),
    ("deepseek-v4-flash", CostRate::new(0.14, 0.28)),
    ("deepseek-reasoner", CostRate::new(0.14, 0.28)),
    ("deepseek-chat", CostRate::new(0.14, 0.28)),
    // ── MiniMax ───────────────────────────────────────────────────────
    ("m2.7-coder", CostRate::new(0.30, 1.20)),
    ("minimax", CostRate::new(0.30, 1.20)),
    // ── Z.AI ──────────────────────────────────────────────────────────
    ("glm-4.6", CostRate::new(0.20, 0.80)),
    ("glm", CostRate::new(0.20, 0.80)),
];

/// Date the rates were last verified against public pricing. Update when the
/// table changes. The DeepSeek rows were re-verified 2026-07-07 (V4 lineup);
/// the other providers' rows carry forward from the 2026-05-06 verification.
pub const RATES_AS_OF: &str = "2026-07-07";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_for_model_matches_known_families() {
        assert!(rate_for_model("deepseek-v4-pro").is_some());
        assert!(rate_for_model("deepseek-v4-flash").is_some());
        assert!(rate_for_model("deepseek-reasoner").is_some());
        assert!(rate_for_model("deepseek-chat").is_some());
        assert!(rate_for_model("claude-opus-4-7").is_some());
        assert!(rate_for_model("claude-sonnet-4-6").is_some());
        assert!(rate_for_model("gpt-5").is_some());
        assert!(rate_for_model("gemini-2.5-pro").is_some());
        assert!(rate_for_model("gemini-2.5-flash").is_some());
        assert!(rate_for_model("glm-4.6").is_some());
    }

    #[test]
    fn rate_for_model_case_insensitive() {
        assert_eq!(
            rate_for_model("deepseek-chat"),
            rate_for_model("DeepSeek-Chat")
        );
        assert_eq!(
            rate_for_model("CLAUDE-OPUS-4-7"),
            rate_for_model("claude-opus-4-7")
        );
    }

    #[test]
    fn rate_for_model_unknown_returns_none() {
        assert!(rate_for_model("foobar").is_none());
        assert!(rate_for_model("").is_none());
        assert!(rate_for_model("o3-mini").is_none()); // not in table
                                                      // deepseek-coder removed (not V4 lineup, no verifiable rate) → n/a.
        assert!(rate_for_model("deepseek-coder").is_none());
    }

    #[test]
    fn estimate_usd_matches_public_pricing() {
        // 1M input + 1M output deepseek-v4-pro = $0.435 + $0.87 = $1.305
        let rate = rate_for_model("deepseek-v4-pro").unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!(
            (cost - 1.305).abs() < 0.001,
            "expected ~$1.305, got ${cost}"
        );

        // 1M input + 1M output deepseek-v4-flash = $0.14 + $0.28 = $0.42
        // (legacy `deepseek-chat`/`deepseek-reasoner` route to this rate).
        let rate = rate_for_model("deepseek-chat").unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!((cost - 0.42).abs() < 0.001, "expected ~$0.42, got ${cost}");

        // 100K input + 50K output claude-sonnet = $0.30 + $0.75 = $1.05
        let rate = rate_for_model("claude-sonnet-4-6").unwrap();
        let cost = rate.estimate_usd(100_000, 50_000);
        assert!((cost - 1.05).abs() < 0.001, "expected ~$1.05, got ${cost}");

        // Zero tokens → zero cost.
        let rate = rate_for_model("gpt-5").unwrap();
        assert_eq!(rate.estimate_usd(0, 0), 0.0);
    }

    #[test]
    fn rates_table_is_non_empty() {
        // Smoke — guards against accidental wholesale deletion.
        assert!(MODEL_RATES.len() >= 10);
    }

    #[test]
    fn estimate_usd_with_cache_bills_cache_tokens() {
        // claude-sonnet: input 3.00, output 15.00 per 1M.
        //   base  = 100K in ×3/1M   + 50K out ×15/1M = 0.30 + 0.75 = 1.05
        //   write = 200K ×3 ×1.25/1M                  = 0.75
        //   read  = 1M   ×3 ×0.10/1M                  = 0.30
        //   total = 2.10
        let rate = rate_for_model("claude-sonnet-4-6").unwrap();
        let cost = rate.estimate_usd_with_cache(100_000, 50_000, 200_000, 1_000_000);
        assert!((cost - 2.10).abs() < 0.001, "expected ~$2.10, got ${cost}");
    }

    #[test]
    fn estimate_usd_with_cache_zero_cache_equals_base() {
        // No cache activity must bill exactly the same as the input+output-only
        // estimate — the no-regression guarantee for #992.
        for model in ["claude-opus-4-7", "gpt-5", "deepseek-v4-pro", "glm-4.6"] {
            let rate = rate_for_model(model).unwrap();
            let base = rate.estimate_usd(123_456, 65_432);
            let with_zero_cache = rate.estimate_usd_with_cache(123_456, 65_432, 0, 0);
            assert_eq!(
                base, with_zero_cache,
                "{model}: zero-cache estimate must equal the base estimate"
            );
        }
    }

    #[test]
    fn cache_eligible_is_true_only_for_claude_rows() {
        // Anthropic Claude rows → cache_eligible (exact multipliers).
        for m in ["claude-opus-4-7", "claude-sonnet-4-6", "CLAUDE-HAIKU-4-5"] {
            assert!(
                rate_for_model(m).unwrap().cache_eligible,
                "{m} should be cache_eligible"
            );
        }
        // Every other provider row → NOT cache_eligible ($0 cache, fail-loud).
        for m in [
            "gpt-5-codex",
            "gemini-2.5-pro",
            "deepseek-v4-pro",
            "glm-4.6",
            "minimax",
        ] {
            assert!(
                !rate_for_model(m).unwrap().cache_eligible,
                "{m} must not be cache_eligible"
            );
        }
        // A locally-named model that matches NO rate row bills nothing at all —
        // cache-eligibility is moot because rate_for_model returns None.
        assert!(rate_for_model("claude3-local-gguf").is_none());
    }

    #[test]
    fn cache_read_is_cheaper_than_cache_write() {
        // Structural: at equal token counts a cache READ (hit) must cost less
        // than a cache WRITE, per the 0.10× vs 1.25× multipliers.
        let rate = rate_for_model("claude-opus-4-7").unwrap();
        let write_only = rate.estimate_usd_with_cache(0, 0, 1_000_000, 0);
        let read_only = rate.estimate_usd_with_cache(0, 0, 0, 1_000_000);
        assert!(
            read_only < write_only,
            "cache read (${read_only}) must be cheaper than cache write (${write_only})"
        );
    }
}
