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

/// Cost rate for one model. Both fields are USD per 1,000,000 tokens.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostRate {
    pub input_per_1m_usd: f64,
    pub output_per_1m_usd: f64,
}

impl CostRate {
    pub const fn new(input: f64, output: f64) -> Self {
        Self {
            input_per_1m_usd: input,
            output_per_1m_usd: output,
        }
    }

    /// Estimate the cost in USD for a session with the given token counts.
    pub fn estimate_usd(&self, input_tokens: u64, output_tokens: u64) -> f64 {
        let i = (input_tokens as f64) * self.input_per_1m_usd / 1_000_000.0;
        let o = (output_tokens as f64) * self.output_per_1m_usd / 1_000_000.0;
        i + o
    }
}

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
    ("claude-opus-4-7", CostRate::new(15.00, 75.00)),
    ("claude-opus-4-6", CostRate::new(15.00, 75.00)),
    ("claude-opus", CostRate::new(15.00, 75.00)),
    ("claude-sonnet-4-7", CostRate::new(3.00, 15.00)),
    ("claude-sonnet-4-6", CostRate::new(3.00, 15.00)),
    ("claude-sonnet", CostRate::new(3.00, 15.00)),
    ("claude-haiku-4-5", CostRate::new(1.00, 5.00)),
    ("claude-haiku", CostRate::new(1.00, 5.00)),
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
    // cache-MISS input price + output price — the estimator bills
    // input_tokens + output_tokens only (cache tokens captured-not-billed, see
    // `attributed_session_to_event`). The former 75%-off promo became the
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
}
