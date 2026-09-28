//! Cost arithmetic and pure bundled-rate compatibility lookup.
//!
//! Model metadata and all rate data now live in the versioned JSON model
//! manifest. Runtime aggregation loads a complete snapshot from its explicit
//! base directory; no build or daemon restart is needed for subsequent data
//! updates. This module retains the public `CostRate` arithmetic contract.
//!
//! Estimates use the transcript-selected model (configured fallback if absent)
//! and SESSION START, not billing-exact per-turn attribution. Session boundary
//! approximations and nullable cache prices are unchanged. Unknown models or
//! missing time for dated pricing stay `None`, rather than invented rates.

use chrono::{DateTime, Utc};

/// Cost rate for one model. `input`/`output` fields are USD per 1,000,000
/// tokens. The two cache fields hold that row's own prompt-cache PRICES, in the
/// same unit — not multipliers, and not derived from any other field at billing
/// time (an internal ticket).
///
/// `None` means "no verified price for this row", which bills that cache
/// dimension at $0 — the module's fail-loud contract: csq does not guess a price
/// it has not read from the vendor. Read and write are separate `Option`s
/// because a vendor may publish one and not the other, which is exactly the
/// current DeepSeek situation (cache-HIT published, cache-WRITE not).
///
/// **Why prices and not multipliers.** The prior model billed cache as a global
/// multiple of the row's input rate ([`CACHE_READ_INPUT_MULTIPLIER`] = 0.10).
/// Measured against published prices, one constant cannot fit: it over-bills
/// DeepSeek by 3.0× and under-bills Z.AI by 1.86× — opposite directions, so no
/// constant is simultaneously too high and too low. Nor is a per-PROVIDER
/// constant enough: DeepSeek v4-pro's own cache ratio is 1/120 before its
/// 2026-08-16 cutover and 1/30 after. The price therefore has to be per-ROW
/// data, which is what this struct now carries — and because a row is already
/// selected per time tier by the manifest, peak/off-peak cache pricing
/// follows with no change to that type.
///
/// Cache-eligibility remains keyed on the matched rate ROW (not a separate
/// model-name check), so a model matching no row is billed nothing at all.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostRate {
    pub input_per_1m_usd: f64,
    pub output_per_1m_usd: f64,
    /// USD per 1M cache-READ (hit) tokens. `None` = no verified price → $0.
    pub cache_read_per_1m_usd: Option<f64>,
    /// USD per 1M cache-WRITE (creation) tokens. `None` = no verified price → $0.
    pub cache_write_per_1m_usd: Option<f64>,
}

impl CostRate {
    /// A rate with no verified cache pricing — cache tokens bill $0.
    pub const fn new(input: f64, output: f64) -> Self {
        Self {
            input_per_1m_usd: input,
            output_per_1m_usd: output,
            cache_read_per_1m_usd: None,
            cache_write_per_1m_usd: None,
        }
    }

    /// A rate whose cache prices follow Anthropic's published RELATION to the
    /// base input rate: write at [`CACHE_WRITE_INPUT_MULTIPLIER`], read at
    /// [`CACHE_READ_INPUT_MULTIPLIER`]. Anthropic Claude rows only, where that
    /// relation is exact.
    ///
    /// The multipliers are applied HERE, once, at table-construction time —
    /// they are a property of how Anthropic publishes its prices, not of how
    /// csq bills cache. Every Claude row keeps exactly the prices it billed
    /// before an internal ticket; this constructor's meaning is unchanged.
    pub const fn with_cache(input: f64, output: f64) -> Self {
        Self {
            input_per_1m_usd: input,
            output_per_1m_usd: output,
            cache_read_per_1m_usd: Some(input * CACHE_READ_INPUT_MULTIPLIER),
            cache_write_per_1m_usd: Some(input * CACHE_WRITE_INPUT_MULTIPLIER),
        }
    }

    /// A rate whose cache-READ price is published outright and bears no fixed
    /// relation to the input rate, and whose cache-WRITE price is NOT published.
    ///
    /// The asymmetry is deliberate and is the honest state, not an oversight:
    /// DeepSeek publishes a cache-hit price but no cache-write price. Inferring
    /// one from the shape of the pricing page would be a guess, and a wrong
    /// guess here OVER-bills the user. `None` bills cache-write at $0, which is
    /// the same under-report csq has always had on that dimension — strictly no
    /// worse than today, and it invents nothing.
    pub const fn with_cache_read_only(input: f64, output: f64, cache_read: f64) -> Self {
        Self {
            input_per_1m_usd: input,
            output_per_1m_usd: output,
            cache_read_per_1m_usd: Some(cache_read),
            cache_write_per_1m_usd: None,
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

    /// Estimate the cost in USD including prompt-cache tokens (an internal ticket).
    ///
    /// Cache-write (`cache_creation_input_tokens`) and cache-read
    /// (`cache_read_input_tokens`) are billed at this row's OWN stored prices.
    /// A dimension with no verified price ([`None`]) contributes $0.
    ///
    /// Two identities hold, and both are asserted by tests:
    /// - zero cache tokens ⇒ exactly [`Self::estimate_usd`], so sessions with no
    ///   cache activity never move;
    /// - both cache prices `None` ⇒ exactly [`Self::estimate_usd`] for ANY token
    ///   counts, which is what lets the caller drop its `cache_eligible` branch
    ///   and call this unconditionally.
    pub fn estimate_usd_with_cache(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        cache_creation_tokens: u64,
        cache_read_tokens: u64,
    ) -> f64 {
        let base = self.estimate_usd(input_tokens, output_tokens);
        let write = (cache_creation_tokens as f64) * self.cache_write_per_1m_usd.unwrap_or(0.0)
            / 1_000_000.0;
        let read =
            (cache_read_tokens as f64) * self.cache_read_per_1m_usd.unwrap_or(0.0) / 1_000_000.0;
        base + write + read
    }
}

/// How ANTHROPIC publishes its prompt-cache prices, expressed as multiples of
/// the base input rate (5-minute TTL): a cache WRITE costs 1.25× and a cache
/// READ (hit) costs 0.10× that row's input rate.
///
/// **Scope — read this before reusing them.** These describe *Anthropic's
/// price list*, not csq's billing rule. They are consumed in exactly one place,
/// [`CostRate::with_cache`], which multiplies them out at table-construction
/// time into the stored `cache_read_per_1m_usd` / `cache_write_per_1m_usd`
/// prices. Billing itself ([`CostRate::estimate_usd_with_cache`]) reads only
/// those stored prices and never touches a multiplier.
///
/// **Do not apply them to a non-Anthropic row.** Cache economics are unrelated
/// across vendors, and a single constant is wrong in BOTH directions at once —
/// measured against published prices, 0.10 over-bills DeepSeek v4-pro by 3.0×
/// (true ratio 1/30) and under-bills Z.AI GLM 5.2 by 1.86× (true ratio 1/5.4).
/// It is not even constant within one vendor: DeepSeek v4-pro is 1/120 before
/// its 2026-08-16 cutover and 1/30 after. That is why prices are stored
/// per-row; see the [`CostRate`] doc. Use [`CostRate::with_cache_read_only`]
/// for a vendor that publishes an outright cache price.
///
/// For a Claude slot, billing cache at these prices remains far closer to true
/// cost than the pre-an internal ticket "cache = $0" model, since cache-read volume routinely
/// dwarfs fresh input on long coding sessions.
///
/// NOTE (known pre-existing limitation): cache pricing is keyed on the matched
/// rate ROW, and [`rate_for_model_at`] itself is provider-blind — a locally-run
/// model whose name coincidentally contains a Claude rate pattern (e.g. an
/// Ollama pull literally named `claude-sonnet-local`) would match a Claude row
/// and be billed at Claude base+cache rates. That mis-attribution predates an internal ticket
/// (it already applied to base input/output billing) and is a
/// `rate_for_model_at` provider-awareness gap, tracked separately.
pub const CACHE_WRITE_INPUT_MULTIPLIER: f64 = 1.25;
/// See [`CACHE_WRITE_INPUT_MULTIPLIER`]. Cache-read (hit) multiplier.
pub const CACHE_READ_INPUT_MULTIPLIER: f64 = 0.10;

/// Historical DeepSeek daily pricing cutover, 2026-08-16T16:00:00Z.
/// Kept for API compatibility and independently pinned by named tests; runtime
/// prices and schedules are data in the selected model manifest.
pub const DEEPSEEK_TIERED_PRICING_START_UNIX: i64 = 1_786_896_000;

/// DeepSeek V4.1 Flash cutover, 2026-09-10T04:00:00Z.
pub const DEEPSEEK_V41_PRICING_START_UNIX: i64 = 1_789_012_800;

/// Pure bundled-price lookup retained for library compatibility. Runtime usage
/// aggregation loads one `ModelManifest` snapshot from its explicit base dir
/// instead. Unknown names or missing timestamps for dated rates return `None`.
pub fn rate_for_model_at(model: &str, at: Option<DateTime<Utc>>) -> Option<CostRate> {
    crate::providers::model_manifest::ModelManifest::bundled().rate_for_model_at(model, at)
}

/// Last bundled verification checkpoint, not the revision of a local manifest.
/// V4.1 Flash was verified 2026-09-14; other rows retain their older evidence
/// boundaries, recorded per rule in `model-rates.builtin.json`.
pub const RATES_AS_OF: &str = "2026-09-14";

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed instants — never `now`-relative (`testing.md` Rule 1; the
    /// cutover is itself a fixed instant, so literals are the natural form).
    fn at(rfc3339: &str) -> Option<DateTime<Utc>> {
        Some(
            DateTime::parse_from_rfc3339(rfc3339)
                .expect("test literal must be valid RFC3339")
                .with_timezone(&Utc),
        )
    }

    /// An instant comfortably before the DeepSeek cutover, used wherever the
    /// test is about a time-INVARIANT row and the instant is irrelevant.
    fn any_instant() -> Option<DateTime<Utc>> {
        at("2026-07-01T12:00:00Z")
    }

    #[test]
    fn rate_for_model_matches_known_families() {
        let t = any_instant();
        assert!(rate_for_model_at("deepseek-v4-pro", t).is_some());
        assert!(rate_for_model_at("deepseek-v4-flash", t).is_some());
        assert!(rate_for_model_at("deepseek-reasoner", t).is_some());
        assert!(rate_for_model_at("deepseek-chat", t).is_some());
        assert!(rate_for_model_at("kimi-k3", t).is_some());
        assert!(rate_for_model_at("claude-opus-4-7", t).is_some());
        assert!(rate_for_model_at("claude-sonnet-4-6", t).is_some());
        assert!(rate_for_model_at("gpt-5", t).is_some());
        assert!(rate_for_model_at("gemini-2.5-pro", t).is_some());
        assert!(rate_for_model_at("gemini-2.5-flash", t).is_some());
        assert!(rate_for_model_at("glm-4.6", t).is_some());
    }

    #[test]
    fn rate_for_model_case_insensitive() {
        let t = any_instant();
        assert_eq!(
            rate_for_model_at("deepseek-chat", t),
            rate_for_model_at("DeepSeek-Chat", t)
        );
        assert_eq!(
            rate_for_model_at("CLAUDE-OPUS-4-7", t),
            rate_for_model_at("claude-opus-4-7", t)
        );
        // Case-insensitivity must survive the time-varying lookup too.
        let peak = at("2026-08-20T02:00:00Z");
        assert_eq!(
            rate_for_model_at("DeepSeek-V4-Pro", peak),
            rate_for_model_at("deepseek-v4-pro", peak)
        );
    }

    #[test]
    fn rate_for_model_unknown_returns_none() {
        let t = any_instant();
        assert!(rate_for_model_at("foobar", t).is_none());
        assert!(rate_for_model_at("", t).is_none());
        assert!(rate_for_model_at("o3-mini", t).is_none()); // not in table
                                                            // deepseek-coder removed (not V4 lineup, no verifiable rate) → n/a.
        assert!(rate_for_model_at("deepseek-coder", t).is_none());
    }

    // Fixed historical instants are intentional: these tests compare vendor
    // pricing epochs, never an expiry against wall-clock now.
    #[test]
    fn deepseek_v41_cutover_is_vendor_2026_09_10_0400z() {
        assert_eq!(
            DEEPSEEK_V41_PRICING_START_UNIX,
            at("2026-09-10T04:00:00Z").unwrap().timestamp()
        );
    }

    #[test]
    fn deepseek_v41_flash_canonical_and_legacy_aliases_use_new_prices() {
        for model in [
            "deepseek-flash",
            "DeepSeek-Flash[1m]",
            "deepseek-v4-flash",
            "deepseek-v4-flash[1m]",
            "deepseek-v4-flash-vision-exp",
        ] {
            for ts in ["2026-09-10T04:00:00Z", "2026-09-14T12:00:00Z"] {
                assert_eq!(
                    rate_for_model_at(model, at(ts)),
                    Some(CostRate::with_cache_read_only(0.15, 0.60, 0.003)),
                    "{model} @ {ts}: canonical and retired Flash IDs use V4.1"
                );
            }
            assert_eq!(
                rate_for_model_at(model, at("2026-09-14T02:00:00Z")),
                Some(CostRate::with_cache_read_only(0.30, 1.20, 0.006)),
                "{model}: weekday peak includes its own cache-hit price"
            );
        }
    }

    #[test]
    fn deepseek_v41_flash_cutover_preserves_historical_legacy_prices() {
        for model in ["deepseek-v4-flash", "deepseek-v4-flash-vision-exp"] {
            assert_eq!(
                rate_for_model_at(model, at("2026-09-10T03:59:59Z")),
                Some(CostRate::with_cache_read_only(0.44, 1.32, 0.014)),
                "{model}: last old-rate second must not be repriced"
            );
            assert_eq!(
                rate_for_model_at(model, at("2026-09-05T02:00:00Z")),
                Some(CostRate::with_cache_read_only(0.44, 1.32, 0.014)),
                "{model}: old DAILY schedule must not become weekday-only"
            );
        }
        assert_eq!(
            rate_for_model_at("deepseek-v4-flash", at("2026-07-04T02:00:00Z")),
            Some(CostRate::with_cache_read_only(0.14, 0.28, 0.0028))
        );
    }

    #[test]
    fn deepseek_v41_flash_weekends_are_off_peak_for_every_utc_hour() {
        for day in ["2026-09-12", "2026-09-13"] {
            for hour in 0..24 {
                let ts = format!("{day}T{hour:02}:30:00Z");
                assert_eq!(
                    rate_for_model_at("deepseek-flash", at(&ts)),
                    Some(CostRate::with_cache_read_only(0.15, 0.60, 0.003)),
                    "{ts}: Saturday and Sunday have no peak hours"
                );
            }
        }
    }

    #[test]
    fn deepseek_v41_flash_weekday_peak_windows_are_half_open() {
        for (clock, peak) in [
            ("00:59:59", false),
            ("01:00:00", true),
            ("03:59:59", true),
            ("04:00:00", false),
            ("05:59:59", false),
            ("06:00:00", true),
            ("09:59:59", true),
            ("10:00:00", false),
        ] {
            let expected = if peak {
                CostRate::with_cache_read_only(0.30, 1.20, 0.006)
            } else {
                CostRate::with_cache_read_only(0.15, 0.60, 0.003)
            };
            for day in [
                "2026-09-14",
                "2026-09-15",
                "2026-09-16",
                "2026-09-17",
                "2026-09-18",
            ] {
                let ts = format!("{day}T{clock}Z");
                assert_eq!(
                    rate_for_model_at("deepseek-flash", at(&ts)),
                    Some(expected),
                    "{ts}"
                );
            }
        }
    }

    #[test]
    fn deepseek_v41_unknown_time_or_model_does_not_guess() {
        assert!(rate_for_model_at("deepseek-flash", at("2026-09-10T03:59:59Z")).is_none());
        for model in [
            "deepseek-flash",
            "deepseek-v4-flash",
            "deepseek-v4-flash-vision-exp",
        ] {
            assert!(rate_for_model_at(model, None).is_none(), "{model}");
        }
        for model in [
            "deepseek-flash-2",
            "deepseek-v4-flash-unknown",
            "deepseek-v4.1-flash",
            "deepseek-pro",
        ] {
            assert!(
                rate_for_model_at(model, at("2026-09-14T02:00:00Z")).is_none(),
                "{model}"
            );
        }
    }

    #[test]
    fn deepseek_v41_does_not_apply_cancelled_pro_retirement() {
        for ts in ["2026-09-14T03:59:59Z", "2026-09-14T06:00:00Z"] {
            assert_eq!(
                rate_for_model_at("deepseek-v4-pro", at(ts)),
                Some(CostRate::with_cache_read_only(1.32, 3.96, 0.044)),
                "{ts}: current vendor docs retain Pro and its prices"
            );
        }
    }

    // ── an internal ticket: DeepSeek peak / off-peak, selected by SESSION time ──────

    #[test]
    fn deepseek_cutover_constant_is_2026_08_16_1600z() {
        // The constant is hand-derived; this is the check that it is the
        // instant the docs name. Falsifying result: any other epoch second.
        let literal = DateTime::parse_from_rfc3339("2026-08-16T16:00:00Z")
            .expect("literal")
            .timestamp();
        assert_eq!(
            DEEPSEEK_TIERED_PRICING_START_UNIX, literal,
            "cutover constant must equal 2026-08-16T16:00:00Z"
        );
    }

    #[test]
    fn deepseek_before_cutover_prices_at_the_old_flat_rate() {
        // A July session — and the last second before the cutover — both bill
        // the pre-cutover flat rate, on BOTH the peak and off-peak side of the
        // daily clock (the schedule does not exist yet, so the hour is moot).
        for ts in [
            "2026-07-04T02:30:00Z", // would be "peak" hour, but pre-cutover
            "2026-07-04T20:30:00Z",
            "2026-08-16T15:59:59Z", // one second before
        ] {
            let r = rate_for_model_at("deepseek-v4-pro", at(ts)).unwrap();
            assert_eq!(
                r,
                CostRate::with_cache_read_only(0.435, 0.87, 0.003625),
                "{ts}: pre-cutover sessions keep the old flat rate"
            );
            let f = rate_for_model_at("deepseek-v4-flash", at(ts)).unwrap();
            assert_eq!(
                f,
                CostRate::with_cache_read_only(0.14, 0.28, 0.0028),
                "{ts}: flash, pre-cutover"
            );
        }
    }

    #[test]
    fn deepseek_after_cutover_peak_hours_price_at_peak() {
        // UTC hours 1,2,3 and 6,7,8,9 are peak. The cutover instant itself
        // (16:00Z) is NOT a peak hour, so it is covered by the off-peak test.
        for ts in [
            "2026-08-17T01:00:00Z", // window start — peak (half-open)
            "2026-08-17T03:59:59Z", // last instant of the first window
            "2026-08-20T06:00:00Z",
            "2026-08-20T09:59:59Z",
        ] {
            assert_eq!(
                rate_for_model_at("deepseek-v4-pro", at(ts)).unwrap(),
                CostRate::with_cache_read_only(1.32, 3.96, 0.044),
                "{ts}: pro must bill the PEAK rate"
            );
            assert_eq!(
                rate_for_model_at("deepseek-v4-flash", at(ts)).unwrap(),
                CostRate::with_cache_read_only(0.44, 1.32, 0.014),
                "{ts}: flash must bill the PEAK rate"
            );
        }
    }

    #[test]
    fn deepseek_after_cutover_off_peak_hours_price_at_off_peak() {
        for ts in [
            "2026-08-16T16:00:00Z", // the cutover instant itself
            "2026-08-17T00:59:59Z", // last instant before the first window
            "2026-08-17T04:00:00Z", // window END is OFF-peak (half-open)
            "2026-08-17T05:30:00Z", // the gap between the two windows
            "2026-08-17T10:00:00Z", // second window END is OFF-peak
            "2026-08-17T23:59:59Z",
        ] {
            assert_eq!(
                rate_for_model_at("deepseek-v4-pro", at(ts)).unwrap(),
                CostRate::with_cache_read_only(0.66, 1.98, 0.022),
                "{ts}: pro must bill the OFF-PEAK rate"
            );
            assert_eq!(
                rate_for_model_at("deepseek-v4-flash", at(ts)).unwrap(),
                CostRate::with_cache_read_only(0.22, 0.66, 0.007),
                "{ts}: flash must bill the OFF-PEAK rate"
            );
        }
    }

    #[test]
    fn deepseek_peak_is_exactly_double_off_peak() {
        // Structural relation published by DeepSeek: off-peak is half of peak.
        // Guards a transcription slip in either column of either row.
        for model in ["deepseek-v4-pro", "deepseek-v4-flash"] {
            let peak = rate_for_model_at(model, at("2026-08-17T02:00:00Z")).unwrap();
            let off = rate_for_model_at(model, at("2026-08-17T12:00:00Z")).unwrap();
            assert!(
                (peak.input_per_1m_usd - 2.0 * off.input_per_1m_usd).abs() < 1e-9,
                "{model}: peak input must be 2× off-peak"
            );
            assert!(
                (peak.output_per_1m_usd - 2.0 * off.output_per_1m_usd).abs() < 1e-9,
                "{model}: peak output must be 2× off-peak"
            );
        }
    }

    #[test]
    fn no_instant_fails_loud_for_time_varying_rows_only() {
        // A time-varying row cannot pick a tier without an instant → `n/a`.
        assert!(
            rate_for_model_at("deepseek-v4-pro", None).is_none(),
            "no timestamp must render n/a, never a guessed tier"
        );
        assert!(rate_for_model_at("deepseek-v4-flash", None).is_none());
        // Time-INVARIANT rows are unaffected — their price does not depend on
        // when, so a missing timestamp must not regress them to n/a.
        assert!(rate_for_model_at("claude-opus-4-7", None).is_some());
        assert!(rate_for_model_at("gpt-5", None).is_some());
        assert!(rate_for_model_at("deepseek-chat", None).is_some());
        assert!(rate_for_model_at("deepseek-reasoner", None).is_some());
    }

    #[test]
    fn retired_deepseek_aliases_stay_flat_at_the_pre_cutover_rate() {
        // Retired 2026-07-24: every session naming them predates the cutover,
        // so they are FLAT and must NOT pick up peak/off-peak — including at
        // an instant that would be peak for a live V4 row.
        for ts in [
            "2026-06-01T02:00:00Z",
            "2026-08-20T02:00:00Z", // peak hour, post-cutover
            "2026-08-20T12:00:00Z",
        ] {
            for model in ["deepseek-chat", "deepseek-reasoner"] {
                assert_eq!(
                    rate_for_model_at(model, at(ts)).unwrap(),
                    CostRate::new(0.14, 0.28),
                    "{model} @ {ts}: retired alias must stay flat"
                );
            }
        }
    }

    #[test]
    fn time_invariant_rows_ignore_the_instant() {
        // Every non-DeepSeek-V4 family must return the identical rate at a
        // pre-cutover instant, a post-cutover peak instant, and a post-cutover
        // off-peak instant. Guards against a future edit accidentally routing
        // another provider through the tiered path.
        for model in [
            "claude-opus-4-7",
            "claude-sonnet-4-6",
            "claude-haiku-4-5",
            "gpt-5-codex",
            "gemini-2.5-pro",
            "kimi-k3",
            "minimax",
            "glm-4.6",
        ] {
            let before = rate_for_model_at(model, at("2026-07-01T02:00:00Z"));
            let peak = rate_for_model_at(model, at("2026-08-20T02:00:00Z"));
            let off = rate_for_model_at(model, at("2026-08-20T12:00:00Z"));
            assert_eq!(before, peak, "{model}: rate must not vary with time");
            assert_eq!(before, off, "{model}: rate must not vary with time");
            assert!(before.is_some(), "{model}: expected a rate row");
        }
    }

    /// C4 (an internal journal entry, issue 3): the native Kimi/Grok CLI surfaces
    /// (`kimi-for-coding` / `grok-4.5`, `providers::native::KIMI` /
    /// `GROK::default_model`) are vendor SUBSCRIPTION products — Kimi
    /// Coding Subscription, Grok's own plan — not pay-per-token APIs. This
    /// bundled manifest intentionally carries NO rate row for either name. Suppression
    /// of per-token cost happens at the `BillingMode::Subscription`
    /// classification (`accounts::discovery::discover_native`), never by
    /// adding a rate here. This test locks that "miss is intentional, not a
    /// gap" invariant against an accidental future addition to
    /// the bundled manifest under a false "fix the n/a" framing — the 3P Bearer
    /// `kimi-k3` row is a DIFFERENT (pay-per-token) product and is
    /// unaffected.
    #[test]
    fn rate_for_model_native_kimi_grok_intentionally_unrated() {
        let t = any_instant();
        assert!(
            rate_for_model_at("kimi-for-coding", t).is_none(),
            "native Kimi's model is a subscription product — must stay unrated"
        );
        assert!(
            rate_for_model_at("grok-4.5", t).is_none(),
            "native Grok's model is a subscription product — must stay unrated"
        );
        // The 3P bearer Kimi provider's model IS rated — confirms the two
        // "kimi" surfaces are correctly distinguished by model name, not
        // conflated into one substring match. The 1M-context catalog id
        // `kimi-k3[1m]` resolves via the same `kimi-k3` substring family.
        assert!(rate_for_model_at("kimi-k3", t).is_some());
        assert!(rate_for_model_at("kimi-k3[1m]", t).is_some());
    }

    #[test]
    fn estimate_usd_matches_public_pricing() {
        // 1M input + 1M output deepseek-v4-pro, PRE-cutover = $0.435 + $0.87
        let rate = rate_for_model_at("deepseek-v4-pro", any_instant()).unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!(
            (cost - 1.305).abs() < 0.001,
            "expected ~$1.305, got ${cost}"
        );

        // Same tokens, POST-cutover peak = $1.32 + $3.96 = $5.28 (4.05× the
        // pre-cutover bill — the silent under-report this fix removes).
        let rate = rate_for_model_at("deepseek-v4-pro", at("2026-08-20T02:00:00Z")).unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!((cost - 5.28).abs() < 0.001, "expected ~$5.28, got ${cost}");

        // Same tokens, POST-cutover off-peak = $0.66 + $1.98 = $2.64.
        let rate = rate_for_model_at("deepseek-v4-pro", at("2026-08-20T12:00:00Z")).unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!((cost - 2.64).abs() < 0.001, "expected ~$2.64, got ${cost}");

        // 1M input + 1M output deepseek-v4-flash = $0.14 + $0.28 = $0.42
        // (retired `deepseek-chat`/`deepseek-reasoner` keep this rate).
        let rate = rate_for_model_at("deepseek-chat", any_instant()).unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!((cost - 0.42).abs() < 0.001, "expected ~$0.42, got ${cost}");

        // 100K input + 50K output claude-sonnet = $0.30 + $0.75 = $1.05
        let rate = rate_for_model_at("claude-sonnet-4-6", any_instant()).unwrap();
        let cost = rate.estimate_usd(100_000, 50_000);
        assert!((cost - 1.05).abs() < 0.001, "expected ~$1.05, got ${cost}");

        // Zero tokens → zero cost.
        let rate = rate_for_model_at("gpt-5", any_instant()).unwrap();
        assert_eq!(rate.estimate_usd(0, 0), 0.0);

        // 1M input + 1M output kimi-k3 = $3.0 + $15.0 = $18.0
        let rate = rate_for_model_at("kimi-k3", any_instant()).unwrap();
        let cost = rate.estimate_usd(1_000_000, 1_000_000);
        assert!((cost - 18.0).abs() < 0.001, "expected ~$18.0, got ${cost}");
    }

    #[test]
    fn rates_table_is_non_empty() {
        // Smoke — guards against accidental wholesale deletion.
        let manifest = crate::providers::model_manifest::ModelManifest::bundled();
        assert!(manifest.rates.len() >= 10);
        assert!(manifest.rates.iter().any(|rule| rule.epochs.len() > 1));
    }

    #[test]
    fn estimate_usd_with_cache_bills_cache_tokens() {
        // claude-sonnet: input 3.00, output 15.00 per 1M.
        //   base  = 100K in ×3/1M   + 50K out ×15/1M = 0.30 + 0.75 = 1.05
        //   write = 200K ×3 ×1.25/1M                  = 0.75
        //   read  = 1M   ×3 ×0.10/1M                  = 0.30
        //   total = 2.10
        let rate = rate_for_model_at("claude-sonnet-4-6", any_instant()).unwrap();
        let cost = rate.estimate_usd_with_cache(100_000, 50_000, 200_000, 1_000_000);
        assert!((cost - 2.10).abs() < 0.001, "expected ~$2.10, got ${cost}");
    }

    #[test]
    fn estimate_usd_with_cache_zero_cache_equals_base() {
        // No cache activity must bill exactly the same as the input+output-only
        // estimate — the no-regression guarantee for an internal ticket.
        for model in ["claude-opus-4-7", "gpt-5", "deepseek-v4-pro", "glm-4.6"] {
            let rate = rate_for_model_at(model, any_instant()).unwrap();
            let base = rate.estimate_usd(123_456, 65_432);
            let with_zero_cache = rate.estimate_usd_with_cache(123_456, 65_432, 0, 0);
            assert_eq!(
                base, with_zero_cache,
                "{model}: zero-cache estimate must equal the base estimate"
            );
        }
    }

    #[test]
    fn cache_prices_are_stored_only_where_published() {
        let t = any_instant();
        // Anthropic Claude rows: both dimensions priced, at Anthropic's
        // published relation to that row's own input rate.
        for m in ["claude-opus-4-7", "claude-sonnet-4-6", "CLAUDE-HAIKU-4-5"] {
            let r = rate_for_model_at(m, t).unwrap();
            assert_eq!(
                r.cache_read_per_1m_usd,
                Some(r.input_per_1m_usd * CACHE_READ_INPUT_MULTIPLIER),
                "{m} cache-read price"
            );
            assert_eq!(
                r.cache_write_per_1m_usd,
                Some(r.input_per_1m_usd * CACHE_WRITE_INPUT_MULTIPLIER),
                "{m} cache-write price"
            );
        }
        // Providers publishing no verified cache price: both `None` → $0.
        for m in [
            "gpt-5-codex",
            "gemini-2.5-pro",
            "kimi-k3",
            "glm-4.6",
            "minimax",
        ] {
            let r = rate_for_model_at(m, t).unwrap();
            assert_eq!(
                r.cache_read_per_1m_usd, None,
                "{m} must have no cache-read price"
            );
            assert_eq!(
                r.cache_write_per_1m_usd, None,
                "{m} must have no cache-write price"
            );
        }
        // A model matching NO rate row bills nothing at all.
        assert!(rate_for_model_at("claude3-local-gguf", t).is_none());
    }

    /// The DeepSeek cache-hit price is per-TIER, so the tier that priced the
    /// base rate must price the cache too. Guards the whole point of an internal ticket:
    /// a single per-provider number could not satisfy this.
    #[test]
    fn deepseek_cache_read_price_follows_the_tier() {
        // (instant, model, expected cache-read price)
        let cases = [
            ("2026-08-01T12:00:00Z", "deepseek-v4-pro", 0.003625), // pre-cutover
            ("2026-08-20T02:00:00Z", "deepseek-v4-pro", 0.044),    // peak
            ("2026-08-20T12:00:00Z", "deepseek-v4-pro", 0.022),    // off-peak
            ("2026-08-01T12:00:00Z", "deepseek-v4-flash", 0.0028),
            ("2026-08-20T02:00:00Z", "deepseek-v4-flash", 0.014),
            ("2026-08-20T12:00:00Z", "deepseek-v4-flash", 0.007),
        ];
        for (ts, model, expected) in cases {
            let r = rate_for_model_at(model, at(ts)).unwrap();
            assert_eq!(
                r.cache_read_per_1m_usd,
                Some(expected),
                "{model} at {ts}: cache-read price must follow the tier"
            );
            // Cache-WRITE is unpublished for DeepSeek and must stay unpriced —
            // guessing it would OVER-bill. See the bundled manifest epochs.
            assert_eq!(
                r.cache_write_per_1m_usd, None,
                "{model} at {ts}: cache-write must stay unpriced"
            );
        }
    }

    /// DeepSeek's cache ratio is NOT Anthropic's, in either direction, and not
    /// even constant within DeepSeek across time. This is the measurement that
    /// makes a stored per-row price necessary rather than a multiplier.
    #[test]
    fn deepseek_cache_ratio_is_not_the_anthropic_multiplier() {
        for (ts, model, want_ratio) in [
            ("2026-08-20T12:00:00Z", "deepseek-v4-pro", 1.0 / 30.0),
            ("2026-08-20T02:00:00Z", "deepseek-v4-pro", 1.0 / 30.0),
            ("2026-08-01T12:00:00Z", "deepseek-v4-pro", 1.0 / 120.0),
        ] {
            let r = rate_for_model_at(model, at(ts)).unwrap();
            let ratio = r.cache_read_per_1m_usd.unwrap() / r.input_per_1m_usd;
            assert!(
                (ratio - want_ratio).abs() < 1e-9,
                "{model} at {ts}: ratio {ratio} != expected {want_ratio}"
            );
            // The whole premise: applying Anthropic's 0.10 here would be wrong,
            // and wrong by a wide margin (≥3× on every DeepSeek row).
            assert!(
                CACHE_READ_INPUT_MULTIPLIER / ratio >= 3.0,
                "{model} at {ts}: Anthropic's multiplier should over-bill by ≥3×"
            );
        }
    }

    /// A row with no verified cache price must bill cache at exactly $0, for
    /// ANY token counts — this identity is what lets `attributed_session_to_event`
    /// call `estimate_usd_with_cache` unconditionally.
    #[test]
    fn unpriced_cache_bills_zero_for_any_token_counts() {
        for m in ["gpt-5", "glm-4.6", "kimi-k3"] {
            let r = rate_for_model_at(m, any_instant()).unwrap();
            assert_eq!(
                r.estimate_usd_with_cache(1_000, 2_000, 9_999_999, 9_999_999),
                r.estimate_usd(1_000, 2_000),
                "{m}: unpriced cache must contribute exactly $0"
            );
        }
    }

    /// Regression for the 2026-08-14 Z.AI under-report correction (vendor
    /// pricing: https://docs.z.ai/guides/overview/pricing). Pins each GLM id
    /// THROUGH `rate_for_model_at` — not by reading manifest fields directly —
    /// so this test is what actually catches the substring-precedence bug
    /// preserved from the former static table: `glm-5.2` must be listed before
    /// the bare `glm` catch-all, or `"glm-5.2[1m]".contains("glm")` would
    /// match the catch-all first and silently return the wrong rate. The
    /// catch-all is deliberately set to the SAME value as `glm-4.6` (not
    /// `glm-5.2`), so an ordering regression that lets `glm-5.2[1m]` fall
    /// through to the catch-all is distinguishable from the correct answer.
    /// GLM has one unbounded flat manifest epoch, so `any_instant()` is
    /// correct and the choice of instant is not itself under test here.
    #[test]
    fn rate_for_model_glm_pins_vendor_rates_in_precedence_order() {
        let t = any_instant();
        let glm_5_2 = rate_for_model_at("glm-5.2[1m]", t).expect("glm-5.2[1m] must resolve");
        assert_eq!(glm_5_2.input_per_1m_usd, 1.40, "glm-5.2 input rate");
        assert_eq!(glm_5_2.output_per_1m_usd, 4.40, "glm-5.2 output rate");

        // The bracket-free alias (`providers::models` catalog entry) must
        // resolve identically to the bracketed default_model id.
        let glm_5_2_bare = rate_for_model_at("glm-5.2", t).expect("glm-5.2 must resolve");
        assert_eq!(glm_5_2_bare, glm_5_2);

        let glm_4_6 = rate_for_model_at("glm-4.6", t).expect("glm-4.6 must resolve");
        assert_eq!(glm_4_6.input_per_1m_usd, 0.60, "glm-4.6 input rate");
        assert_eq!(glm_4_6.output_per_1m_usd, 2.20, "glm-4.6 output rate");

        // Bare "glm" catch-all (unrecognized minor version) — same as 4.6,
        // and MUST differ from 5.2 for this test to discriminate ordering.
        let glm_catchall =
            rate_for_model_at("glm-9.9-unreleased", t).expect("glm catch-all must fire");
        assert_eq!(glm_catchall, glm_4_6);
        assert_ne!(
            glm_catchall, glm_5_2,
            "catch-all and glm-5.2 must diverge, or this test cannot detect \
             glm-5.2 falling through to the catch-all"
        );
    }

    /// Regression for the 2026-08-15 GLM 5.3 default bump (issue: csq's
    /// shipping Z.AI default moved from `glm-5.2[1m]` to `glm-5.3[1m]`, since
    /// Z.AI's own `/v1/messages` endpoint already aliases a `glm-5.2` model
    /// request to `glm-5.3` server-side — probed live 2026-08-15). Pins the
    /// carried-forward rate THROUGH `rate_for_model_at`, mirroring
    /// `rate_for_model_glm_pins_vendor_rates_in_precedence_order` above:
    /// `glm-5.3` must precede the bare `glm` catch-all in manifest rules, or
    /// `"glm-5.3[1m]".to_lowercase().contains("glm")` would match the
    /// catch-all first and silently return $0.60/$2.20 instead of the
    /// carried-forward $1.40/$4.40.
    ///
    /// Historical non-vacuity receipt, before manifest extraction:
    /// (`instrument-discipline.md` MUST-2). Two mutations were applied to the
    /// former `MODEL_RATES` and this test run against each before that table was
    /// restored to its shipped state:
    /// (1) delete the `glm-5.3` row entirely — `glm-5.3[1m]` then falls
    /// through to the bare `glm` catch-all (there is no `glm-5` pattern to
    /// catch it first) and resolves to $0.60/$2.20; the test REDs at
    /// `assert_eq!(glm_5_3.input_per_1m_usd, 1.40, ...)` with `left: 0.6,
    /// right: 1.4`.
    /// (2) move the `glm-5.3` row to AFTER the `glm` catch-all (reordered,
    /// not deleted) — same fall-through, same observed failure: `left: 0.6,
    /// right: 1.4` at the identical assertion. Both confirm the row is
    /// reached ONLY because it precedes the catch-all, not because the
    /// `.expect()` alone would have caught a missing or misordered row.
    #[test]
    fn rate_for_model_glm_5_3_pins_carried_forward_rate() {
        let t = any_instant();
        let glm_5_3 = rate_for_model_at("glm-5.3[1m]", t).expect("glm-5.3[1m] must resolve");
        assert_eq!(glm_5_3.input_per_1m_usd, 1.40, "glm-5.3 input rate");
        assert_eq!(glm_5_3.output_per_1m_usd, 4.40, "glm-5.3 output rate");

        // The bracket-free alias (`providers::models` catalog entry) must
        // resolve identically to the bracketed default_model id.
        let glm_5_3_bare = rate_for_model_at("glm-5.3", t).expect("glm-5.3 must resolve");
        assert_eq!(glm_5_3_bare, glm_5_3);

        // The retained `glm-5.2` alias (existing slot files still pin the
        // bracketed `glm-5.2[1m]` id) must resolve to the SAME carried-forward
        // rate as `glm-5.3` — it is 5.2's own published price, unchanged.
        let glm_5_2 = rate_for_model_at("glm-5.2[1m]", t).expect("glm-5.2[1m] must resolve");
        assert_eq!(
            glm_5_2, glm_5_3,
            "glm-5.2 and glm-5.3 share one carried-forward rate"
        );

        // Bare "glm" catch-all (unrecognized minor version) — MUST differ
        // from 5.3, or this test cannot detect glm-5.3 falling through.
        let glm_catchall =
            rate_for_model_at("glm-9.9-unreleased", t).expect("glm catch-all must fire");
        assert_ne!(
            glm_catchall, glm_5_3,
            "catch-all and glm-5.3 must diverge, or this test cannot detect \
             glm-5.3 falling through to the catch-all"
        );
    }

    #[test]
    fn cache_read_is_cheaper_than_cache_write() {
        // Structural, Anthropic rows: at equal token counts a cache READ (hit)
        // must cost less than a cache WRITE, per the 0.10 vs 1.25 relation.
        let rate = rate_for_model_at("claude-opus-4-7", any_instant()).unwrap();
        let write_only = rate.estimate_usd_with_cache(0, 0, 1_000_000, 0);
        let read_only = rate.estimate_usd_with_cache(0, 0, 0, 1_000_000);
        assert!(
            read_only < write_only,
            "cache read (${read_only}) must be cheaper than cache write (${write_only})"
        );
    }
}
