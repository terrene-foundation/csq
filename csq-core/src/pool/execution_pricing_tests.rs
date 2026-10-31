use super::*;
use crate::providers::model_manifest::{RateEpoch, RateRule};
use crate::providers::ModelInfo;
use csq_sdk::{FinishReason, Usage};

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}
fn prices(input: f64, output: f64) -> RatePrices {
    RatePrices {
        input_per_1m_usd: input,
        output_per_1m_usd: output,
        cache_read_per_1m_usd: None,
        cache_write_per_1m_usd: None,
    }
}
fn epoch(start: Option<i64>, end: Option<i64>, rate: RatePrices) -> RateEpoch {
    RateEpoch {
        start_unix: start,
        end_unix: end,
        rate,
        peak: None,
    }
}
fn fixture() -> (ModelManifest, PoolExecRequest) {
    let manifest = ModelManifest {
        schema_version: 1,
        revision: "synthetic-pricing".into(),
        models: vec![ModelInfo {
            id: "fixture".into(),
            name: "Fixture".into(),
            provider: "claude".into(),
            context_window: Some(1000),
            output_limit: Some(100),
            aliases: vec!["alias".into()],
            served_model_ids: vec![],
        }],
        rates: vec![RateRule {
            match_kind: MatchKind::Exact,
            patterns: vec!["fixture".into()],
            strip_context_hint: false,
            evidence: "Synthetic local accounting".into(),
            epochs: vec![epoch(None, None, prices(1.0, 2.0))],
        }],
    };
    manifest.validate().unwrap();
    let request = PoolExecRequest {
        provider: "anthropic".into(),
        model: "fixture".into(),
        prompt: "x".into(),
        system: None,
        max_tokens: 10,
        max_input_bytes: 200000,
        timeout_secs: 30,
    };
    (manifest, request)
}
fn usage(input: u64, output: u64, read: u64, write: u64) -> Completion {
    Completion::new("answer", "fixture", "anthropic", FinishReason::Stop).with_usage(
        Usage::default()
            .with_input_tokens(input)
            .with_output_tokens(output)
            .with_cache_read_input_tokens(read)
            .with_cache_creation_input_tokens(write),
    )
}
fn window(manifest: &ModelManifest, request: &PoolExecRequest, start: &str, end: &str) -> Pricing {
    prepare(manifest, request, at(start), at(end)).unwrap()
}

#[test]
fn interval_excludes_outside_epochs_and_settles_on_its_own_maxima() {
    let (mut m, r) = fixture();
    let cut = at("2026-10-26T00:00:10Z").timestamp();
    m.rates[0].epochs = vec![
        epoch(None, Some(cut), prices(1.0, 2.0)),
        epoch(Some(cut), None, prices(3.0, 4.0)),
    ];
    let low = window(
        &m,
        &r,
        "2026-10-26T00:00:00Z",
        "2026-10-26T00:00:09.999999999Z",
    );
    assert_eq!(low.hold_nanos, 1_020_000);
    assert_eq!(low.price_completion(&usage(1, 1, 0, 0)), Some(3000));
    let crossing = window(&m, &r, "2026-10-26T00:00:00Z", "2026-10-26T00:00:10Z");
    assert_eq!(crossing.hold_nanos, 3_040_000);
    assert_eq!(crossing.price_completion(&usage(1, 1, 0, 0)), Some(7000));
    m.rates[0].epochs[0].rate = prices(9.0, 10.0);
    let future = window(&m, &r, "2026-10-26T00:00:10Z", "2026-10-26T00:00:11Z");
    assert_eq!(future.hold_nanos, 3_040_000);
    assert_eq!(low.price_completion(&usage(1, 1, 0, 0)), Some(3000));
}

#[test]
fn dated_served_identity_requires_explicit_frozen_row_authorization() {
    for openai in [false, true] {
        let (mut manifest, mut request) = fixture();
        if openai {
            manifest.models[0].provider = "codex".into();
            manifest.rates[0].epochs[0].rate.cache_read_per_1m_usd = Some(0.5);
            request.provider = "openai".into();
        }
        let dated = "fixture-20261026";
        manifest.models[0].aliases.push(dated.into());
        let instant = at("2026-10-26T00:00:00Z");
        let mut response = usage(1, 1, 0, 0);
        response.provider = request.provider.clone();
        response.model = dated.into();
        assert!(
            prepare(&manifest, &request, instant, instant)
                .unwrap()
                .price_completion(&response)
                .is_none(),
            "picker aliases authorize no served identity"
        );
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["models"][0]["served_model_ids"] = serde_json::json!([dated]);
        manifest = ModelManifest::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        let admitted = prepare(&manifest, &request, instant, instant).unwrap();
        assert_eq!(admitted.price_completion(&response), Some(3000));
        value["models"][0]["served_model_ids"] = serde_json::json!([]);
        manifest = ModelManifest::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            admitted.price_completion(&response),
            Some(3000),
            "admitted snapshot is frozen"
        );
        assert!(prepare(&manifest, &request, instant, instant)
            .unwrap()
            .price_completion(&response)
            .is_none());
        for wrong in [
            "Fixture-20261026",
            "fixture-20261027",
            "fixture-20261026[1m]",
        ] {
            response.model = wrong.into();
            assert!(admitted.price_completion(&response).is_none());
        }
        response.model = dated.into();
        response.provider = "other".into();
        assert!(admitted.price_completion(&response).is_none());
        let mut served_request = request.clone();
        served_request.model = dated.into();
        assert!(prepare(&manifest, &served_request, instant, instant).is_none());
    }
}

#[test]
fn coverage_rejects_interior_past_and_closed_deadline_gaps_without_later_rule_fallback() {
    let (mut m, r) = fixture();
    let t = at("2026-10-26T00:00:00Z");
    let second = t.timestamp();
    let mut fallback = m.rates[0].clone();
    fallback.match_kind = MatchKind::Contains;
    m.rates.push(fallback);
    for epochs in [
        vec![
            epoch(None, Some(second + 5), prices(1.0, 2.0)),
            epoch(Some(second + 6), None, prices(1.0, 2.0)),
        ],
        vec![epoch(Some(second + 1), None, prices(1.0, 2.0))],
        vec![epoch(None, Some(second + 10), prices(1.0, 2.0))],
    ] {
        m.rates[0].epochs = epochs;
        m.validate().unwrap();
        assert!(prepare(&m, &r, t, t + chrono::Duration::seconds(10)).is_none());
    }
    assert!(prepare(&m, &r, t, t - chrono::Duration::nanoseconds(1)).is_none());
}

#[test]
fn peak_entry_exit_day_and_weekly_coverage_include_only_effective_prices() {
    let (mut m, r) = fixture();
    m.rates[0].epochs[0].peak = Some(PeakSchedule {
        weekdays: vec![1],
        windows_utc: vec![[60, 120]],
        rate: prices(3.0, 4.0),
    });
    for (start, end, expected) in [
        (
            "2026-10-26T00:59:59Z",
            "2026-10-26T00:59:59.999999999Z",
            1_020_000,
        ),
        ("2026-10-26T00:59:59Z", "2026-10-26T01:00:00Z", 3_040_000),
        ("2026-10-26T01:59:59Z", "2026-10-26T02:00:00Z", 3_040_000),
        ("2026-10-26T02:00:00Z", "2026-10-26T02:00:01Z", 1_020_000),
        ("2026-10-27T01:00:00Z", "2026-10-27T01:30:00Z", 1_020_000),
        ("2026-10-25T23:59:59Z", "2026-10-26T01:00:00Z", 3_040_000),
        ("2026-10-27T02:00:00Z", "2026-11-03T02:00:00Z", 3_040_000),
    ] {
        assert_eq!(window(&m, &r, start, end).hold_nanos, expected);
    }
    m.rates[0].epochs[0].rate = prices(9.0, 10.0);
    assert_eq!(
        window(&m, &r, "2026-10-26T01:00:00Z", "2026-10-26T01:59:59Z").hold_nanos,
        3_040_000
    );
    let peak = m.rates[0].epochs[0].peak.as_mut().unwrap();
    peak.weekdays = (1..=7).collect();
    peak.windows_utc = vec![[0, 720], [720, 1440]];
    assert_eq!(
        prepare(&m, &r, DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC)
            .unwrap()
            .hold_nanos,
        3_040_000
    );
}

#[test]
fn cache_dimensions_use_independent_interval_maxima_and_keep_missing_prices_missing() {
    let (mut m, r) = fixture();
    let cut = at("2026-10-26T00:00:10Z").timestamp();
    let mut first = prices(1.0, 2.0);
    first.cache_read_per_1m_usd = Some(0.5);
    first.cache_write_per_1m_usd = Some(4.0);
    let mut next = prices(3.0, 1.0);
    next.cache_read_per_1m_usd = Some(2.0);
    next.cache_write_per_1m_usd = Some(1.0);
    m.rates[0].epochs = vec![epoch(None, Some(cut), first), epoch(Some(cut), None, next)];
    let p = window(&m, &r, "2026-10-26T00:00:00Z", "2026-10-26T00:00:10Z");
    assert_eq!(p.hold_nanos, 4_020_000);
    assert_eq!(p.price_completion(&usage(2, 1, 3, 4)), Some(30_000));
    assert_eq!(
        p.price_completion(&usage(0, 10, 0, 1000)),
        Some(p.hold_nanos)
    );
    m.rates[0].epochs[1].rate.cache_read_per_1m_usd = None;
    let p = window(&m, &r, "2026-10-26T00:00:00Z", "2026-10-26T00:00:10Z");
    assert!(p.price_completion(&usage(2, 1, 3, 0)).is_none());
    assert_eq!(p.price_completion(&usage(2, 1, 0, 0)), Some(8000));
}

#[test]
fn openai_raw_input_includes_cache_and_anthropic_dimensions_are_disjoint() {
    let (mut m, mut r) = fixture();
    m.rates[0].epochs[0].rate.cache_read_per_1m_usd = Some(0.5);
    m.rates[0].epochs[0].rate.cache_write_per_1m_usd = Some(1.25);
    let p = window(&m, &r, "2026-10-26T00:00:00Z", "2026-10-26T00:00:30Z");
    assert_eq!(p.price_completion(&usage(5, 2, 3, 2)), Some(13_000));
    assert!(p.price_completion(&usage(999, 1, 2, 0)).is_none());
    m.models[0].provider = "codex".into();
    r.provider = "openai".into();
    let p = window(&m, &r, "2026-10-26T00:00:00Z", "2026-10-26T00:00:30Z");
    let mut c = usage(5, 2, 3, 0);
    c.provider = "openai".into();
    assert_eq!(p.price_completion(&c), Some(7500));
    c.usage.as_mut().unwrap().cache_read_input_tokens = Some(6);
    assert!(p.price_completion(&c).is_none());
    c.usage.as_mut().unwrap().cache_read_input_tokens = Some(0);
    c.usage.as_mut().unwrap().cache_creation_input_tokens = Some(1);
    assert!(p.price_completion(&c).is_none());
}

#[test]
fn openai_automatic_cache_requires_known_price_throughout_the_interval() {
    let (mut m, mut r) = fixture();
    m.models[0].provider = "codex".into();
    r.provider = "openai".into();
    let start = at("2026-10-26T00:00:00Z");
    let end = at("2026-10-26T00:00:10Z");
    assert!(prepare(&m, &r, start, end).is_none());
    m.rates[0].epochs[0].rate.cache_read_per_1m_usd = Some(0.5);
    assert!(prepare(&m, &r, start, end).is_some());
    m.rates[0].epochs[0].end_unix = Some(end.timestamp());
    m.rates[0]
        .epochs
        .push(epoch(Some(end.timestamp()), None, prices(1.0, 2.0)));
    assert!(prepare(&m, &r, start, end).is_none());
}

#[test]
fn identity_bounds_and_required_usage_refuse_unsupported_or_inconsistent_accounting() {
    let (mut m, r) = fixture();
    let t = at("2026-10-26T00:00:00Z");
    for case in 0..8 {
        let mut bad = r.clone();
        match case {
            0 => bad.model = "alias".into(),
            1 => bad.model = "fixture[1m]".into(),
            2 => bad.provider = "openai".into(),
            3 => bad.max_tokens = 0,
            4 => bad.max_tokens = 101,
            5 => bad.max_tokens = 1001,
            6 => bad.model = "Fixture".into(),
            _ => bad.provider = "other".into(),
        }
        assert!(prepare(&m, &bad, t, t).is_none());
    }
    let p = prepare(&m, &r, t, t).unwrap();
    let leap = at("2016-12-31T23:59:60Z");
    assert!(prepare(&m, &r, leap, leap).is_none());
    assert_eq!(p.context, 1000);
    for case in 0..7 {
        let mut c = usage(1, 1, 0, 0);
        match case {
            0 => c.model = "alias".into(),
            1 => c.provider = "openai".into(),
            2 => c.usage = None,
            3 => c.usage.as_mut().unwrap().input_tokens = None,
            4 => c.usage.as_mut().unwrap().output_tokens = None,
            5 => c.usage.as_mut().unwrap().output_tokens = Some(11),
            _ => c.usage.as_mut().unwrap().input_tokens = Some(1001),
        }
        assert!(p.price_completion(&c).is_none());
    }
    for bound in [None, Some(0)] {
        m.models[0].context_window = bound;
        assert!(prepare(&m, &r, t, t).is_none());
    }
    m.models[0].context_window = Some(1000);
    m.models[0].output_limit = None;
    assert!(prepare(&m, &r, t, t).is_none());
}

#[test]
fn exact_integer_rounding_positive_prices_missing_and_overflow_are_distinct() {
    assert_eq!(price_nanos(f64::from_bits(1)), Some(1));
    assert_eq!(price_nanos(0.1), Some(100_000_001));
    for price in [f64::NAN, f64::INFINITY, -1.0, 0.0, -0.0, 1_000_001.0] {
        assert!(price_nanos(price).is_none());
    }
    assert_eq!(total_nanos(&[(1, 1)]), Some(1));
    assert!(total_nanos(&[(u64::MAX, u64::MAX), (u64::MAX, u64::MAX)]).is_none());
    let (mut m, r) = fixture();
    let t = at("2026-10-26T00:00:00Z");
    m.rates[0].epochs[0].rate = prices(0.0, 0.0);
    m.rates[0].epochs[0].rate.cache_read_per_1m_usd = Some(0.0);
    assert!(prepare(&m, &r, t, t).is_none());
    m.rates[0].epochs[0].rate = prices(1e-300, 1e-300);
    m.rates[0].epochs[0].rate.cache_read_per_1m_usd = Some(1e-300);
    m.models[0].context_window = Some(u64::MAX);
    let p = prepare(&m, &r, t, t).unwrap();
    assert!(p.price_completion(&usage(u64::MAX, 0, 1, 0)).is_none());
    m.rates[0].epochs[0].rate = prices(1_000_000.0, 1_000_000.0);
    assert!(prepare(&m, &r, t, t).is_none());
}
