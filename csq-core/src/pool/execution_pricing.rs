//! Pure conservative accounting over a frozen admission/deadline price interval.
use super::execution::PoolExecRequest;
use crate::providers::model_manifest::{MatchKind, ModelManifest, PeakSchedule, RatePrices};
use chrono::{DateTime, Utc};
use csq_sdk::Completion;

const SECOND: i128 = 1_000_000_000;
const MINUTE: i128 = 60 * SECOND;
const DAY: i128 = 1440 * MINUTE;
const WEEK: i128 = 7 * DAY;

pub(crate) struct Pricing {
    pub hold_nanos: u64,
    pub context: u64,
    model: String,
    served_model_ids: Vec<String>,
    provider: String,
    max_tokens: u64,
    prices: [Option<u64>; 4],
}

pub(crate) fn prepare(
    manifest: &ModelManifest,
    request: &PoolExecRequest,
    admission: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Option<Pricing> {
    // Match literal API ids; picker aliases and selector annotations supply no bound.
    if request.model.contains('[') || request.model.contains('@') {
        return None;
    }
    let model = manifest
        .models
        .iter()
        .find(|model| model.id == request.model)?;
    let provider_matches = match request.provider.as_str() {
        "anthropic" => model.provider == "claude",
        "openai" => matches!(model.provider.as_str(), "openai" | "codex"),
        _ => false,
    };
    let context = model.context_window.filter(|bound| *bound > 0)?;
    let output = model.output_limit.filter(|bound| *bound > 0)?;
    if !provider_matches
        || request.max_tokens == 0
        || request.max_tokens > context
        || request.max_tokens > output
    {
        return None;
    }
    let start = instant_nanos(admission)?;
    let end = instant_nanos(deadline)?.checked_add(1)?;
    if start >= end {
        return None;
    }
    let lower = request.model.to_lowercase();
    // First-rule ownership includes gaps, matching rate_for_model_at's precedence.
    let rule = manifest.rates.iter().find(|rule| {
        let query = if rule.strip_context_hint {
            lower.strip_suffix("[1m]").unwrap_or(&lower)
        } else {
            &lower
        };
        rule.patterns.iter().any(|pattern| match rule.match_kind {
            MatchKind::Exact => query == pattern.to_lowercase(),
            MatchKind::Contains => query.contains(&pattern.to_lowercase()),
        })
    })?;
    let mut clipped = Vec::new();
    for epoch in &rule.epochs {
        let bound = |time: Option<i64>, fallback| -> Option<i128> {
            match time {
                Some(value) => instant_nanos(DateTime::<Utc>::from_timestamp(value, 0)?),
                None => Some(fallback),
            }
        };
        let from = start.max(bound(epoch.start_unix, start)?);
        let until = end.min(bound(epoch.end_unix, end)?);
        if from < until {
            clipped.push((from, until, epoch));
        }
    }
    clipped.sort_unstable_by_key(|(from, _, _)| *from);
    let mut covered = start;
    let mut effective = Vec::new();
    for (from, until, epoch) in clipped {
        if from != covered {
            return None;
        }
        covered = until;
        match &epoch.peak {
            None => effective.push(epoch.rate),
            Some(peak) => {
                let (base_active, peak_active) = schedule_activity(peak, from, until)?;
                if base_active {
                    effective.push(epoch.rate);
                }
                if peak_active {
                    effective.push(peak.rate);
                }
            }
        }
    }
    if covered != end {
        return None;
    }
    let mut rows = effective.into_iter();
    let mut prices = nano_prices(rows.next()?)?;
    let mut input_max = prices
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .filter_map(|(_, price)| *price)
        .max()?;
    for row in rows {
        let next = nano_prices(row)?;
        for (index, value) in next.iter().enumerate() {
            if index != 1 {
                if let Some(value) = value {
                    input_max = input_max.max(*value);
                }
            }
            // Missing in any effective tier stays unknown for that raw dimension.
            prices[index] = prices[index]
                .zip(*value)
                .map(|(left, right)| left.max(right));
        }
    }
    // OpenAI may serve cached input without an explicit cache control in our request.
    if request.provider == "openai" && prices[2].is_none() {
        return None;
    }
    let hold_nanos = total_nanos(&[(context, input_max), (request.max_tokens, prices[1]?)])?;
    Some(Pricing {
        hold_nanos,
        context,
        model: request.model.clone(),
        served_model_ids: model.served_model_ids.clone(),
        provider: request.provider.clone(),
        max_tokens: request.max_tokens,
        prices,
    })
}

impl Pricing {
    pub(crate) fn price_completion(&self, completion: &Completion) -> Option<u64> {
        if completion.provider != self.provider
            || !(completion.model == self.model
                || self
                    .served_model_ids
                    .iter()
                    .any(|id| id == &completion.model))
        {
            return None;
        }
        let usage = completion.usage.as_ref()?;
        let input = usage.input_tokens?;
        let output = usage.output_tokens?;
        let read = usage.cache_read_input_tokens.unwrap_or(0);
        let write = usage.cache_creation_input_tokens.unwrap_or(0);
        if output > self.max_tokens || input > self.context {
            return None;
        }
        let uncached = if self.provider == "openai" {
            if write != 0 {
                return None;
            }
            input.checked_sub(read)?
        } else {
            if input.checked_add(read)?.checked_add(write)? > self.context {
                return None;
            }
            input
        };
        let mut dimensions = [(0, 0); 4];
        for (index, tokens) in [uncached, output, read, write].into_iter().enumerate() {
            dimensions[index] = (tokens, if tokens == 0 { 0 } else { self.prices[index]? });
        }
        let actual = total_nanos(&dimensions)?;
        (actual <= self.hold_nanos).then_some(actual)
    }
}

fn instant_nanos(time: DateTime<Utc>) -> Option<i128> {
    // chrono represents leap seconds with nanoseconds >= 1e9; refuse that ambiguous axis.
    if time.timestamp_subsec_nanos() >= 1_000_000_000 {
        return None;
    }
    i128::from(time.timestamp())
        .checked_mul(SECOND)?
        .checked_add(i128::from(time.timestamp_subsec_nanos()))
}

/// Return which tiers intersect [start,end); short spans visit at most eight UTC days.
fn schedule_activity(peak: &PeakSchedule, start: i128, end: i128) -> Option<(bool, bool)> {
    let mut days = [false; 7];
    for day in &peak.weekdays {
        let index = usize::from(day.checked_sub(1)?);
        if *days.get(index)? {
            return None;
        }
        days[index] = true;
    }
    let mut daily_minutes = 0i128;
    let mut previous = 0;
    for &[from, until] in &peak.windows_utc {
        if from < previous || from >= until || until > 1440 {
            return None;
        }
        daily_minutes = daily_minutes.checked_add(i128::from(until - from))?;
        previous = until;
    }
    let weekly_minutes =
        daily_minutes.checked_mul(days.iter().filter(|day| **day).count() as i128)?;
    let span = end.checked_sub(start)?;
    if span >= WEEK {
        return Some((weekly_minutes < 10080, weekly_minutes > 0));
    }
    let mut peak_nanos = 0i128;
    let first = start.div_euclid(DAY);
    let last = end.checked_sub(1)?.div_euclid(DAY);
    for day in first..=last {
        // UNIX day zero was Thursday; rem_euclid also handles dates before 1970.
        if !days[usize::try_from((day + 3).rem_euclid(7)).ok()?] {
            continue;
        }
        let midnight = day.checked_mul(DAY)?;
        for &[from, until] in &peak.windows_utc {
            let left = start.max(midnight.checked_add(i128::from(from).checked_mul(MINUTE)?)?);
            let right = end.min(midnight.checked_add(i128::from(until).checked_mul(MINUTE)?)?);
            if left < right {
                peak_nanos = peak_nanos.checked_add(right.checked_sub(left)?)?;
            }
        }
    }
    Some((peak_nanos < span, peak_nanos > 0))
}

fn nano_prices(prices: RatePrices) -> Option<[Option<u64>; 4]> {
    let optional = |price| match price {
        Some(value) => Some(Some(price_nanos(value)?)),
        None => Some(None),
    };
    Some([
        Some(price_nanos(prices.input_per_1m_usd)?),
        Some(price_nanos(prices.output_per_1m_usd)?),
        optional(prices.cache_read_per_1m_usd)?,
        optional(prices.cache_write_per_1m_usd)?,
    ])
}

/// Round the exact stored f64 price up to nano-USD per million with integer arithmetic.
fn price_nanos(price: f64) -> Option<u64> {
    if !price.is_finite() || price <= 0.0 || price > 1_000_000.0 {
        return None;
    }
    let bits = price.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as u32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, shift) = if exponent == 0 {
        (fraction, 1074)
    } else {
        (fraction | (1u64 << 52), 1075u32.checked_sub(exponent)?)
    };
    let numerator = u128::from(mantissa).checked_mul(1_000_000_000)?;
    let rounded = if shift >= 128 {
        u128::from(numerator != 0)
    } else {
        let denominator = 1u128 << shift;
        (numerator / denominator).checked_add(u128::from(numerator % denominator != 0))?
    };
    u64::try_from(rounded).ok()
}

fn total_nanos(dimensions: &[(u64, u64)]) -> Option<u64> {
    let numerator = dimensions
        .iter()
        .try_fold(0u128, |total, (tokens, price)| {
            total.checked_add(u128::from(*tokens).checked_mul(u128::from(*price))?)
        })?;
    let rounded = numerator
        .checked_div(1_000_000)?
        .checked_add(u128::from(numerator % 1_000_000 != 0))?;
    u64::try_from(rounded).ok()
}

#[cfg(test)]
#[path = "execution_pricing_tests.rs"]
mod tests;
