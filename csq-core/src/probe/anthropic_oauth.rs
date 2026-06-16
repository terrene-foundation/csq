//! Cell 01 — Anthropic OAuth probe.
//!
//! Asserts the response from `GET /api/oauth/usage` matches the
//! contract pinned in spec 05 §5.1. Six load-bearing assertions:
//!
//! 1. HTTP status is `200`.
//! 2. Body parses as JSON object.
//! 3. Body has both `five_hour` and `seven_day` keys, each an object.
//! 4. Each window object has `utilization` (f64) AND `resets_at` (RFC3339).
//! 5. `0.0 <= utilization <= 100.0` (the 5800% bug from journal 0028
//!    was a missing-multiply inversion; a value > 100 means a regression).
//! 6. `resets_at` parses as a UTC timestamp in the future (`> now()`).

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SCHEMA_VERSION};
use crate::credentials::AnthropicCredentialFile;
use crate::http;
use crate::types::AccountNum;
use std::time::Instant;

pub(super) const CELL_NAME: &str = "anthropic-oauth";
pub(super) const SPEC_ANCHOR: &str = "05§5.1";
pub(super) const ENDPOINT_URL: &str = "https://api.anthropic.com/api/oauth/usage";
const ANTHROPIC_BETA_HEADER: &str = "oauth-2025-04-20";

pub fn probe(slot: AccountNum, creds: &AnthropicCredentialFile) -> ProbeRecord {
    let token = creds
        .claude_ai_oauth
        .access_token
        .expose_secret()
        .to_string();
    probe_with_token(slot, &token, CELL_NAME, SPEC_ANCHOR)
}

/// Shared probe core. Cell 01 (OAuth) and Cell 02 (API key) both hit
/// `/api/oauth/usage` with a Bearer token; only the cell-name and
/// spec-anchor differ for diagnostic surfacing.
pub(super) fn probe_with_token(
    slot: AccountNum,
    token: &str,
    cell_name: &'static str,
    spec_anchor: &'static str,
) -> ProbeRecord {
    let started = Instant::now();
    let extra_headers = [("Anthropic-Beta", ANTHROPIC_BETA_HEADER)];

    // Use the Node-bridge transport — direct reqwest is body-stripped
    // by Cloudflare on api.anthropic.com (journal csq-v2/0056). Same
    // transport the daemon's usage poller uses.
    let result = http::get_bearer_node(ENDPOINT_URL, token, &extra_headers);
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok((status, body)) => evaluate(slot, status, &body, elapsed_ms, cell_name, spec_anchor),
        Err(transport_err) => fail(
            slot,
            elapsed_ms,
            0,
            "transport: request reached endpoint",
            "request failed before any HTTP status was returned",
            &transport_err,
            None,
            cell_name,
            spec_anchor,
        ),
    }
}

fn evaluate(
    slot: AccountNum,
    status: u16,
    body: &[u8],
    elapsed_ms: u64,
    cell_name: &'static str,
    spec_anchor: &'static str,
) -> ProbeRecord {
    // Assertion 1: HTTP 200.
    if status != 200 {
        return fail(
            slot,
            elapsed_ms,
            0,
            "A1: HTTP status is 200",
            &format!("HTTP {status}"),
            match status {
                401 => "401 — access token is expired or invalid; the daemon refresher is responsible for keeping this fresh. Run `csq daemon status` and check refresher logs.",
                429 => "429 — rate limited by Anthropic. Wait and retry; not a code regression.",
                403 => "403 — token lacks the `oauth-2025-04-20` beta scope. Re-login the slot.",
                _ => "non-200 status from /api/oauth/usage. Check the daemon refresher logs and Anthropic status page.",
            },
            Some(body),
            cell_name,
            spec_anchor,
        );
    }

    // Assertion 2: body parses as JSON object.
    let json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                slot,
                elapsed_ms,
                1,
                "A2: body parses as JSON",
                &format!("parse error: {e}"),
                "spec 05 §5.1 requires a JSON object body. Cloudflare body-stripping or upstream HTML error pages produce this failure.",
                Some(body),
                cell_name,
                spec_anchor,
            );
        }
    };
    if !json.is_object() {
        return fail(
            slot,
            elapsed_ms,
            1,
            "A2: body parses as JSON object",
            &format!("got JSON {}", json_kind(&json)),
            "spec 05 §5.1 requires an object, not an array or scalar.",
            Some(body),
            cell_name,
            spec_anchor,
        );
    }

    // Assertion 3: both `five_hour` and `seven_day` keys present + objects.
    let five_hour = match json.get("five_hour").filter(|v| v.is_object()) {
        Some(v) => v,
        None => {
            return fail(
                slot,
                elapsed_ms,
                2,
                "A3: body has `five_hour` object",
                &format!("top-level keys: {}", top_keys(&json)),
                "spec 05 §5.1 requires both `five_hour` and `seven_day` window objects.",
                Some(body),
                cell_name,
                spec_anchor,
            );
        }
    };
    let seven_day = match json.get("seven_day").filter(|v| v.is_object()) {
        Some(v) => v,
        None => {
            return fail(
                slot,
                elapsed_ms,
                2,
                "A3: body has `seven_day` object",
                &format!("top-level keys: {}", top_keys(&json)),
                "spec 05 §5.1 requires both `five_hour` and `seven_day` window objects.",
                Some(body),
                cell_name,
                spec_anchor,
            );
        }
    };

    // Assertions 4-6 run per window. Both windows must pass.
    if let Err(d) = check_window(five_hour, "five_hour") {
        return ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: cell_name,
            spec_anchor,
            status: ProbeStatus::Fail,
            endpoint: ENDPOINT_URL.to_string(),
            elapsed_ms,
            assertions_passed: 3,
            assertions_total: 6,
            diagnostic: Some(d),
            redacted_response_excerpt: Some(redact_excerpt(body)),
        };
    }
    if let Err(d) = check_window(seven_day, "seven_day") {
        return ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: cell_name,
            spec_anchor,
            status: ProbeStatus::Fail,
            endpoint: ENDPOINT_URL.to_string(),
            elapsed_ms,
            assertions_passed: 4,
            assertions_total: 6,
            diagnostic: Some(d),
            redacted_response_excerpt: Some(redact_excerpt(body)),
        };
    }

    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: cell_name,
        spec_anchor,
        status: ProbeStatus::Ok,
        endpoint: ENDPOINT_URL.to_string(),
        elapsed_ms,
        assertions_passed: 6,
        assertions_total: 6,
        diagnostic: None,
        redacted_response_excerpt: None,
    }
}

fn check_window(window: &serde_json::Value, label: &str) -> Result<(), ProbeDiagnostic> {
    // A4: `utilization` is f64. `resets_at` is string OR null (null
    // when utilization is 0 — round-1 redteam discovery, spec 05 §5.1
    // amended 2026-05-07).
    let util = window
        .get("utilization")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ProbeDiagnostic {
            failed_assertion: format!("A4: {label}.utilization is f64"),
            observed_shape: format!("{label} = {}", json_kind(window)),
            hint: "spec 05 §5.1: `utilization` MUST be a non-null number.".into(),
        })?;

    // A5: 0.0 <= utilization <= 100.0.
    if !(0.0..=100.0).contains(&util) {
        return Err(ProbeDiagnostic {
            failed_assertion: format!("A5: 0.0 <= {label}.utilization <= 100.0"),
            observed_shape: format!("{label}.utilization = {util}"),
            hint: "spec 05 §5.1: utilization is a percentage (0-100), not a fraction (0-1). A value > 100 is the journal-0028 5800% regression class.".into(),
        });
    }

    // A6: resets_at parses to UTC and is in the future, EXCEPT when
    // utilization is 0 — Anthropic returns null `resets_at` for
    // zero-usage windows because no reset is scheduled. Spec 05 §5.1
    // amendment (round-1 redteam drift discovery 2026-05-07).
    let resets_field = window.get("resets_at");
    if util == 0.0 && resets_field.map(|v| v.is_null()).unwrap_or(true) {
        return Ok(());
    }
    let resets_str =
        resets_field
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProbeDiagnostic {
                failed_assertion: format!("A4: {label}.resets_at is string (when utilization > 0)"),
                observed_shape: format!(
                    "{label}.utilization = {util}; resets_at = {}",
                    json_kind(resets_field.unwrap_or(&serde_json::Value::Null))
                ),
                hint: "spec 05 §5.1: `resets_at` MUST be an RFC3339 string when utilization is non-zero. Null is only permitted on zero-usage windows.".into(),
            })?;
    let resets_epoch = parse_iso8601_to_epoch(resets_str).ok_or_else(|| ProbeDiagnostic {
        failed_assertion: format!("A6: {label}.resets_at parses as UTC RFC3339"),
        observed_shape: format!("{label}.resets_at = {resets_str:?}"),
        hint: "spec 05 §5.1: timestamps must be UTC (`Z` or `+00:00` suffix).".into(),
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if resets_epoch <= now {
        return Err(ProbeDiagnostic {
            failed_assertion: format!("A6: {label}.resets_at > now()"),
            observed_shape: format!(
                "{label}.resets_at = {resets_str} ({resets_epoch} epoch); now = {now} epoch"
            ),
            hint: "reset time is in the past — either clock skew or the response is stale (cached upstream?).".into(),
        });
    }

    Ok(())
}

/// Minimal RFC 3339 parser, mirroring
/// `daemon::usage_poller::anthropic::parse_iso8601_to_epoch`. Kept
/// duplicated here because the daemon's parser is `pub(crate)` and
/// scoped to the poller module; centralizing it would be a separate
/// refactor (see spec 11 §11.7 follow-up).
///
/// Round-2 redteam C4: re-exported `pub(super)` so `gemini_local`
/// can replace its 365.25-day-approximation `current_utc_year()`
/// year-comparison with an exact epoch-vs-now comparison.
pub(super) fn parse_iso8601_to_epoch(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00"))?;
    let s = match s.find('.') {
        Some(dot) => &s[..dot],
        None => s,
    };
    // YYYY-MM-DDTHH:MM:SS — 19 chars exactly.
    if s.len() != 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    let second: u32 = s.get(17..19)?.parse().ok()?;
    days_from_civil(year, month, day).map(|days| {
        let secs = days * 86400 + (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);
        if secs < 0 {
            0
        } else {
            secs as u64
        }
    })
}

/// Howard Hinnant's date algorithm: civil date -> days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u64;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (d as i64) - 1;
    let doe = yoe as i64 * 365 + (yoe / 4) as i64 - (yoe / 100) as i64 + doy;
    Some(era * 146097 + doe - 719468)
}

#[allow(clippy::too_many_arguments)]
fn fail(
    slot: AccountNum,
    elapsed_ms: u64,
    assertions_passed: u32,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
    body: Option<&[u8]>,
    cell_name: &'static str,
    spec_anchor: &'static str,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: cell_name,
        spec_anchor,
        status: ProbeStatus::Fail,
        endpoint: ENDPOINT_URL.to_string(),
        elapsed_ms,
        assertions_passed,
        assertions_total: 6,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed_assertion.to_string(),
            observed_shape: observed_shape.to_string(),
            hint: hint.to_string(),
        }),
        redacted_response_excerpt: body.map(redact_excerpt),
    }
}

fn redact_excerpt(body: &[u8]) -> String {
    crate::error::redact_excerpt(body, 256)
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn top_keys(v: &serde_json::Value) -> String {
    v.as_object()
        .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| "<not an object>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_evaluate(body: serde_json::Value, status: u16) -> ProbeRecord {
        let bytes = serde_json::to_vec(&body).unwrap();
        evaluate(
            AccountNum::try_from(1).unwrap(),
            status,
            &bytes,
            100,
            CELL_NAME,
            SPEC_ANCHOR,
        )
    }

    #[test]
    fn ok_when_response_matches_contract() {
        let future = chrono_like_iso(7 * 86400);
        let r = run_evaluate(
            json!({
                "five_hour": {"utilization": 42.0, "resets_at": future.clone()},
                "seven_day": {"utilization": 15.0, "resets_at": future},
            }),
            200,
        );
        assert_eq!(r.status, ProbeStatus::Ok);
        assert_eq!(r.assertions_passed, 6);
        assert!(r.diagnostic.is_none());
    }

    #[test]
    fn fail_on_non_200_status() {
        let r = run_evaluate(json!({}), 401);
        assert_eq!(r.status, ProbeStatus::Fail);
        assert_eq!(r.assertions_passed, 0);
        assert!(r.diagnostic.unwrap().hint.contains("401"));
    }

    #[test]
    fn fail_on_utilization_above_100() {
        let future = chrono_like_iso(86400);
        let r = run_evaluate(
            json!({
                "five_hour": {"utilization": 5800.0, "resets_at": future.clone()},
                "seven_day": {"utilization": 15.0, "resets_at": future},
            }),
            200,
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        // A1 ok, A2 ok, A3 ok, A4 ok, A5 fails on five_hour.
        assert_eq!(r.assertions_passed, 3);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A5"));
        assert!(d.hint.contains("journal-0028"));
    }

    /// Round-1 redteam round-1 amendment (spec 05 §5.1, dated 2026-05-07):
    /// Anthropic returns `resets_at: null` on zero-utilization windows.
    /// `check_window` early-returns Ok in that case. This test pins the
    /// carve-out so a future refactor cannot silently re-introduce the
    /// FAIL on healthy zero-usage accounts. Round-2 redteam C1.
    #[test]
    fn ok_when_zero_utilization_carries_null_resets_at() {
        let future = chrono_like_iso(7 * 86400);
        let r = run_evaluate(
            json!({
                "five_hour": {"utilization": 0.0, "resets_at": null},
                "seven_day": {"utilization": 15.0, "resets_at": future},
            }),
            200,
        );
        assert_eq!(r.status, ProbeStatus::Ok);
        assert!(r.diagnostic.is_none());
    }

    /// Companion to `ok_when_zero_utilization_carries_null_resets_at`:
    /// the carve-out only fires when utilization IS zero. A non-zero
    /// utilization with null `resets_at` is still a contract violation
    /// (spec 05 §5.1: "MUST be an RFC3339 string when utilization is
    /// non-zero"). Round-2 redteam C1.
    #[test]
    fn fail_on_null_resets_at_when_utilization_nonzero() {
        let r = run_evaluate(
            json!({
                "five_hour": {"utilization": 5.0, "resets_at": null},
                "seven_day": {"utilization": 0.0, "resets_at": null},
            }),
            200,
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A4"));
        assert!(d.hint.contains("Null is only permitted on zero-usage"));
    }

    #[test]
    fn fail_on_missing_seven_day_window() {
        let future = chrono_like_iso(86400);
        let r = run_evaluate(
            json!({"five_hour": {"utilization": 10.0, "resets_at": future}}),
            200,
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("seven_day"));
    }

    #[test]
    fn fail_on_resets_at_in_the_past() {
        let past = "2020-01-01T00:00:00Z".to_string();
        let future = chrono_like_iso(86400);
        let r = run_evaluate(
            json!({
                "five_hour": {"utilization": 10.0, "resets_at": past},
                "seven_day": {"utilization": 15.0, "resets_at": future},
            }),
            200,
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A6"));
    }

    #[test]
    fn fail_on_non_object_body() {
        let bytes = b"not json at all";
        let r = evaluate(
            AccountNum::try_from(1).unwrap(),
            200,
            bytes,
            100,
            CELL_NAME,
            SPEC_ANCHOR,
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        assert!(r.diagnostic.unwrap().failed_assertion.contains("A2"));
    }

    #[test]
    fn parse_iso8601_round_trips_known_dates() {
        assert_eq!(parse_iso8601_to_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_to_epoch("2026-01-01T00:00:00Z"),
            Some(1767225600)
        );
        // Fractional-seconds variant.
        assert_eq!(
            parse_iso8601_to_epoch("2026-01-01T00:00:00.123Z"),
            Some(1767225600)
        );
    }

    fn chrono_like_iso(seconds_from_now: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let target = now + seconds_from_now;
        // Simple epoch-to-iso converter using days_from_civil inverse.
        // For tests we just produce a known-future ISO string.
        let days = target / 86400;
        let secs_in_day = target % 86400;
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z",
            y = y,
            m = m,
            d = d,
            h = (secs_in_day / 3600) as u32,
            mi = ((secs_in_day % 3600) / 60) as u32,
            s = (secs_in_day % 60) as u32,
        )
    }

    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719468;
        let era = if z >= 0 {
            z / 146097
        } else {
            (z - 146096) / 146097
        };
        let doe = (z - era * 146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
        let y = if m <= 2 { y + 1 } else { y };
        (y, m, d)
    }
}
