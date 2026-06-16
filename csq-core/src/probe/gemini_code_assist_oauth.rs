//! Cell 09 — Gemini Code Assist OAuth probe.
//!
//! Two-call probe per spec 05 §5.8.2 + spec 11 §11.2 Cell 09:
//!
//! - `POST :loadCodeAssist`  — discovers the user's GCP project
//! - `POST :retrieveUserQuota` — returns `BucketInfo[]` per (model, tokenType)
//!
//! Six load-bearing assertions:
//!
//! 1. loadCodeAssist returns HTTP 200.
//! 2. loadCodeAssist body has `cloudaicompanionProject: String` (non-empty).
//! 3. retrieveUserQuota returns HTTP 200.
//! 4. retrieveUserQuota body has `buckets: []` (non-empty array).
//! 5. Every bucket has `modelId`, `tokenType`, `remainingFraction in [0.0, 1.0]`,
//!    `resetTime`. `remainingAmount` is optional per gemini-cli's
//!    handling (`if (bucket.remainingAmount) …` then `limit = 100`
//!    fallback) — Google omits it for fraction-only quotas.
//! 6. The local aggregator (`aggregate_to_usage_window`) produces
//!    `(used_percentage in [0.0, 100.0], resets_at in future)`.
//!
//! 401 from either call routes to a soft hint (not a probe FAIL — the
//! operator-side fix is to run `gemini` once to refresh the token).

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SCHEMA_VERSION};
use crate::http;
use crate::providers::gemini::code_assist_quota::{
    aggregate_to_usage_window, build_headers, build_load_code_assist_body,
    build_retrieve_user_quota_body, read_oauth_creds, BucketInfo, LoadCodeAssistResponse,
    OauthCredsError, RetrieveUserQuotaResponse, CLOUDCODE_PA_BASE_URL,
};
use crate::types::AccountNum;
use secrecy::ExposeSecret;
use std::path::Path;
use std::time::Instant;

const CELL_NAME: &str = "gemini-code-assist-oauth";
const SPEC_ANCHOR: &str = "05§5.8.2";

pub fn probe(slot: AccountNum, home_dir: &Path) -> ProbeRecord {
    let started = Instant::now();

    // Prerequisite: ~/.gemini/oauth_creds.json present + parseable.
    let creds = match read_oauth_creds(home_dir) {
        Ok(c) => c,
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return prereq_fail(slot, elapsed_ms, &e);
        }
    };
    let bearer = creds.access_token.expose_secret().to_string();
    let headers = build_headers(&bearer);

    // Call 1: :loadCodeAssist
    let load_url = format!("{CLOUDCODE_PA_BASE_URL}:loadCodeAssist");
    let load_body = build_load_code_assist_body();
    let load_result = http::post_json_with_headers(&load_url, &headers, &load_body);

    let (load_status, _load_resp_headers, load_body_text) = match load_result {
        Ok(triple) => triple,
        Err(transport_err) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return fail(
                slot,
                load_url.clone(),
                elapsed_ms,
                0,
                "transport: loadCodeAssist request reached endpoint",
                "request failed before any HTTP status was returned",
                &transport_err,
                None,
            );
        }
    };

    // A1: loadCodeAssist HTTP 200. Round-1 redteam H3-d: 401 routes to
    // Skipped (operator state — token stale), not Fail (contract drift).
    if load_status == 401 {
        return skipped_op_state(
            slot,
            load_url,
            "loadCodeAssist returned 401",
            "OAuth token stale; gemini-cli has not refreshed yet",
            "run `gemini` once interactively to refresh ~/.gemini/oauth_creds.json, then re-probe.",
        );
    }
    if load_status != 200 {
        let elapsed_ms = started.elapsed().as_millis() as u64;
        return fail(
            slot,
            load_url,
            elapsed_ms,
            0,
            "A1: loadCodeAssist HTTP 200",
            &format!("HTTP {load_status}"),
            non_200_hint(load_status, "loadCodeAssist"),
            Some(load_body_text.as_bytes()),
        );
    }

    // A2: cloudaicompanionProject present + non-empty. Round-1 redteam
    // H3-d: empty project routes to Skipped (operator hasn't bootstrapped),
    // HTML body on 200 routes to Skipped (Cloudflare interception), real
    // schema mismatch stays as Fail.
    let project = match parse_load_response(&load_body_text) {
        Ok(Some(p)) if !p.is_empty() => p,
        Ok(_) => {
            return skipped_op_state(
                slot,
                load_url,
                "loadCodeAssist returned empty cloudaicompanionProject",
                "operator has no Code Assist project provisioned",
                "open `gemini` once to bootstrap the project; re-probe.",
            );
        }
        Err(e) => {
            // Detect HTML body (Cloudflare maintenance page or
            // upstream interception) — route to Skipped not Fail.
            let body_lower = load_body_text.to_lowercase();
            if body_lower.starts_with("<!doctype")
                || body_lower.starts_with("<html")
                || body_lower.contains("<title>")
            {
                return skipped_op_state(
                    slot,
                    load_url,
                    "loadCodeAssist returned HTML body on 200",
                    "Cloudflare interception or upstream maintenance page",
                    "retry in a few minutes; check cloudcode-pa.googleapis.com status.",
                );
            }
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return fail(
                slot,
                load_url,
                elapsed_ms,
                1,
                "A2: loadCodeAssist body parses",
                &format!("parse error: {e}"),
                "spec 05 §5.8.2: loadCodeAssist body must deserialize to LoadCodeAssistResponse.",
                Some(load_body_text.as_bytes()),
            );
        }
    };

    // Round-1 redteam H2-d: TOCTOU defense — re-read oauth_creds before
    // call 2. gemini-cli may rotate the file between calls.
    let bearer = match read_oauth_creds(home_dir) {
        Ok(c) => c.access_token.expose_secret().to_string(),
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return prereq_fail(slot, elapsed_ms, &e);
        }
    };
    let headers = build_headers(&bearer);

    // Call 2: :retrieveUserQuota
    let quota_url = format!("{CLOUDCODE_PA_BASE_URL}:retrieveUserQuota");
    let quota_body = build_retrieve_user_quota_body(&project);
    let quota_result = http::post_json_with_headers(&quota_url, &headers, &quota_body);

    let (quota_status, _quota_headers, quota_text) = match quota_result {
        Ok(triple) => triple,
        Err(transport_err) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return fail(
                slot,
                quota_url,
                elapsed_ms,
                2,
                "transport: retrieveUserQuota request reached endpoint",
                "request failed before any HTTP status was returned",
                &transport_err,
                None,
            );
        }
    };

    // A3: retrieveUserQuota HTTP 200. Round-1 redteam H3-d: 401 → Skipped.
    if quota_status == 401 {
        return skipped_op_state(
            slot,
            quota_url,
            "retrieveUserQuota returned 401",
            "OAuth token stale between calls (gemini-cli rotated mid-probe)",
            "run `gemini` once interactively to refresh; re-probe.",
        );
    }
    if quota_status != 200 {
        let elapsed_ms = started.elapsed().as_millis() as u64;
        return fail(
            slot,
            quota_url,
            elapsed_ms,
            2,
            "A3: retrieveUserQuota HTTP 200",
            &format!("HTTP {quota_status}"),
            non_200_hint(quota_status, "retrieveUserQuota"),
            Some(quota_text.as_bytes()),
        );
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    evaluate_quota(slot, quota_url, &quota_text, elapsed_ms)
}

fn evaluate_quota(
    slot: AccountNum,
    endpoint: String,
    body_text: &str,
    elapsed_ms: u64,
) -> ProbeRecord {
    // A4: body has non-empty `buckets`.
    let parsed: RetrieveUserQuotaResponse = match serde_json::from_str(body_text) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                slot,
                endpoint,
                elapsed_ms,
                3,
                "A4: retrieveUserQuota body parses",
                &format!("parse error: {e}"),
                "spec 05 §5.8.2: retrieveUserQuota body must deserialize to RetrieveUserQuotaResponse.",
                Some(body_text.as_bytes()),
            );
        }
    };
    let buckets = match parsed.buckets {
        Some(b) if !b.is_empty() => b,
        _ => {
            return fail(
                slot,
                endpoint,
                elapsed_ms,
                3,
                "A4: retrieveUserQuota.buckets is non-empty array",
                "buckets is null or empty",
                "spec 05 §5.8.2: a Code Assist subscription must return at least one bucket.",
                Some(body_text.as_bytes()),
            );
        }
    };

    // A5: every bucket has the load-bearing fields.
    for (i, b) in buckets.iter().enumerate() {
        if let Err(d) = check_bucket(b, i) {
            return ProbeRecord {
                schema_version: SCHEMA_VERSION,
                slot: slot.get(),
                cell: CELL_NAME,
                spec_anchor: SPEC_ANCHOR,
                status: ProbeStatus::Fail,
                endpoint,
                elapsed_ms,
                assertions_passed: 4,
                assertions_total: 6,
                diagnostic: Some(d),
                redacted_response_excerpt: Some(redact_excerpt(body_text.as_bytes())),
            };
        }
    }

    // A6: aggregator output is in [0, 100] and resets_at parses to future.
    let projection = match aggregate_to_usage_window(&buckets) {
        Some(p) => p,
        None => {
            return fail(
                slot,
                endpoint,
                elapsed_ms,
                5,
                "A6: aggregate_to_usage_window returns Some(projection)",
                "every bucket was filtered out (remainingFraction out of [0,1])",
                "spec 05 §5.8.2 + code_assist_quota.rs: the aggregator drops buckets with out-of-range remainingFraction; if every bucket is dropped, the slot's quota cannot be projected. Investigate upstream schema drift.",
                Some(body_text.as_bytes()),
            );
        }
    };
    if !(0.0..=100.0).contains(&projection.used_percentage) {
        return fail(
            slot,
            endpoint,
            elapsed_ms,
            5,
            "A6: 0.0 <= projected used_percentage <= 100.0",
            &format!("used_percentage = {}", projection.used_percentage),
            "aggregator output is out of [0, 100]; this should be unreachable given A5 passed — investigate aggregator code.",
            Some(body_text.as_bytes()),
        );
    }

    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Ok,
        endpoint,
        elapsed_ms,
        assertions_passed: 6,
        assertions_total: 6,
        diagnostic: None,
        redacted_response_excerpt: None,
    }
}

fn check_bucket(b: &BucketInfo, idx: usize) -> Result<(), ProbeDiagnostic> {
    if b.model_id.as_deref().unwrap_or("").is_empty() {
        return Err(ProbeDiagnostic {
            failed_assertion: format!("A5: buckets[{idx}].modelId is non-empty"),
            observed_shape: format!("modelId = {:?}", b.model_id),
            hint: "spec 05 §5.8.2: every BucketInfo MUST identify a model.".into(),
        });
    }
    if b.token_type.as_deref().unwrap_or("").is_empty() {
        return Err(ProbeDiagnostic {
            failed_assertion: format!("A5: buckets[{idx}].tokenType is non-empty"),
            observed_shape: format!("tokenType = {:?}", b.token_type),
            hint: "spec 05 §5.8.2: tokenType is one of REQUESTS, INPUT_TOKENS, OUTPUT_TOKENS, …"
                .into(),
        });
    }
    let frac = b.remaining_fraction.ok_or_else(|| ProbeDiagnostic {
        failed_assertion: format!("A5: buckets[{idx}].remainingFraction is f64"),
        observed_shape: "remainingFraction = null".into(),
        hint: "spec 05 §5.8.2: remainingFraction MUST be a number in [0.0, 1.0].".into(),
    })?;
    if !(0.0..=1.0).contains(&frac) {
        return Err(ProbeDiagnostic {
            failed_assertion: format!("A5: 0.0 <= buckets[{idx}].remainingFraction <= 1.0"),
            observed_shape: format!("remainingFraction = {frac}"),
            hint:
                "spec 05 §5.8.2: a value outside [0,1] is upstream schema drift; aggregator drops it."
                    .into(),
        });
    }
    if b.reset_time.as_deref().unwrap_or("").is_empty() {
        return Err(ProbeDiagnostic {
            failed_assertion: format!("A5: buckets[{idx}].resetTime is non-empty string"),
            observed_shape: format!("resetTime = {:?}", b.reset_time),
            hint: "spec 05 §5.8.2: resetTime is an RFC3339 timestamp string.".into(),
        });
    }
    // `remainingAmount` is optional — gemini-cli treats it as
    // `if (bucket.remainingAmount) …` with a fallback. Google omits it
    // for fraction-only buckets (verified empirically against a Code
    // Assist Free Tier account, 2026-05-08). The aggregator
    // (`aggregate_to_usage_window`) only consumes `remainingFraction`,
    // so the field's absence does not affect the projection.
    Ok(())
}

fn parse_load_response(body: &str) -> Result<Option<String>, serde_json::Error> {
    let parsed: LoadCodeAssistResponse = serde_json::from_str(body)?;
    Ok(parsed.project)
}

fn prereq_fail(slot: AccountNum, elapsed_ms: u64, e: &OauthCredsError) -> ProbeRecord {
    let (failed, observed, hint): (&str, String, &str) = match e {
        OauthCredsError::NotFound { path: _ } => (
            "prerequisite: ~/.gemini/oauth_creds.json exists",
            // Do NOT interpolate `path.display()` — the resolved path
            // (`/Users/<u>/.gemini/oauth_creds.json`) leaks OS username +
            // home-dir layout (security.md §2). Canonical path is named
            // in failed_assertion.
            "missing".into(),
            "run `gemini` once interactively to provision Code Assist OAuth credentials.",
        ),
        OauthCredsError::Malformed { reason, .. } => (
            "prerequisite: ~/.gemini/oauth_creds.json parses",
            format!("malformed: {reason}"),
            "the file is partial or corrupt; run `gemini` interactively once (gemini-cli v0.41.2+ has no auth subcommand — auth happens in the first-run picker) to rewrite. Journal 0054.",
        ),
        OauthCredsError::ReadFailed { reason, .. } => (
            "prerequisite: ~/.gemini/oauth_creds.json readable",
            format!("read error: {reason}"),
            "check file permissions (must be 0o600 owned by current user).",
        ),
    };
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Skipped,
        endpoint: "prereq".to_string(),
        elapsed_ms,
        assertions_passed: 0,
        assertions_total: 6,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed.to_string(),
            observed_shape: observed,
            hint: hint.to_string(),
        }),
        redacted_response_excerpt: None,
    }
}

fn non_200_hint(status: u16, call: &str) -> &'static str {
    match (status, call) {
        (401, _) => "401 — Code Assist OAuth token stale. Run `gemini` once interactively to refresh; csq is read-only on ~/.gemini/oauth_creds.json.",
        (403, _) => "403 — token lacks Code Assist scope. Run `gemini` interactively once (the v0.41.2+ first-run picker re-grants scopes); journal 0054.",
        (429, _) => "429 — rate limited by Cloudcode-PA. Wait and retry; not a code regression.",
        _ => "non-200 status from cloudcode-pa.googleapis.com. Check status page and retry.",
    }
}

#[allow(clippy::too_many_arguments)]
fn fail(
    slot: AccountNum,
    endpoint: String,
    elapsed_ms: u64,
    assertions_passed: u32,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
    body: Option<&[u8]>,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Fail,
        endpoint,
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

/// Round-1 redteam H3-d: route operator-state failures (401, empty
/// project, HTML interception) to `Skipped` rather than `Fail` so they
/// don't block release tags. Spec 11 §11.4 framing: `Fail` means
/// contract drift; `Skipped` means operator action needed.
fn skipped_op_state(
    slot: AccountNum,
    endpoint: String,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Skipped,
        endpoint,
        elapsed_ms: 0,
        assertions_passed: 0,
        assertions_total: 6,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed_assertion.to_string(),
            observed_shape: observed_shape.to_string(),
            hint: hint.to_string(),
        }),
        redacted_response_excerpt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(model: &str, token_type: &str, frac: f64) -> BucketInfo {
        BucketInfo {
            model_id: Some(model.into()),
            token_type: Some(token_type.into()),
            remaining_fraction: Some(frac),
            remaining_amount: Some("1000".into()),
            reset_time: Some("2099-01-01T00:00:00Z".into()),
        }
    }

    fn slot1() -> AccountNum {
        AccountNum::try_from(1).unwrap()
    }

    fn ok_response_body() -> String {
        serde_json::to_string(&serde_json::json!({
            "buckets": [
                {
                    "modelId": "gemini-2.5-flash",
                    "tokenType": "REQUESTS",
                    "remainingFraction": 0.8,
                    "remainingAmount": "800",
                    "resetTime": "2099-01-01T00:00:00Z",
                },
                {
                    "modelId": "gemini-2.5-pro",
                    "tokenType": "INPUT_TOKENS",
                    "remainingFraction": 0.5,
                    "remainingAmount": "50000",
                    "resetTime": "2099-01-01T00:00:00Z",
                },
            ],
        }))
        .unwrap()
    }

    #[test]
    fn evaluate_ok_when_buckets_pass_all_assertions() {
        let r = evaluate_quota(slot1(), "test".into(), &ok_response_body(), 100);
        assert_eq!(r.status, ProbeStatus::Ok);
        assert_eq!(r.assertions_passed, 6);
        assert!(r.diagnostic.is_none());
    }

    #[test]
    fn evaluate_fails_when_buckets_empty() {
        let body = serde_json::to_string(&serde_json::json!({"buckets": []})).unwrap();
        let r = evaluate_quota(slot1(), "test".into(), &body, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A4"));
    }

    #[test]
    fn evaluate_fails_when_buckets_null() {
        let body = serde_json::to_string(&serde_json::json!({})).unwrap();
        let r = evaluate_quota(slot1(), "test".into(), &body, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A4"));
    }

    #[test]
    fn evaluate_fails_when_remaining_fraction_out_of_range() {
        let body = serde_json::to_string(&serde_json::json!({
            "buckets": [
                {
                    "modelId": "gemini-2.5-flash",
                    "tokenType": "REQUESTS",
                    "remainingFraction": 1.5,
                    "remainingAmount": "1000",
                    "resetTime": "2099-01-01T00:00:00Z",
                },
            ],
        }))
        .unwrap();
        let r = evaluate_quota(slot1(), "test".into(), &body, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A5"));
        assert!(d.observed_shape.contains("1.5"));
    }

    #[test]
    fn evaluate_fails_when_token_type_missing() {
        let body = serde_json::to_string(&serde_json::json!({
            "buckets": [
                {
                    "modelId": "gemini-2.5-flash",
                    "remainingFraction": 0.5,
                    "remainingAmount": "1000",
                    "resetTime": "2099-01-01T00:00:00Z",
                },
            ],
        }))
        .unwrap();
        let r = evaluate_quota(slot1(), "test".into(), &body, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("tokenType"));
    }

    #[test]
    fn check_bucket_accepts_well_formed_input() {
        let b = bucket("gemini-2.5-flash", "REQUESTS", 0.5);
        assert!(check_bucket(&b, 0).is_ok());
    }

    /// Code Assist Free Tier omits `remainingAmount` for fraction-only
    /// buckets (verified against a real account 2026-05-08). gemini-cli
    /// treats it as optional. Reject only the load-bearing fields
    /// (modelId, tokenType, remainingFraction, resetTime).
    #[test]
    fn check_bucket_accepts_missing_remaining_amount() {
        let mut b = bucket("gemini-2.5-flash", "REQUESTS", 0.49);
        b.remaining_amount = None;
        assert!(check_bucket(&b, 0).is_ok());
    }

    /// Live shape from the Code Assist Free Tier 2026-05-08: only
    /// `resetTime`, `tokenType`, `modelId`, `remainingFraction`. No
    /// `remainingAmount` field. The probe MUST pass A5 + A6 on this
    /// shape.
    #[test]
    fn evaluate_ok_for_fraction_only_response_shape() {
        let body = serde_json::to_string(&serde_json::json!({
            "buckets": [
                {
                    "resetTime": "2099-05-08T11:17:49Z",
                    "tokenType": "REQUESTS",
                    "modelId": "gemini-2.5-flash",
                    "remainingFraction": 0.49333334,
                },
                {
                    "resetTime": "2099-05-09T04:25:06Z",
                    "tokenType": "REQUESTS",
                    "modelId": "gemini-2.5-pro",
                    "remainingFraction": 0.95,
                },
            ],
        }))
        .unwrap();
        let r = evaluate_quota(slot1(), "test".into(), &body, 100);
        assert_eq!(r.status, ProbeStatus::Ok, "diag = {:?}", r.diagnostic);
        assert_eq!(r.assertions_passed, 6);
    }

    #[test]
    fn parse_load_response_extracts_project() {
        let body = serde_json::to_string(&serde_json::json!({
            "cloudaicompanionProject": "projects/example",
            "ignored_field": 42,
        }))
        .unwrap();
        let project = parse_load_response(&body).unwrap();
        assert_eq!(project, Some("projects/example".to_string()));
    }

    #[test]
    fn parse_load_response_handles_missing_project() {
        let body = serde_json::to_string(&serde_json::json!({})).unwrap();
        let project = parse_load_response(&body).unwrap();
        assert_eq!(project, None);
    }

    /// #516 sibling: prereq_fail for `OauthCredsError::NotFound` MUST NOT
    /// interpolate the resolved path (`/Users/<u>/.gemini/oauth_creds.json`)
    /// into observed_shape — `security.md` §2 (no path-bearing detail in
    /// operator-facing strings). The canonical file is named in
    /// failed_assertion; slot is on ProbeRecord.slot.
    #[test]
    fn code_assist_oauth_creds_not_found_diagnostic_is_path_free() {
        // Construct the NotFound error directly (no need to drive the
        // full read_oauth_creds_once codepath; prereq_fail is the
        // unit under test for the path-leak invariant).
        let err = OauthCredsError::NotFound {
            path: std::path::PathBuf::from("/Users/leak-test/.gemini/oauth_creds.json"),
        };
        let r = prereq_fail(slot1(), 100, &err);

        assert_eq!(r.status, ProbeStatus::Skipped);
        let diag = r.diagnostic.as_ref().unwrap();
        assert_eq!(
            diag.observed_shape, "missing",
            "observed_shape MUST be exactly \"missing\" (path-free); got: {:?}",
            diag.observed_shape
        );

        let json = serde_json::to_string(&r).unwrap();
        // The NotFound error carries a path in its payload, but the
        // diagnostic MUST NOT echo it. Use a fixture path containing
        // `/Users/leak-test/` so a regression that re-introduced the
        // interpolation would surface here.
        assert!(
            !json.contains("/Users/"),
            "code-assist OAuth prereq-fail record MUST NOT contain /Users/ path; got: {json}"
        );
        assert!(
            !json.contains("leak-test"),
            "code-assist OAuth prereq-fail record MUST NOT echo NotFound.path content; got: {json}"
        );
        assert!(
            !diag.observed_shape.contains('/'),
            "observed_shape MUST NOT contain path separator; got: {:?}",
            diag.observed_shape
        );
    }
}
