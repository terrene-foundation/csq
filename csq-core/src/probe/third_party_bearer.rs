//! Cells 04 + 05 + 06 — 3P Bearer probes (MiniMax, Z.AI, DeepSeek).
//!
//! Three providers, three contracts, but they share enough infrastructure
//! (per-slot API key load, Bearer GET, response-body inspection) that
//! the dispatcher lives here. Each cell is its own `mod` below; the
//! exposed entry point is [`probe`] which the parent dispatcher routes
//! by `provider_id`.
//!
//! Shared:
//! - `load_3p_api_key_for_slot` reads `config-<N>/settings.json` for
//!   the per-slot bearer.
//! - `http::get_bearer` (direct reqwest) — these endpoints are NOT
//!   Cloudflare-fronted in a body-stripping way (verified for MM/Z.AI
//!   in spec 05 §§5.3, 5.4; DeepSeek probe asserts on headers only).

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SCHEMA_VERSION};
use crate::daemon::usage_poller::third_party::load_3p_api_key_for_slot;
use crate::http;
use crate::types::AccountNum;
use std::path::Path;
use std::time::Instant;

/// Probe a 3P bearer slot. `provider_id` is the catalog id (`mm`,
/// `zai`, `deepseek`). Returns `None` if the provider is not in the
/// supported set; caller falls back to a generic Skip diagnostic.
pub fn probe(base_dir: &Path, slot: AccountNum, provider_id: &str) -> Option<ProbeRecord> {
    let cell = match provider_id {
        "mm" | "minimax" => Cell::Minimax,
        "zai" => Cell::Zai,
        "deepseek" => Cell::Deepseek,
        "kimi" => Cell::Kimi,
        _ => return None,
    };
    let started = Instant::now();
    let api_key = match load_3p_api_key_for_slot(base_dir, slot.get(), provider_id) {
        Some(k) => k,
        None => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return Some(prereq_skip(
                slot,
                cell,
                elapsed_ms,
                "prerequisite: per-slot API key present",
                &format!("no API key in config-{}/settings.json", slot.get()),
                "run `csq setkey <provider> <key> --slot <N>` to bind.",
            ));
        }
    };
    let bearer = api_key.expose_secret().to_string();
    let elapsed_setup = started.elapsed().as_millis() as u64;
    Some(match cell {
        Cell::Minimax => minimax::probe(slot, &bearer, started, elapsed_setup),
        Cell::Zai => zai::probe(slot, &bearer, started, elapsed_setup),
        Cell::Deepseek => deepseek::probe(slot, &bearer, started),
        Cell::Kimi => kimi::probe(slot, &bearer, started),
    })
}

#[derive(Copy, Clone)]
enum Cell {
    Minimax,
    Zai,
    Deepseek,
    Kimi,
}

fn prereq_skip(
    slot: AccountNum,
    cell: Cell,
    elapsed_ms: u64,
    failed: &str,
    observed: &str,
    hint: &str,
) -> ProbeRecord {
    let (cell_name, spec_anchor, total) = cell.metadata();
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: cell_name,
        spec_anchor,
        status: ProbeStatus::Skipped,
        endpoint: "prereq".to_string(),
        elapsed_ms,
        assertions_passed: 0,
        assertions_total: total,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed.to_string(),
            observed_shape: observed.to_string(),
            hint: hint.to_string(),
        }),
        redacted_response_excerpt: None,
    }
}

impl Cell {
    fn metadata(self) -> (&'static str, &'static str, u32) {
        match self {
            Cell::Minimax => ("minimax-bearer", "05§5.3", 5),
            Cell::Zai => ("zai-bearer", "05§5.4", 6),
            Cell::Deepseek => ("deepseek-bearer", "05§5.4a", 3),
            Cell::Kimi => ("kimi-bearer", "05§5.4b", 2),
        }
    }
}

// ============================================================
// Cell 04 — MiniMax bearer
// ============================================================
mod minimax {
    use super::*;

    const URL: &str = "https://platform.minimax.io/v1/api/openplatform/coding_plan/remains";
    const CELL_NAME: &str = "minimax-bearer";
    const SPEC_ANCHOR: &str = "05§5.3";

    pub fn probe(
        slot: AccountNum,
        bearer: &str,
        started: Instant,
        _elapsed_setup_ms: u64,
    ) -> ProbeRecord {
        let result = http::get_bearer(URL, bearer, &[]);
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok((200, body)) => evaluate(slot, &body, elapsed_ms),
            Ok((status, body)) => fail(
                slot,
                elapsed_ms,
                0,
                "A1: HTTP status is 200",
                &format!("HTTP {status}"),
                non_200_hint(status),
                Some(&body),
            ),
            Err(e) => fail(
                slot,
                elapsed_ms,
                0,
                "transport: request reached endpoint",
                "transport failure",
                &e,
                None,
            ),
        }
    }

    fn evaluate(slot: AccountNum, body: &[u8], elapsed_ms: u64) -> ProbeRecord {
        // A2: body parses as JSON object.
        let json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return fail(
                    slot,
                    elapsed_ms,
                    1,
                    "A2: body parses as JSON",
                    &format!("parse error: {e}"),
                    "spec 05 §5.3 requires a JSON object body.",
                    Some(body),
                );
            }
        };

        // A3: model_remains is a non-empty array.
        let model_remains = match json.get("model_remains").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr,
            _ => {
                return fail(
                    slot,
                    elapsed_ms,
                    2,
                    "A3: model_remains is a non-empty array",
                    "missing or empty",
                    "spec 05 §5.3: a coding plan returns at least one entry under model_remains.",
                    Some(body),
                );
            }
        };

        // A4: at least one entry has the load-bearing fields with
        // remaining-vs-consumed semantic preserved
        // (current_interval_total_count >= current_interval_usage_count).
        //
        // Round-1 redteam H4-d: this assertion is satisfied trivially
        // when usage_count == 0 — the inequality holds regardless of
        // semantic. We log a warning at A5 when total > 0 && usage == 0
        // so the operator knows the assertion is weakly verified.
        let mut any_valid = false;
        let mut weakly_verified_for_zero_usage = false;
        for entry in model_remains {
            let total = entry
                .get("current_interval_total_count")
                .and_then(|v| v.as_i64());
            let used = entry
                .get("current_interval_usage_count")
                .and_then(|v| v.as_i64());
            let start = entry.get("start_time").and_then(|v| v.as_i64());
            let end = entry.get("end_time").and_then(|v| v.as_i64());
            if let (Some(t), Some(u), Some(s), Some(e)) = (total, used, start, end) {
                if t >= u && s < e {
                    any_valid = true;
                    if t > 0 && u == 0 {
                        weakly_verified_for_zero_usage = true;
                    }
                    break;
                }
                if t < u {
                    return fail(
                        slot,
                        elapsed_ms,
                        3,
                        "A4: current_interval_total_count >= current_interval_usage_count",
                        &format!("total={t}, usage={u} (usage_count is REMAINING per spec 05 §5.3)"),
                        "spec 05 §5.3: usage_count is REMAINING (the endpoint name is `/remains`). total < usage means the upstream changed the field's semantic — file a provider-drift issue.",
                        Some(body),
                    );
                }
            }
        }
        if weakly_verified_for_zero_usage {
            tracing::info!(
                "minimax probe A4 weakly verified: usage_count=0 satisfies total>=usage trivially; semantic-flip undetectable without write-side canary (spec 11 §11.2 Cell 04)"
            );
        }
        if !any_valid {
            return fail(
                slot,
                elapsed_ms,
                3,
                "A4: at least one entry has total/usage/start_time/end_time",
                "no entry had all four fields",
                "spec 05 §5.3 requires these fields on the limiting entry.",
                Some(body),
            );
        }

        // A5: response is healthy (load-bearing fields verified).
        ok(slot, elapsed_ms)
    }

    fn ok(slot: AccountNum, elapsed_ms: u64) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Ok,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: 5,
            assertions_total: 5,
            diagnostic: None,
            redacted_response_excerpt: None,
        }
    }

    fn fail(
        slot: AccountNum,
        elapsed_ms: u64,
        passed: u32,
        failed: &str,
        observed: &str,
        hint: &str,
        body: Option<&[u8]>,
    ) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Fail,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: passed,
            assertions_total: 5,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: failed.to_string(),
                observed_shape: observed.to_string(),
                hint: hint.to_string(),
            }),
            redacted_response_excerpt: body.map(|b| crate::error::redact_excerpt(b, 256)),
        }
    }

    fn non_200_hint(status: u16) -> &'static str {
        match status {
            401 => "401 — invalid API key. Re-run `csq setkey mm <key> --slot N`.",
            403 => "403 — API key lacks coding plan scope. Check MiniMax dashboard.",
            429 => "429 — rate limited by MiniMax. Wait and retry.",
            _ => "non-200 from platform.minimax.io. Check status page.",
        }
    }
}

// ============================================================
// Cell 05 — Z.AI bearer
// ============================================================
mod zai {
    use super::*;

    const URL: &str = "https://api.z.ai/api/monitor/usage/quota/limit";
    const CELL_NAME: &str = "zai-bearer";
    const SPEC_ANCHOR: &str = "05§5.4";

    pub fn probe(
        slot: AccountNum,
        bearer: &str,
        started: Instant,
        _elapsed_setup_ms: u64,
    ) -> ProbeRecord {
        let result = http::get_bearer(URL, bearer, &[]);
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok((200, body)) => evaluate(slot, &body, elapsed_ms),
            Ok((status, body)) => fail(
                slot,
                elapsed_ms,
                0,
                "A1: HTTP status is 200",
                &format!("HTTP {status}"),
                non_200_hint(status),
                Some(&body),
            ),
            Err(e) => fail(
                slot,
                elapsed_ms,
                0,
                "transport: request reached endpoint",
                "transport failure",
                &e,
                None,
            ),
        }
    }

    fn evaluate(slot: AccountNum, body: &[u8], elapsed_ms: u64) -> ProbeRecord {
        // A2: body parses + has code:200 + data.limits[].
        let json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return fail(
                    slot,
                    elapsed_ms,
                    1,
                    "A2: body parses as JSON",
                    &format!("parse error: {e}"),
                    "spec 05 §5.4 requires a JSON object.",
                    Some(body),
                );
            }
        };
        if json.get("code").and_then(|v| v.as_i64()) != Some(200) {
            return fail(
                slot,
                elapsed_ms,
                2,
                "A2: top-level code == 200",
                &format!("code = {:?}", json.get("code")),
                "spec 05 §5.4: response envelope code field MUST be 200 on success.",
                Some(body),
            );
        }
        let limits = match json
            .get("data")
            .and_then(|d| d.get("limits"))
            .and_then(|v| v.as_array())
        {
            Some(arr) if !arr.is_empty() => arr.clone(),
            _ => {
                return fail(
                    slot,
                    elapsed_ms,
                    3,
                    "A3: data.limits is a non-empty array",
                    "missing or empty",
                    "spec 05 §5.4: a Z.AI coding plan returns at least one entry under data.limits.",
                    Some(body),
                );
            }
        };

        // Per spec 05 §5.4: filter by `type: "TOKENS_LIMIT"` first —
        // Z.AI emits other entries (TIME_LIMIT for monthly time
        // quotas, etc.) that are NOT the coding-plan TOKENS_LIMIT
        // window pair this probe contracts.
        let token_limits: Vec<&serde_json::Value> = limits
            .iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("TOKENS_LIMIT"))
            .collect();
        if token_limits.is_empty() {
            return fail(
                slot,
                elapsed_ms,
                3,
                "A4: at least one TOKENS_LIMIT entry",
                "no entry with type == TOKENS_LIMIT",
                "spec 05 §5.4: the coding plan emits TOKENS_LIMIT entries with units 3 (5h) and 6 (7d). Their absence means the plan tier doesn't include coding quota — file a [provider-drift] issue if this is unexpected.",
                Some(body),
            );
        }

        // A4: at least one TOKENS_LIMIT entry with unit==3 (5h) AND
        // one with unit==6 (7d). Null `nextResetTime` is accepted —
        // Z.AI emits null for windows with zero usage (no reset
        // scheduled because no consumption); the daemon poller
        // (`usage_poller::zai`) silently drops those windows from
        // `quota.json` rather than failing. Spec 05 §5.4 Revision
        // 2026-05-06.
        let mut has_unit3 = false;
        let mut has_unit6 = false;
        for entry in &token_limits {
            let unit = entry.get("unit").and_then(|v| v.as_i64()).unwrap_or(-1);
            let pct = entry
                .get("percentage")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let reset_opt = entry.get("nextResetTime").and_then(|v| v.as_i64());
            if !(0..=100).contains(&pct) {
                return fail(
                    slot,
                    elapsed_ms,
                    4,
                    "A5: TOKENS_LIMIT percentage in [0, 100]",
                    &format!("percentage = {pct} (unit={unit})"),
                    "spec 05 §5.4: percentage MUST be an integer 0-100.",
                    Some(body),
                );
            }
            // A6: if nextResetTime is present, it MUST be positive.
            // Null is acceptable for zero-usage windows (no reset
            // scheduled); the daemon poller treats this as
            // "no window data available" and skips silently.
            if let Some(reset) = reset_opt {
                if reset <= 0 {
                    return fail(
                        slot,
                        elapsed_ms,
                        4,
                        "A6: TOKENS_LIMIT.nextResetTime is positive when present",
                        &format!("nextResetTime = {reset} (unit={unit})"),
                        "spec 05 §5.4: when present, nextResetTime is i64 Unix milliseconds. Null is accepted for zero-usage windows.",
                        Some(body),
                    );
                }
            }
            match unit {
                3 => has_unit3 = true,
                6 => has_unit6 = true,
                _ => {}
            }
        }
        if !has_unit3 {
            return fail(
                slot,
                elapsed_ms,
                4,
                "A4: at least one entry with unit == 3 (5h window)",
                "no unit-3 entry",
                "spec 05 §5.4: unit 3 is the 5h window; missing means no coding-plan window.",
                Some(body),
            );
        }
        if !has_unit6 {
            return fail(
                slot,
                elapsed_ms,
                5,
                "A4: at least one entry with unit == 6 (7d window)",
                "no unit-6 entry",
                "spec 05 §5.4: unit 6 is the 7d window; missing means no weekly window.",
                Some(body),
            );
        }

        ok(slot, elapsed_ms)
    }

    fn ok(slot: AccountNum, elapsed_ms: u64) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Ok,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: 6,
            assertions_total: 6,
            diagnostic: None,
            redacted_response_excerpt: None,
        }
    }

    fn fail(
        slot: AccountNum,
        elapsed_ms: u64,
        passed: u32,
        failed: &str,
        observed: &str,
        hint: &str,
        body: Option<&[u8]>,
    ) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Fail,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: passed,
            assertions_total: 6,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: failed.to_string(),
                observed_shape: observed.to_string(),
                hint: hint.to_string(),
            }),
            redacted_response_excerpt: body.map(|b| crate::error::redact_excerpt(b, 256)),
        }
    }

    fn non_200_hint(status: u16) -> &'static str {
        match status {
            401 => "401 — invalid API key.",
            403 => "403 — API key lacks coding plan scope.",
            429 => "429 — rate limited by Z.AI.",
            _ => "non-200 from api.z.ai. Check status page.",
        }
    }
}

// ============================================================
// Cell 06 — DeepSeek negative-headers probe
// ============================================================
mod deepseek {
    use super::*;

    const URL: &str = "https://api.deepseek.com/anthropic/v1/messages";
    const CELL_NAME: &str = "deepseek-bearer";
    const SPEC_ANCHOR: &str = "05§5.4a";

    pub fn probe(slot: AccountNum, bearer: &str, started: Instant) -> ProbeRecord {
        // Minimal Anthropic-shaped request body. max_tokens=1 + a one-
        // character user message is the cheapest shape that still
        // produces a valid response. We don't care about the body —
        // only the response headers.
        let body = serde_json::json!({
            "model": "deepseek-v4-flash",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "."}],
        })
        .to_string();
        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {bearer}")),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("anthropic-version".to_string(), "2023-06-01".to_string()),
        ];
        let result = http::post_json_with_headers(URL, &headers, &body);
        let elapsed_ms = started.elapsed().as_millis() as u64;

        let (status, resp_headers, _resp_body) = match result {
            Ok(triple) => triple,
            Err(e) => {
                return fail(
                    slot,
                    elapsed_ms,
                    0,
                    "transport: request reached endpoint",
                    "transport failure",
                    &e,
                );
            }
        };

        // A1: HTTP 200 OR 400 (a malformed minimal request still proves
        // reachability — both confirm the bridge is up).
        if status != 200 && status != 400 {
            return fail(
                slot,
                elapsed_ms,
                0,
                "A1: HTTP status is 200 or 400",
                &format!("HTTP {status}"),
                "spec 05 §5.4a: 200 or 400 prove the bridge is up. Other statuses mean the bridge is unreachable or auth is broken.",
            );
        }

        // A2: NO `anthropic-ratelimit-requests-*` header AND NO
        // `anthropic-ratelimit-tokens-*` header. Header keys arrive
        // lowercased per http::post_json_with_headers.
        let unexpected: Vec<String> = resp_headers
            .keys()
            .filter(|k| {
                k.starts_with("anthropic-ratelimit-requests-")
                    || k.starts_with("anthropic-ratelimit-tokens-")
            })
            .cloned()
            .collect();
        if !unexpected.is_empty() {
            return fail(
                slot,
                elapsed_ms,
                1,
                "A2: response carries no anthropic-ratelimit-* headers",
                &format!("unexpected headers: {}", unexpected.join(", ")),
                "spec 05 §5.4a: DeepSeek's bridge changed and now emits rate-limit headers. csq's QuotaKind::Unknown skip in usage_poller::third_party.rs is now dropping useful data — file [provider-drift] issue.",
            );
        }

        // A3: implicit — the negative assertion held; the catalog's
        // QuotaKind::Unknown decision still aligns with reality.
        ok(slot, elapsed_ms)
    }

    fn ok(slot: AccountNum, elapsed_ms: u64) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Ok,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: 3,
            assertions_total: 3,
            diagnostic: None,
            redacted_response_excerpt: None,
        }
    }

    // NOTE: this `fail()` takes NO `body` param and always sets
    // `redacted_response_excerpt: None` — the DeepSeek cell asserts on
    // response HEADERS only and never surfaces a body, so there is no
    // current leak. If a future edit adds body inspection here, it MUST
    // thread the body through `crate::error::redact_excerpt(b, 256)` like
    // the MiniMax/Z.AI cells above (lines ~277, ~514) — NEVER `format!`
    // a raw body into `observed_shape`. (security-reviewer R1 LOW.)
    fn fail(
        slot: AccountNum,
        elapsed_ms: u64,
        passed: u32,
        failed: &str,
        observed: &str,
        hint: &str,
    ) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Fail,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: passed,
            assertions_total: 3,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: failed.to_string(),
                observed_shape: observed.to_string(),
                hint: hint.to_string(),
            }),
            redacted_response_excerpt: None,
        }
    }
}

/// Cell — Kimi coding subscription (`https://api.kimi.com/coding`). Kimi's catalog
/// entry is `QuotaKind::Unknown` (the coding endpoint exposes no quota / balance /
/// rate-limit endpoint), so — unlike the MiniMax/Z.AI cells — there is no quota
/// shape to assert. This cell is a **reachability + auth** probe: it confirms the
/// endpoint is up AND the per-slot bearer (the `sk-kimi-` subscription key)
/// authenticates, which is the actionable operator signal for a keyed 3P slot with
/// no quota API. It makes NO claim about response headers (the coding endpoint's
/// success-case header set is unverified — the negative header assertion the
/// DeepSeek cell makes was grounded in a live probe; Kimi's was not).
mod kimi {
    use super::*;

    const URL: &str = "https://api.kimi.com/coding/v1/messages";
    const CELL_NAME: &str = "kimi-bearer";
    const SPEC_ANCHOR: &str = "05§5.4b";

    pub fn probe(slot: AccountNum, bearer: &str, started: Instant) -> ProbeRecord {
        // Minimal Anthropic-shaped request — max_tokens=1 + a one-char message.
        // We only inspect the HTTP status; the body is never surfaced.
        let body = serde_json::json!({
            "model": "kimi-k3[1m]",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "."}],
        })
        .to_string();
        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {bearer}")),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("anthropic-version".to_string(), "2023-06-01".to_string()),
        ];
        let elapsed_ms = || started.elapsed().as_millis() as u64;

        // A1: transport reached the endpoint.
        let (status, _headers, _body) = match http::post_json_with_headers(URL, &headers, &body) {
            Ok(triple) => triple,
            Err(e) => {
                return fail(
                    slot,
                    elapsed_ms(),
                    0,
                    "A1: request reached the Kimi coding endpoint",
                    "transport failure",
                    &e,
                );
            }
        };

        // A2: the per-slot bearer authenticated. 200/400 prove the endpoint is up
        // AND the key is accepted (400 = malformed minimal request, still auth-OK).
        // 401/403 is the actionable failure — the key is invalid/expired, or it is a
        // pay-per-token Moonshot key (which 401s the coding-subscription endpoint).
        if status == 401 || status == 403 {
            return fail(
                slot,
                elapsed_ms(),
                1,
                "A2: per-slot bearer authenticates against api.kimi.com/coding",
                &format!("HTTP {status} (invalid authentication)"),
                "re-key the slot: `csq setkey kimi --slot <N>` with a valid Kimi coding-subscription key (`sk-kimi-…`). A pay-per-token Moonshot (`api.moonshot.ai`) key will 401 against the coding endpoint.",
            );
        }
        if status != 200 && status != 400 {
            return fail(
                slot,
                elapsed_ms(),
                1,
                "A2: Kimi coding endpoint reachable (HTTP 200/400)",
                &format!("HTTP {status}"),
                "non-2xx/4xx status means the Kimi coding endpoint is unreachable or erroring.",
            );
        }
        ok(slot, elapsed_ms())
    }

    fn ok(slot: AccountNum, elapsed_ms: u64) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Ok,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: 2,
            assertions_total: 2,
            diagnostic: None,
            redacted_response_excerpt: None,
        }
    }

    // Asserts on HTTP status only — never surfaces a response body (no leak).
    fn fail(
        slot: AccountNum,
        elapsed_ms: u64,
        passed: u32,
        failed: &str,
        observed: &str,
        hint: &str,
    ) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: slot.get(),
            cell: CELL_NAME,
            spec_anchor: SPEC_ANCHOR,
            status: ProbeStatus::Fail,
            endpoint: URL.to_string(),
            elapsed_ms,
            assertions_passed: passed,
            assertions_total: 2,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: failed.to_string(),
                observed_shape: observed.to_string(),
                hint: hint.to_string(),
            }),
            redacted_response_excerpt: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn cell_metadata_distinguishes_each_provider() {
        let mut names: BTreeSet<&str> = BTreeSet::new();
        names.insert(Cell::Minimax.metadata().0);
        names.insert(Cell::Zai.metadata().0);
        names.insert(Cell::Deepseek.metadata().0);
        names.insert(Cell::Kimi.metadata().0);
        assert_eq!(names.len(), 4);
        assert!(names.contains("minimax-bearer"));
        assert!(names.contains("zai-bearer"));
        assert!(names.contains("deepseek-bearer"));
        assert!(names.contains("kimi-bearer"));
    }

    #[test]
    fn probe_dispatch_recognizes_kimi() {
        // A kimi slot with no key present routes to Cell::Kimi and returns a
        // prereq-skip (NOT None, which would mean "unknown provider" → the
        // misleading "not yet implemented" fallback the redteam flagged).
        let dir = tempfile::tempdir().unwrap();
        let rec = probe(dir.path(), AccountNum::try_from(1).unwrap(), "kimi");
        let rec = rec.expect("kimi must be a recognized bearer cell");
        assert_eq!(rec.cell, "kimi-bearer");
    }

    #[test]
    fn probe_returns_none_for_unknown_provider() {
        let dir = tempfile::tempdir().unwrap();
        let result = probe(
            dir.path(),
            AccountNum::try_from(1).unwrap(),
            "unknown-provider",
        );
        assert!(result.is_none());
    }
}
