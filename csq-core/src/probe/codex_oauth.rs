//! Cell 03 — Codex OAuth probe.
//!
//! GET `https://chatgpt.com/backend-api/wham/usage` per spec 05 §5.7.
//! Reads codex credentials via the SAME channel as the daemon's
//! production paths: `resolve_slot_to_uuid` → `credentials_codex_path_for`
//! for the identity-store path, with legacy fallback to
//! `credentials/codex-<N>.json` via `binding_path` when no UUID mapping
//! exists (pre-A++ installs). The probe does NOT read `~/.codex/auth.json`
//! — that file is codex-cli's standalone state, csq-unmanaged. Reading
//! it would violate `account-terminal-separation.md` MUST Rule 4
//! (diagnostic-daemon parity). Origin: an internal ticket.
//!
//! Reuses `crate::http::codex::fetch_wham_usage` (Node bridge — direct
//! reqwest is body-stripped by Cloudflare). Six load-bearing assertions.

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SkipReason, SCHEMA_VERSION};
use crate::credentials::file as cred_file;
use crate::http::codex as codex_http;
use crate::types::AccountNum;
use std::path::Path;
use std::time::Instant;

const CELL_NAME: &str = "codex-oauth";
const SPEC_ANCHOR: &str = "05§5.7";
const ENDPOINT_URL: &str = "https://chatgpt.com/backend-api/wham/usage";

pub fn probe(base_dir: &Path, slot: AccountNum) -> ProbeRecord {
    let started = Instant::now();

    // Resolve credential path via the same chain as the daemon's
    // usage poller (`daemon/usage_poller/codex.rs:188-200`) and the
    // handle-dir spawn (`session/handle_dir.rs:402-408`):
    //   1. `resolve_slot_to_uuid` → Some(uuid) → identity-store path.
    //   2. None → legacy `credentials/codex-<N>.json` fallback.
    let creds_path = match crate::accounts::profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        Some(uuid) => crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid),
        None => crate::providers::codex::provisioning::binding_path(base_dir, slot),
    };

    let creds = match cred_file::load(&creds_path) {
        Ok(c) => c,
        Err(_e) => {
            // Do NOT propagate `creds_path.display()` or `{e}` — the resolved
            // path (`/Users/<u>/.claude/accounts/identities/<UUID>/...`)
            // leaks OS username + home-dir + UUID; cred_file error Display
            // may echo paths (security.md §2, §8). The `NoCodexCredentials`
            // Skip arm carries fixed-vocabulary path-free strings.
            return super::skipped(
                slot,
                CELL_NAME,
                SPEC_ANCHOR,
                "prereq",
                SkipReason::NoCodexCredentials,
            );
        }
    };
    let codex_creds = match creds.codex() {
        Some(c) => c,
        None => {
            // Wrong-variant: the credential file parsed but does not carry
            // the Codex variant (operator pasted an Anthropic-shape payload
            // at the codex path, OR identity store contains an unexpected
            // shape). Route through `WrongVariantBinding` for the canonical
            // operator-facing strings + `csq logout/login` remediation.
            return super::skipped(
                slot,
                CELL_NAME,
                SPEC_ANCHOR,
                "prereq",
                SkipReason::WrongVariantBinding {
                    surface: crate::providers::catalog::Surface::Codex,
                    observed_kind: creds.observed_variant_tag(),
                },
            );
        }
    };

    let access_token = codex_creds.tokens.access_token.clone();
    let result = codex_http::fetch_wham_usage(&access_token);
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(snapshot) => evaluate(slot, snapshot, elapsed_ms),
        Err(e) => fail_codex_http(slot, elapsed_ms, &e),
    }
}

fn evaluate(slot: AccountNum, snapshot: codex_http::WhamSnapshot, elapsed_ms: u64) -> ProbeRecord {
    // A1: HTTP 200 — implicit (fetch_wham_usage returns Ok only on
    // 200 + parse). A2-A4: WhamSnapshot deserialization handles
    // structural assertions (rate_limit.{primary,secondary}_window
    // present, used_percent + reset_at fields).
    let primary = &snapshot.rate_limit.primary_window;
    // `secondary_window` is nullable since 2026-07 (pro plans send a single
    // 7-day `primary_window` + `secondary_window: null`). A null secondary is
    // VALID, not a probe failure — the A2/A3/A4 secondary checks only run when
    // it is present.
    let secondary = snapshot.rate_limit.secondary_window.as_ref();

    // A2: used_percent in [0, 100] for both windows.
    if !(0.0..=100.0).contains(&primary.used_percent) {
        return fail(
            slot,
            elapsed_ms,
            1,
            "A2: 0.0 <= primary_window.used_percent <= 100.0",
            &format!("primary.used_percent = {}", primary.used_percent),
            "spec 05 §5.7: used_percent is already a percentage (0-100), not a fraction. Out-of-range value is upstream schema drift.",
        );
    }
    if let Some(secondary) = secondary {
        if !(0.0..=100.0).contains(&secondary.used_percent) {
            return fail(
                slot,
                elapsed_ms,
                2,
                "A2: 0.0 <= secondary_window.used_percent <= 100.0",
                &format!("secondary.used_percent = {}", secondary.used_percent),
                "spec 05 §5.7: used_percent is a percentage (0-100). Out-of-range = drift.",
            );
        }
    }

    // A3: reset_at is in the future for both windows.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if primary.reset_at <= now {
        return fail(
            slot,
            elapsed_ms,
            3,
            "A3: primary_window.reset_at > now()",
            &format!("primary.reset_at = {}, now = {}", primary.reset_at, now),
            "reset time is in the past; possible clock skew or stale upstream response.",
        );
    }
    if let Some(secondary) = secondary {
        if secondary.reset_at <= now {
            return fail(
                slot,
                elapsed_ms,
                4,
                "A3: secondary_window.reset_at > now()",
                &format!("secondary.reset_at = {}, now = {}", secondary.reset_at, now),
                "reset time is in the past; possible clock skew or stale upstream response.",
            );
        }
    }

    // A4: clock-skew sanity for both windows per spec 05 §5.7
    // (`abs(reset_at - now() - reset_after_seconds) <= 5s`). Round-1
    // redteam M2-d: previously discarded; now surfaced as Fail when
    // skew exceeds 5s.
    const CLOCK_SKEW_TOLERANCE_S: i64 = 5;
    let primary_skew = clock_skew(primary.reset_at, now, primary.reset_after_seconds);
    if primary_skew.abs() > CLOCK_SKEW_TOLERANCE_S {
        return fail(
            slot,
            elapsed_ms,
            5,
            "A4: |primary_window clock_skew| <= 5s",
            &format!("primary_skew = {primary_skew}s"),
            "spec 05 §5.7: reset_at vs (now + reset_after_seconds) must agree within 5s. Operator clock or upstream out of sync.",
        );
    }
    if let Some(secondary) = secondary {
        let secondary_skew = clock_skew(secondary.reset_at, now, secondary.reset_after_seconds);
        if secondary_skew.abs() > CLOCK_SKEW_TOLERANCE_S {
            return fail(
                slot,
                elapsed_ms,
                5,
                "A4: |secondary_window clock_skew| <= 5s",
                &format!("secondary_skew = {secondary_skew}s"),
                "spec 05 §5.7: reset_at vs (now + reset_after_seconds) must agree within 5s. Operator clock or upstream out of sync.",
            );
        }
    }

    // A5: plan_type is non-empty.
    if snapshot.plan_type.is_empty() {
        return fail(
            slot,
            elapsed_ms,
            6,
            "A5: plan_type is non-empty",
            "plan_type = \"\"",
            "spec 05 §5.7: plan_type is a UI label; empty string is upstream drift.",
        );
    }

    // A6: rate_limit.{allowed, limit_reached} field existence is enforced by
    // the WhamSnapshot deserialize layer — if missing, fetch_wham_usage
    // returns `MalformedResponse` before reaching here. No runtime check
    // needed.

    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Ok,
        endpoint: ENDPOINT_URL.to_string(),
        elapsed_ms,
        assertions_passed: 6,
        assertions_total: 6,
        diagnostic: None,
        redacted_response_excerpt: None,
    }
}

fn clock_skew(reset_at: u64, now: u64, reset_after_seconds: u64) -> i64 {
    (reset_at as i64) - (now as i64) - (reset_after_seconds as i64)
}

fn fail_codex_http(
    slot: AccountNum,
    elapsed_ms: u64,
    e: &codex_http::CodexHttpError,
) -> ProbeRecord {
    use codex_http::CodexHttpError as E;
    let (assertion, hint): (&str, &str) = match e {
        E::TokenExpired => (
            "A1: HTTP 200",
            "401/token_expired — the daemon refresher should rotate this. Check `csq daemon status` and refresher logs.",
        ),
        E::RefreshReused => (
            "A1: HTTP 200",
            "OpenAI rotates refresh tokens; reusing a stale one fails. Run `codex login` to re-authorize.",
        ),
        E::TokenInvalidated => (
            "A1: HTTP 200",
            "401/token_invalidated — ChatGPT revoked this token server-side (typically because a newer login on the same account minted a replacement chain). Run `csq login <N> --provider codex` to mint a fresh chain.",
        ),
        E::Upstream { status, .. } if *status == 429 => (
            "A1: HTTP 200",
            "429 — rate limited by ChatGPT. Wait and retry; not a code regression.",
        ),
        E::Upstream { .. } => (
            "A1: HTTP 200",
            "Upstream returned an unexpected error. Check chatgpt.com status and retry.",
        ),
        E::MalformedResponse { .. } => (
            "A2: body parses as WhamSnapshot",
            "spec 05 §5.7: response did not match WhamSnapshot. Upstream schema drift. File a provider-drift issue.",
        ),
        E::Transport => (
            "transport: request reached endpoint",
            "Node bridge or TLS handshake failed. Check internet + Node runtime.",
        ),
    };
    fail(slot, elapsed_ms, 0, assertion, &format!("{e}"), hint)
}

fn fail(
    slot: AccountNum,
    elapsed_ms: u64,
    assertions_passed: u32,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
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
        redacted_response_excerpt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::codex::{WhamRateLimit, WhamSnapshot, WhamWindow};

    fn slot1() -> AccountNum {
        AccountNum::try_from(1).unwrap()
    }

    fn future_window(used: f64) -> WhamWindow {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        WhamWindow {
            used_percent: used,
            limit_window_seconds: 18000,
            reset_after_seconds: 18000,
            reset_at: now + 18000,
        }
    }

    fn ok_snapshot() -> WhamSnapshot {
        WhamSnapshot {
            plan_type: "plus".into(),
            rate_limit: WhamRateLimit {
                allowed: true,
                limit_reached: false,
                primary_window: future_window(42.0),
                secondary_window: Some(future_window(15.0)),
            },
        }
    }

    #[test]
    fn evaluate_ok_when_snapshot_matches_contract() {
        let r = evaluate(slot1(), ok_snapshot(), 100);
        assert_eq!(r.status, ProbeStatus::Ok);
        assert_eq!(r.assertions_passed, 6);
    }

    #[test]
    fn evaluate_fails_on_primary_used_above_100() {
        let mut s = ok_snapshot();
        s.rate_limit.primary_window.used_percent = 150.0;
        let r = evaluate(slot1(), s, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("primary"));
    }

    #[test]
    fn evaluate_fails_on_past_reset_at() {
        let mut s = ok_snapshot();
        s.rate_limit.primary_window.reset_at = 0;
        let r = evaluate(slot1(), s, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("A3"));
    }

    #[test]
    fn evaluate_fails_on_empty_plan_type() {
        let mut s = ok_snapshot();
        s.plan_type = "".into();
        let r = evaluate(slot1(), s, 100);
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d.failed_assertion.contains("plan_type"));
    }

    #[test]
    fn fail_codex_http_maps_token_expired() {
        let r = fail_codex_http(slot1(), 100, &codex_http::CodexHttpError::TokenExpired);
        assert_eq!(r.status, ProbeStatus::Fail);
        assert!(r.diagnostic.unwrap().hint.contains("refresher"));
    }

    #[test]
    fn fail_codex_http_maps_token_invalidated_to_actionable_hint() {
        // The catch-all `Upstream { .. }` arm produces "Check chatgpt.com
        // status and retry" which is misleading — the operator action is
        // `csq login`, not "wait for upstream". Pin the specific hint so
        // future redteam rounds catch any regression to the generic arm.
        let r = fail_codex_http(slot1(), 100, &codex_http::CodexHttpError::TokenInvalidated);
        assert_eq!(r.status, ProbeStatus::Fail);
        let hint = r.diagnostic.unwrap().hint;
        assert!(
            hint.contains("token_invalidated"),
            "hint must name the code so operator can grep journal/docs: {hint:?}"
        );
        assert!(
            hint.contains("csq login"),
            "hint must point at the corrective action (re-login): {hint:?}"
        );
        assert!(
            !hint.contains("Check chatgpt.com status"),
            "hint must NOT fall through to the catch-all Upstream arm: {hint:?}"
        );
    }

    /// an internal ticket sibling + an internal ticket follow-up: the codex-oauth probe's missing-creds
    /// Skip arm (post-an internal ticket = `SkipReason::NoCodexCredentials`) MUST NOT
    /// interpolate any resolved path (identity-store, legacy, or otherwise)
    /// into operator-facing strings — `security.md` §2 (no path-bearing
    /// detail in operator output). Slot number is on `ProbeRecord.slot`.
    #[test]
    fn codex_auth_missing_diagnostic_is_path_free() {
        // Empty base_dir — no profiles.json, no credentials/codex-<N>.json,
        // no identities/. Both credential channels return absent →
        // `cred_file::load` Err → `NoCodexCredentials` Skip.
        let base = tempfile::tempdir().unwrap();
        let r = probe(base.path(), slot1());

        assert_eq!(r.status, ProbeStatus::Skipped);
        let diag = r.diagnostic.as_ref().unwrap();
        assert_eq!(
            diag.failed_assertion, "prerequisite: slot has codex credentials",
            "failed_assertion MUST match canonical NoCodexCredentials text; got: {:?}",
            diag.failed_assertion
        );
        assert_eq!(
            diag.observed_shape, "missing",
            "observed_shape MUST be exactly \"missing\" (path-free); got: {:?}",
            diag.observed_shape
        );

        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("/Users/"),
            "codex_oauth NoCodexCredentials record MUST NOT contain /Users/ path; got: {json}"
        );
        assert!(
            !json.contains("/private/"),
            "codex_oauth NoCodexCredentials record MUST NOT contain /private/ path; got: {json}"
        );
        assert!(
            !json.contains("/tmp/"),
            "codex_oauth NoCodexCredentials record MUST NOT contain /tmp/ path; got: {json}"
        );
        assert!(
            !json.contains("/var/folders/"),
            "codex_oauth NoCodexCredentials record MUST NOT contain /var/folders/ path; got: {json}"
        );
        assert!(
            !diag.observed_shape.contains('/'),
            "observed_shape MUST NOT contain path separator; got: {:?}",
            diag.observed_shape
        );
    }
}
