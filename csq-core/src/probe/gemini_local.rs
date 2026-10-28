//! Cells 07 + 08 — Gemini event-driven local-state probes.
//!
//! Per spec 11 §11.2 Cells 07/08: Gemini ApiKey + Vertex SA slots are
//! event-driven (no remote quota endpoint). The probe asserts on
//! local `quota.json` shape rather than making an HTTP call.
//!
//! Cell 07 (ApiKey) — 5 assertions:
//! 1. `quota.json[N].surface == "gemini"` AND `kind == "counter"`.
//! 2. `counter.requests_today: u64` is present and parses.
//! 3. `counter.resets_at_tz == "America/Los_Angeles"` (ADR-G05).
//! 4. If `rate_limit.active == true`, `rate_limit.reset_at: Option<i64>`
//!    is `Some` with a Unix epoch in the future.
//! 5. `selected_model`, `effective_model` are both present.
//!
//! Cell 08 (Vertex SA) — Cell 07 + 2 extra:
//! 6. Slot's `auth_mode == VertexSa`.
//! 7. `~/.config/gcloud/application_default_credentials.json` exists
//!    and is `0o600`.

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SCHEMA_VERSION};
use crate::quota::state as quota_state;
use crate::types::AccountNum;
use std::path::Path;
use std::time::Instant;

const CELL_API_KEY: &str = "gemini-api-key";
const CELL_VERTEX_SA: &str = "gemini-vertex-sa";
const SPEC_ANCHOR: &str = "11§11.2-Cell07/08";

/// Cell 07 entry point. `base_dir` is csq's accounts root.
pub fn probe_api_key(slot: AccountNum, base_dir: &Path) -> ProbeRecord {
    probe_inner(slot, base_dir, CELL_API_KEY, 5, None)
}

/// Cell 08 entry point. `sa_path` is the absolute path the slot's
/// VertexSa binding points at.
pub fn probe_vertex_sa(slot: AccountNum, base_dir: &Path, sa_path: &Path) -> ProbeRecord {
    probe_inner(
        slot,
        base_dir,
        CELL_VERTEX_SA,
        7,
        Some(sa_path.to_path_buf()),
    )
}

fn probe_inner(
    slot: AccountNum,
    base_dir: &Path,
    cell_name: &'static str,
    total: u32,
    sa_path: Option<std::path::PathBuf>,
) -> ProbeRecord {
    let started = Instant::now();
    // Load quota.json; assert the slot's row matches the contract.
    let quota_file = match quota_state::load_state(base_dir) {
        Ok(qf) => qf,
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return prereq_skip(
                slot,
                cell_name,
                elapsed_ms,
                "prerequisite: quota.json present + parseable",
                &format!("load failure: {e}"),
                "the daemon's usage poller writes quota.json; ensure `csq daemon start` is running.",
                total,
            );
        }
    };
    let row = match quota_file.accounts.get(&slot.get().to_string()) {
        Some(r) => r.clone(),
        None => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return prereq_skip(
                slot,
                cell_name,
                elapsed_ms,
                "prerequisite: quota.json has row for this slot",
                &format!("no `accounts.{}` entry", slot.get()),
                "the daemon hasn't recorded a quota event for this slot yet — spawn `gemini` once and retry.",
                total,
            );
        }
    };

    evaluate_row(slot, &row, cell_name, total, sa_path.as_deref(), started)
}

/// Round-1 redteam H2-int: extracted from `probe_inner` so unit tests
/// can drive the assertion sequence with a hand-built `AccountQuota`
/// instead of re-implementing the assertion order in a test fake (the
/// previous `tests::run()` was a fidelity gap — production logic
/// changes wouldn't surface in tests).
fn evaluate_row(
    slot: AccountNum,
    row: &crate::quota::AccountQuota,
    cell_name: &'static str,
    total: u32,
    sa_path: Option<&Path>,
    started: Instant,
) -> ProbeRecord {
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let mut passed: u32 = 0;

    // A1: surface + kind.
    if row.surface != "gemini" {
        return fail(
            slot,
            cell_name,
            elapsed_ms,
            passed,
            total,
            "A1: surface == \"gemini\"",
            &format!("surface = {:?}", row.surface),
            "the quota.json row was not stamped by a Gemini event — check the slot's binding.",
        );
    }
    if row.kind != "counter" {
        return fail(
            slot,
            cell_name,
            elapsed_ms,
            passed,
            total,
            "A1: kind == \"counter\"",
            &format!("kind = {:?}", row.kind),
            "spec 05 §5.8: Gemini ApiKey/VertexSa slots use event-driven counter, not utilization.",
        );
    }
    passed = 1;

    // A2: counter.requests_today is present (defaulted to 0 by serde
    // when missing; the structural shape check is whether the counter
    // sub-object exists at all).
    let counter = match &row.counter {
        Some(c) => c,
        None => {
            return fail(
                slot,
                cell_name,
                elapsed_ms,
                passed,
                total,
                "A2: counter sub-object present",
                "counter = null",
                "spec 05 §5.8 + spec 07 §7.4.1: Gemini counter slots MUST have a `counter` sub-object.",
            );
        }
    };
    let _requests_today: u64 = counter.requests_today;
    passed = 2;

    // A3: counter.resets_at_tz == "America/Los_Angeles".
    if counter.resets_at_tz != "America/Los_Angeles" {
        return fail(
            slot,
            cell_name,
            elapsed_ms,
            passed,
            total,
            "A3: counter.resets_at_tz == \"America/Los_Angeles\"",
            &format!("resets_at_tz = {:?}", counter.resets_at_tz),
            "ADR-G05 pins TZ to America/Los_Angeles for DST-correctness; any other value is a regression.",
        );
    }
    passed = 3;

    // A4: rate_limit.active==true ⇒ reset_at present + future ISO ts.
    if let Some(rl) = &row.rate_limit {
        if rl.active {
            let reset_at = match &rl.reset_at {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return fail(
                        slot,
                        cell_name,
                        elapsed_ms,
                        passed,
                        total,
                        "A4: rate_limit.active=true requires reset_at present",
                        "rate_limit.reset_at = None or empty",
                        "spec 11 §11.2 Cell 07: an active rate limit MUST carry the reset timestamp.",
                    );
                }
            };
            // Verify ISO-8601 parse + future-ness (reuse the parser
            // from anthropic_oauth via local re-implementation for
            // simplicity — the shape is the same).
            if !looks_like_future_iso8601(reset_at) {
                return fail(
                    slot,
                    cell_name,
                    elapsed_ms,
                    passed,
                    total,
                    "A4: rate_limit.reset_at parses + is in the future",
                    &format!("reset_at = {reset_at:?}"),
                    "spec 11 §11.2 Cell 07: reset_at MUST be RFC3339 UTC and in the future when active.",
                );
            }
        }
    }
    passed = 4;

    // A5: selected_model + effective_model both present.
    if row.selected_model.is_none() {
        return fail(
            slot,
            cell_name,
            elapsed_ms,
            passed,
            total,
            "A5: selected_model is present",
            "selected_model = None",
            "spec 11 §11.2 Cell 07: selected_model is recorded from the spawn-event capture.",
        );
    }
    if row.effective_model.is_none() {
        return fail(
            slot,
            cell_name,
            elapsed_ms,
            passed,
            total,
            "A5: effective_model is present",
            "effective_model = None",
            "spec 11 §11.2 Cell 07: effective_model is recorded from response capture; a Gemini slot that never produced a response will have None — spawn once and retry.",
        );
    }
    passed = 5;

    let sa_path = match sa_path {
        None => {
            // Cell 07 (ApiKey) ends here at A5.
            return ok(slot, cell_name, elapsed_ms, passed, total);
        }
        Some(p) => p,
    };

    // VertexSa-only assertions (A6 + A7).
    // A6: the binding's `auth_mode == VertexSa` was asserted by the
    // caller via the match arm in `probe_slot`, so reaching here is
    // structurally that assertion holding.
    passed = 6;

    // A7: SA file at the path the binding points to exists + is a
    // regular file (NOT a symlink) + is 0o400-or-0o600.
    //
    // Round-1 redteam H4-sec: use `symlink_metadata` and refuse if
    // the path is a symlink. Otherwise a malicious binding could
    // redirect the read at an arbitrary same-UID file. Mirrors the
    // defense in `code_assist_quota::read_oauth_creds_once`.
    // Do NOT interpolate `sa_path.display()` into observed_shape OR hint —
    // the SA path is an operator-configured absolute filesystem path that
    // typically resolves to `/Users/<u>/...` (OS username + home-dir layout
    // leak per security.md §2). Canonical role is named in failed_assertion;
    // the operator already knows the path because they configured it as
    // the slot's binding.
    let meta = match std::fs::symlink_metadata(sa_path) {
        Ok(m) => m,
        Err(_e) => {
            return fail(
                slot,
                cell_name,
                elapsed_ms,
                passed,
                total,
                "A7: VertexSa SA file exists at the bound path",
                "missing or unreadable at bound path",
                "spec 11 §11.2 Cell 08: the slot's binding points at this path; ensure the file is present.",
            );
        }
    };
    if !meta.file_type().is_file() {
        return fail(
            slot,
            cell_name,
            elapsed_ms,
            passed,
            total,
            "A7: VertexSa SA path is a regular file (not a symlink)",
            &format!("not a regular file (file_type = {:?})", meta.file_type()),
            "spec 11 §11.2 Cell 08: SA credentials MUST be a regular file. Symlinks are rejected (TOCTOU + arbitrary-file-read defense).",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        // 0o400 (read-only owner) and 0o600 (rw owner) are both
        // acceptable per provisioning's "0o400-or-stricter" rule.
        if mode & 0o077 != 0 {
            return fail(
                slot,
                cell_name,
                elapsed_ms,
                passed,
                total,
                "A7: VertexSa SA file mode has no group/world bits",
                &format!("mode = 0o{mode:03o}"),
                "spec 11 §11.2 Cell 08: SA credentials MUST be 0o400 or 0o600. Run `chmod 600` on the SA file at the path bound in this slot's settings.json.",
            );
        }
    }
    #[cfg(not(unix))]
    {
        // Windows + non-Unix: skip the mode check; the file's
        // existence is the load-bearing assertion there.
        let _ = meta;
    }
    passed = 7;

    ok(slot, cell_name, elapsed_ms, passed, total)
}

/// Returns true iff `s` is an RFC3339 UTC timestamp whose epoch is
/// strictly greater than now.
///
/// Round-2 redteam C4: previously a structural year-only check using a
/// 365.25-day approximation that drifted ~6 hours/year and could
/// classify a `2025-12-31T23:59:59Z` reset_at as future during the first
/// few hours of 2026. Now uses the exact RFC3339 parser already in
/// `super::anthropic_oauth::parse_iso8601_to_epoch` so the comparison
/// is bit-exact against `SystemTime::now()`.
fn looks_like_future_iso8601(s: &str) -> bool {
    let Some(epoch) = super::anthropic_oauth::parse_iso8601_to_epoch(s) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch > now
}

#[allow(clippy::too_many_arguments)]
fn fail(
    slot: AccountNum,
    cell_name: &'static str,
    elapsed_ms: u64,
    passed: u32,
    total: u32,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: cell_name,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Fail,
        endpoint: "local: quota.json".to_string(),
        elapsed_ms,
        assertions_passed: passed,
        assertions_total: total,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed_assertion.to_string(),
            observed_shape: observed_shape.to_string(),
            hint: hint.to_string(),
        }),
        redacted_response_excerpt: None,
    }
}

fn ok(
    slot: AccountNum,
    cell_name: &'static str,
    elapsed_ms: u64,
    passed: u32,
    total: u32,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: cell_name,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Ok,
        endpoint: "local: quota.json".to_string(),
        elapsed_ms,
        assertions_passed: passed,
        assertions_total: total,
        diagnostic: None,
        redacted_response_excerpt: None,
    }
}

fn prereq_skip(
    slot: AccountNum,
    cell_name: &'static str,
    elapsed_ms: u64,
    failed: &str,
    observed: &str,
    hint: &str,
    total: u32,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: cell_name,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Skipped,
        endpoint: "local: quota.json".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::gemini::provisioning::AuthMode;
    use crate::quota::{AccountQuota, CounterState, RateLimitState};

    fn ok_row() -> AccountQuota {
        AccountQuota {
            surface: "gemini".into(),
            kind: "counter".into(),
            counter: Some(CounterState {
                requests_today: 17,
                resets_at_tz: "America/Los_Angeles".into(),
                last_reset: None,
            }),
            rate_limit: Some(RateLimitState::default()),
            selected_model: Some("gemini-2.5-pro".into()),
            effective_model: Some("gemini-2.5-pro".into()),
            ..Default::default()
        }
    }

    fn run(row: &AccountQuota, mode: AuthMode) -> ProbeRecord {
        // Round-1 redteam H2-int: drive `evaluate_row` directly so
        // tests exercise production logic, not a parallel re-implementation.
        let slot = AccountNum::try_from(1).unwrap();
        let (cell_name, total, sa_path): (&'static str, u32, Option<&Path>) = match mode {
            AuthMode::ApiKey => (CELL_API_KEY, 5, None),
            AuthMode::VertexSa { .. } => (CELL_VERTEX_SA, 7, None),
            AuthMode::CodeAssistOAuth => unreachable!(),
        };
        evaluate_row(slot, row, cell_name, total, sa_path, Instant::now())
    }

    #[test]
    fn ok_row_passes_api_key_assertions() {
        let row = ok_row();
        let r = run(&row, AuthMode::ApiKey);
        assert_eq!(r.status, ProbeStatus::Ok);
        assert_eq!(r.assertions_passed, 5);
    }

    #[test]
    fn fails_when_surface_not_gemini() {
        let mut row = ok_row();
        row.surface = "claude-code".into();
        let r = run(&row, AuthMode::ApiKey);
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    #[test]
    fn fails_when_kind_not_counter() {
        let mut row = ok_row();
        row.kind = "utilization".into();
        let r = run(&row, AuthMode::ApiKey);
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    #[test]
    fn fails_when_resets_at_tz_drifts_from_los_angeles() {
        let mut row = ok_row();
        row.counter.as_mut().unwrap().resets_at_tz = "UTC".into();
        let r = run(&row, AuthMode::ApiKey);
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    #[test]
    fn fails_when_models_missing() {
        let mut row = ok_row();
        row.selected_model = None;
        let r = run(&row, AuthMode::ApiKey);
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    #[test]
    fn looks_like_future_iso8601_accepts_zulu() {
        assert!(looks_like_future_iso8601("2099-01-01T00:00:00Z"));
    }

    #[test]
    fn looks_like_future_iso8601_rejects_short() {
        assert!(!looks_like_future_iso8601("2099-01-01"));
    }

    #[test]
    fn looks_like_future_iso8601_rejects_past_year() {
        assert!(!looks_like_future_iso8601("2000-01-01T00:00:00Z"));
    }

    /// an internal ticket sibling: A7 VertexSa SA-file failures MUST NOT interpolate the
    /// operator-configured `sa_path.display()` into observed_shape OR hint
    /// — `security.md` §2 (no path-bearing detail in operator-facing
    /// strings). The path typically resolves to `/Users/<u>/...`; canonical
    /// role is named in failed_assertion; the operator already knows the
    /// path from their slot's settings.json binding.
    #[test]
    fn vertex_sa_missing_file_diagnostic_is_path_free() {
        let row = ok_row();
        let base = tempfile::tempdir().unwrap();
        // Point sa_path at a /Users/-shaped absolute path that does NOT
        // exist on disk; symlink_metadata will return Err(NotFound),
        // driving the A7 failure branch.
        let sa_path = std::path::PathBuf::from("/Users/leak-test/.gcloud/sa-creds.json");
        let slot = AccountNum::try_from(1).unwrap();
        let r = evaluate_row(
            slot,
            &row,
            CELL_VERTEX_SA,
            7,
            Some(sa_path.as_path()),
            Instant::now(),
        );
        let _ = base; // tempdir kept alive for the call; not used directly

        assert_eq!(r.status, ProbeStatus::Fail);
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.failed_assertion.starts_with("A7:"),
            "expected A7 failure, got: {:?}",
            diag.failed_assertion
        );

        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("/Users/"),
            "VertexSa A7 record MUST NOT contain /Users/ path; got: {json}"
        );
        assert!(
            !json.contains("leak-test"),
            "VertexSa A7 record MUST NOT echo sa_path content; got: {json}"
        );
        assert!(
            !diag.observed_shape.contains('/'),
            "observed_shape MUST NOT contain path separator; got: {:?}",
            diag.observed_shape
        );
        // The hint also MUST NOT carry the sa_path — fix-instruction text
        // is operator-facing and `security.md` §2 applies to all fields.
        assert!(
            !diag.hint.contains("/Users/"),
            "hint MUST NOT contain /Users/ path; got: {:?}",
            diag.hint
        );
        assert!(
            !diag.hint.contains("leak-test"),
            "hint MUST NOT echo sa_path content; got: {:?}",
            diag.hint
        );
    }
}
