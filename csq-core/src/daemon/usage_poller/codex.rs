//! Codex (ChatGPT subscription) usage polling.
//!
//! Polls `GET chatgpt.com/backend-api/wham/usage` for each Codex account,
//! parses the response per the schema pinned in
//! `workspaces/codex/journal/0010`, and writes quota data to `quota.json`.
//!
//! # Surface dispatch
//!
//! Runs on the same 5-minute cadence as the Anthropic poller (see
//! [`super::POLL_INTERVAL`]) but uses a DIFFERENT transport: Codex sits
//! behind Cloudflare's JA3/JA4 TLS fingerprint filter which body-strips
//! reqwest responses (journal 0007). This module accepts the Node
//! subprocess transport via the `http_get_codex` closure — production
//! wires `http::get_bearer_node`, tests pass a mock.
//!
//! # Circuit breaker
//!
//! Separate from the Anthropic poller's per-call 10-minute cooldown.
//! Rationale: codex-cli stops being invoked if its subscription account
//! is unreachable, and repeated failed polls are signal — not noise —
//! that a user needs to re-login. The breaker is DIAGNOSTIC, not a
//! rate-limiter: it prevents the daemon from burning cycles on a known-
//! broken slot while keeping the error surface visible in logs.
//!
//! - `CODEX_BREAKER_FAIL_THRESHOLD` = 5 consecutive failures trips the
//!   breaker.
//! - `CODEX_BREAKER_BASE_COOLDOWN` = 15 minutes on first trip.
//! - Doubles on each subsequent consecutive failure; capped at
//!   `CODEX_BREAKER_MAX_COOLDOWN` = 80 minutes.
//! - Any successful poll resets the fail counter + cooldown.
//!
//! # Raw-body + drift capture
//!
//! On a successful parse, the PII-scrubbed raw body is written to
//! `accounts/codex-wham-raw.json` (0o600) for operator diagnosis. On a
//! `MalformedResponse { status: 200 }` — indicating upstream schema
//! drift — the body is written to `accounts/codex-wham-drift.json`
//! (0o600) so the next session can inspect what changed. Both paths are
//! listed in `.gitignore` and pass through a PII-stripping redactor that
//! removes `user_id`, `account_id`, `email`, any `sub` JWT claim, and
//! any OAuth token patterns (via [`crate::error::redact_tokens`]).

use crate::accounts::{discovery, AccountSource};
use crate::credentials::{self, file as cred_file};
use crate::error::redact_tokens;
use crate::http::codex::{parse_wham_response, WhamSnapshot};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::providers::catalog::Surface;
use crate::quota::{state as quota_state, AccountQuota, QuotaFile, UsageWindow};
use crate::types::AccountNum;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::{HttpGetFn, PollError, CALL_TIMEOUT, MAX_ACCOUNTS_PER_TICK};

// ─── Circuit-breaker constants ─────────────────────────────────────────

/// Consecutive-failure count that trips the circuit breaker.
pub(crate) const CODEX_BREAKER_FAIL_THRESHOLD: u32 = 5;

/// Base cooldown applied the first time the breaker trips.
pub(crate) const CODEX_BREAKER_BASE_COOLDOWN: Duration = Duration::from_secs(15 * 60);

/// Upper bound on the doubling breaker cooldown.
pub(crate) const CODEX_BREAKER_MAX_COOLDOWN: Duration = Duration::from_secs(80 * 60);

// ─── Circuit-breaker state ─────────────────────────────────────────────

/// Per-account breaker state. Tracks consecutive failures plus the
/// `cooldown_until` instant that gates the next allowed poll.
#[derive(Debug, Clone, Default)]
pub(crate) struct BreakerState {
    /// Count of consecutive failed polls since the last success.
    pub fails: u32,
    /// Earliest instant at which another poll is allowed. `None` means
    /// no cooldown active.
    pub cooldown_until: Option<Instant>,
}

impl BreakerState {
    /// Returns true if the breaker is currently blocking polls for this
    /// account.
    pub fn is_open(&self, now: Instant) -> bool {
        match self.cooldown_until {
            Some(until) => now < until,
            None => false,
        }
    }

    /// Records a failed poll. Trips the breaker at
    /// [`CODEX_BREAKER_FAIL_THRESHOLD`] failures; doubles the cooldown
    /// on each subsequent consecutive failure up to
    /// [`CODEX_BREAKER_MAX_COOLDOWN`].
    pub fn record_failure(&mut self, now: Instant) {
        self.fails = self.fails.saturating_add(1);
        if self.fails < CODEX_BREAKER_FAIL_THRESHOLD {
            return;
        }

        // Compute cooldown: base * 2^(fails - threshold), capped.
        let over = self.fails - CODEX_BREAKER_FAIL_THRESHOLD;
        let multiplier = 1u64.checked_shl(over.min(16)).unwrap_or(u64::MAX);
        let cooldown_secs = CODEX_BREAKER_BASE_COOLDOWN
            .as_secs()
            .saturating_mul(multiplier);
        let cooldown = Duration::from_secs(cooldown_secs).min(CODEX_BREAKER_MAX_COOLDOWN);
        self.cooldown_until = Some(now + cooldown);
    }

    /// Records a successful poll. Resets fail counter + cooldown.
    pub fn record_success(&mut self) {
        self.fails = 0;
        self.cooldown_until = None;
    }
}

pub(crate) type BreakerMap = Arc<Mutex<HashMap<u16, BreakerState>>>;

pub(crate) fn breaker_is_open(map: &BreakerMap, account: u16, now: Instant) -> bool {
    let guard = map.lock().unwrap_or_else(|p| p.into_inner());
    match guard.get(&account) {
        Some(state) => state.is_open(now),
        None => false,
    }
}

pub(crate) fn breaker_record_failure(map: &BreakerMap, account: u16, now: Instant) {
    let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
    guard.entry(account).or_default().record_failure(now);
}

pub(crate) fn breaker_record_success(map: &BreakerMap, account: u16) {
    let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
    guard.entry(account).or_default().record_success();
}

// ─── Tick ──────────────────────────────────────────────────────────────

/// Runs a single Codex usage poller tick.
///
/// Discovers Codex accounts, polls wham/usage per-account via the Node
/// transport, applies the circuit breaker, writes `quota.json` on
/// success, and captures the raw body to disk for operator diagnosis.
pub(crate) async fn tick(base_dir: &Path, http_get_codex: &HttpGetFn, breakers: &BreakerMap) {
    debug!("codex usage poller tick starting");

    let mut accounts = discovery::discover_codex(base_dir);
    if accounts.len() > MAX_ACCOUNTS_PER_TICK {
        accounts.truncate(MAX_ACCOUNTS_PER_TICK);
    }

    let mut polled = 0usize;
    let mut skipped = 0usize;

    for info in accounts {
        if info.source != AccountSource::Codex || !info.has_credentials {
            continue;
        }

        let account = match AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Circuit-breaker gate
        if breaker_is_open(breakers, info.id, Instant::now()) {
            skipped += 1;
            continue;
        }

        // Read access token from the canonical Codex credential file.
        let canonical = cred_file::canonical_path_for(base_dir, account, Surface::Codex);
        let creds = match credentials::load(&canonical) {
            Ok(c) => c,
            Err(e) => {
                // CredentialError::Display may echo serde_json body
                // fragments — redact before formatting.
                warn!(
                    account = info.id,
                    error_kind = "codex_poll_cred_load_failed",
                    error = %redact_tokens(&e.to_string()),
                    "codex usage poller: failed to load credentials"
                );
                breaker_record_failure(breakers, info.id, Instant::now());
                continue;
            }
        };
        let token = match creds.codex() {
            Some(c) => c.tokens.access_token.clone(),
            None => {
                warn!(
                    account = info.id,
                    error_kind = "codex_poll_variant_mismatch",
                    "codex usage poller: credential file is not the Codex variant"
                );
                breaker_record_failure(breakers, info.id, Instant::now());
                continue;
            }
        };

        let http = Arc::clone(http_get_codex);
        let join_handle =
            tokio::task::spawn_blocking(move || poll_codex_usage_capture(&token, &http));
        let poll_result = tokio::time::timeout(CALL_TIMEOUT, join_handle).await;

        let poll_result = match poll_result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                warn!(
                    account = info.id,
                    error_kind = "codex_poll_timeout",
                    "codex usage poller: call timed out after 30s"
                );
                breaker_record_failure(breakers, info.id, Instant::now());
                continue;
            }
        };

        match poll_result {
            Ok(Ok((snapshot, raw_body))) => {
                if let Err(e) = write_wham_to_quota(base_dir, account, &snapshot) {
                    warn!(
                        account = info.id,
                        error_kind = "codex_poll_quota_write_failed",
                        error = %redact_tokens(&e.to_string()),
                        "codex usage poller: failed to write quota"
                    );
                    breaker_record_failure(breakers, info.id, Instant::now());
                    continue;
                }
                if let Err(e) = write_raw_capture(base_dir, &raw_body) {
                    debug!(
                        account = info.id,
                        error_kind = "codex_poll_raw_capture_failed",
                        error = %redact_tokens(&e.to_string()),
                        "codex usage poller: raw-body capture failed (non-fatal)"
                    );
                }
                breaker_record_success(breakers, info.id);
                polled += 1;
            }
            Ok(Err(PollCodexError::Drift { body })) => {
                // Schema drift: 200 OK but parser rejected the shape.
                // Capture body for operator diagnosis; degrade into
                // QuotaKind::Unknown in quota.json.
                warn!(
                    account = info.id,
                    error_kind = "codex_poll_schema_drift",
                    "codex usage poller: upstream shape drifted; capturing drift"
                );
                if let Err(e) = write_drift_capture(base_dir, &body) {
                    debug!(
                        account = info.id,
                        error_kind = "codex_poll_drift_capture_failed",
                        error = %redact_tokens(&e.to_string()),
                        "codex usage poller: drift capture write failed (non-fatal)"
                    );
                }
                if let Err(e) = write_unknown_to_quota(base_dir, account) {
                    warn!(
                        account = info.id,
                        error_kind = "codex_poll_unknown_write_failed",
                        error = %redact_tokens(&e.to_string()),
                        "codex usage poller: failed to write unknown-kind quota"
                    );
                }
                breaker_record_failure(breakers, info.id, Instant::now());
            }
            Ok(Err(PollCodexError::Poll(kind))) => {
                let tag = match kind {
                    PollError::RateLimited => "codex_poll_rate_limited",
                    PollError::Unauthorized => "codex_poll_unauthorized",
                    PollError::Transport(_) => "codex_poll_transport_error",
                    PollError::Parse(_) => "codex_poll_parse_error",
                    PollError::HttpError(_) => "codex_poll_http_error",
                };
                debug!(
                    account = info.id,
                    error_kind = tag,
                    "codex usage poller: tick failed"
                );
                breaker_record_failure(breakers, info.id, Instant::now());
            }
            Err(_join_err) => {
                warn!(
                    account = info.id,
                    error_kind = "codex_poll_task_panicked",
                    "codex usage poller: task panicked"
                );
                breaker_record_failure(breakers, info.id, Instant::now());
            }
        }
    }

    debug!(polled, skipped, "codex usage poller tick complete");
}

// ─── Poll + parse ──────────────────────────────────────────────────────

/// Per-call outcome: success (snapshot + raw body), drift (raw body only),
/// or a generic [`PollError`] for non-200 / transport failures.
#[derive(Debug)]
pub(crate) enum PollCodexError {
    /// Upstream returned 200 but the response shape did not match the
    /// pinned `WhamSnapshot` schema. Caller writes `raw` to
    /// `accounts/codex-wham-drift.json`.
    Drift { body: Vec<u8> },
    /// Generic poll failure (transport, 401, 429, non-200, bad JSON).
    Poll(PollError),
}

/// Polls wham/usage and returns both the parsed snapshot and the raw
/// body bytes (for raw-capture writing).
pub(crate) fn poll_codex_usage_capture(
    access_token: &str,
    http_get_codex: &HttpGetFn,
) -> Result<(WhamSnapshot, Vec<u8>), PollCodexError> {
    let url = crate::http::codex::WHAM_USAGE_URL;
    let (status, bytes) = http_get_codex(url, access_token, &[])
        .map_err(|e| PollCodexError::Poll(PollError::Transport(e)))?;

    // Map non-200s into the PollError hierarchy before touching the
    // body, so we never feed an error envelope into the success
    // capture path.
    match status {
        200 => {}
        429 => return Err(PollCodexError::Poll(PollError::RateLimited)),
        401 => return Err(PollCodexError::Poll(PollError::Unauthorized)),
        other => return Err(PollCodexError::Poll(PollError::HttpError(other))),
    }

    match parse_wham_response(status, &bytes) {
        Ok(snap) => Ok((snap, bytes)),
        Err(crate::http::codex::CodexHttpError::MalformedResponse { status: 200 }) => {
            Err(PollCodexError::Drift { body: bytes })
        }
        Err(_other) => Err(PollCodexError::Poll(PollError::Parse(
            "parse failed".into(),
        ))),
    }
}

// ─── Write path ────────────────────────────────────────────────────────

/// Writes a successful snapshot into `quota.json`.
pub(crate) fn write_wham_to_quota(
    base_dir: &Path,
    account: AccountNum,
    snapshot: &WhamSnapshot,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let primary = &snapshot.rate_limit.primary_window;
    let secondary = &snapshot.rate_limit.secondary_window;

    let extras = serde_json::json!({
        "plan_type": snapshot.plan_type,
        "allowed": snapshot.rate_limit.allowed,
        "limit_reached": snapshot.rate_limit.limit_reached,
    });

    quota.set(
        account.get(),
        AccountQuota {
            surface: "codex".into(),
            kind: "utilization".into(),
            five_hour: Some(UsageWindow {
                used_percentage: primary.used_percent,
                resets_at: primary.reset_at,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: secondary.used_percent,
                resets_at: secondary.reset_at,
            }),
            updated_at: now,
            extras: Some(extras),
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account.get(), "codex usage poller: quota updated");
    Ok(())
}

/// Writes a `QuotaKind::Unknown` degradation record for a schema-drift
/// event. Preserves any previous window values implicitly by writing
/// only the surface/kind/updated_at fields (five_hour / seven_day left
/// as None; downstream readers treat that as "no data").
pub(crate) fn write_unknown_to_quota(
    base_dir: &Path,
    account: AccountNum,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota.set(
        account.get(),
        AccountQuota {
            surface: "codex".into(),
            kind: "unknown".into(),
            updated_at: now,
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    Ok(())
}

// ─── Raw-body + drift capture ──────────────────────────────────────────

/// Path where PII-redacted successful wham/usage captures are written.
pub(crate) fn raw_capture_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join("accounts").join("codex-wham-raw.json")
}

/// Path where PII-redacted schema-drift captures are written.
pub(crate) fn drift_capture_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join("accounts").join("codex-wham-drift.json")
}

fn write_raw_capture(base_dir: &Path, body: &[u8]) -> std::io::Result<()> {
    write_redacted(&raw_capture_path(base_dir), body)
}

fn write_drift_capture(base_dir: &Path, body: &[u8]) -> std::io::Result<()> {
    write_redacted(&drift_capture_path(base_dir), body)
}

fn write_redacted(path: &Path, body: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let redacted = redact_pii_json(body);
    let tmp = unique_tmp_path(path);
    if let Err(e) = std::fs::write(&tmp, redacted.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = secure_file(&tmp).map_err(|pe| std::io::Error::other(pe.to_string())) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = atomic_replace(&tmp, path).map_err(|pe| std::io::Error::other(pe.to_string())) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Redacts PII from a wham/usage response body.
///
/// Two passes:
/// 1. JSON-aware replacement of `user_id`, `account_id`, `email`, and
///    any top-level `sub` (JWT-claim-style) field with fixed sentinels.
/// 2. Token-pattern redaction via [`redact_tokens`] for any remaining
///    `sk-*` / `rt_*` / JWT / long-hex matches (defense-in-depth
///    against nested fields carrying tokens).
///
/// Falls back to token-only redaction if the body is not valid JSON —
/// the drift capture is allowed to be non-JSON (that's the whole point
/// of the capture), but we still want PII defense-in-depth on whatever
/// the upstream returned.
pub(crate) fn redact_pii_json(body: &[u8]) -> String {
    // Try JSON-aware redaction first.
    if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) {
        redact_pii_value(&mut value);
        let serialized = serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| String::from_utf8_lossy(body).to_string());
        return redact_tokens(&serialized);
    }
    // Not JSON: best-effort — pass through the token redactor.
    let lossy = String::from_utf8_lossy(body).to_string();
    redact_tokens(&lossy)
}

fn redact_pii_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                match k.as_str() {
                    "user_id" => *v = serde_json::Value::String("REDACTED-user-id".into()),
                    "account_id" => *v = serde_json::Value::String("REDACTED-account-id".into()),
                    "email" => *v = serde_json::Value::String("REDACTED@example.invalid".into()),
                    "sub" => *v = serde_json::Value::String("REDACTED-sub".into()),
                    _ => redact_pii_value(v),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_pii_value(item);
            }
        }
        _ => {}
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        self, file as cred_file, CodexCredentialFile, CodexTokensFile, CredentialFile,
    };
    use crate::providers::catalog::Surface;
    use crate::quota::state as quota_state;
    use crate::types::AccountNum;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::TempDir;

    const WHAM_GOLDEN: &[u8] =
        include_bytes!("../../../tests/fixtures/codex/wham-usage-golden.json");

    // ── Circuit-breaker unit tests ────────────────────────────────

    #[test]
    fn breaker_closed_when_unused() {
        let s = BreakerState::default();
        assert!(!s.is_open(Instant::now()));
    }

    #[test]
    fn breaker_stays_closed_below_threshold() {
        let mut s = BreakerState::default();
        let now = Instant::now();
        for _ in 0..(CODEX_BREAKER_FAIL_THRESHOLD - 1) {
            s.record_failure(now);
        }
        assert!(!s.is_open(now));
    }

    #[test]
    fn breaker_trips_at_threshold_with_base_cooldown() {
        let mut s = BreakerState::default();
        let now = Instant::now();
        for _ in 0..CODEX_BREAKER_FAIL_THRESHOLD {
            s.record_failure(now);
        }
        assert!(s.is_open(now));
        assert!(s.is_open(now + CODEX_BREAKER_BASE_COOLDOWN - Duration::from_secs(1)));
        assert!(!s.is_open(now + CODEX_BREAKER_BASE_COOLDOWN + Duration::from_secs(1)));
    }

    #[test]
    fn breaker_doubles_on_each_subsequent_failure() {
        let mut s = BreakerState::default();
        let now = Instant::now();
        for _ in 0..CODEX_BREAKER_FAIL_THRESHOLD {
            s.record_failure(now);
        }
        let base = s.cooldown_until.unwrap() - now;
        s.record_failure(now);
        let second = s.cooldown_until.unwrap() - now;
        assert!(second >= base * 2 - Duration::from_secs(1));
    }

    #[test]
    fn breaker_caps_at_max_cooldown() {
        let mut s = BreakerState::default();
        let now = Instant::now();
        for _ in 0..100 {
            s.record_failure(now);
        }
        let cooldown = s.cooldown_until.unwrap() - now;
        assert!(cooldown <= CODEX_BREAKER_MAX_COOLDOWN);
    }

    #[test]
    fn breaker_success_clears_state() {
        let mut s = BreakerState::default();
        let now = Instant::now();
        for _ in 0..CODEX_BREAKER_FAIL_THRESHOLD {
            s.record_failure(now);
        }
        assert!(s.is_open(now));
        s.record_success();
        assert!(!s.is_open(now));
        assert_eq!(s.fails, 0);
    }

    // ── PII redactor tests ────────────────────────────────────────

    #[test]
    fn redact_pii_strips_top_level_identifiers() {
        let body = br#"{
            "user_id": "u_abc",
            "account_id": "acct_xyz",
            "email": "real@example.com",
            "plan_type": "plus"
        }"#;
        let redacted = redact_pii_json(body);
        assert!(!redacted.contains("u_abc"));
        assert!(!redacted.contains("acct_xyz"));
        assert!(!redacted.contains("real@example.com"));
        assert!(redacted.contains("plus"));
        assert!(redacted.contains("REDACTED-user-id"));
    }

    #[test]
    fn redact_pii_strips_nested_identifiers() {
        let body = br#"{
            "outer": { "user_id": "nested_u", "email": "n@x.io" }
        }"#;
        let redacted = redact_pii_json(body);
        assert!(!redacted.contains("nested_u"));
        assert!(!redacted.contains("n@x.io"));
    }

    #[test]
    fn redact_pii_strips_sub_jwt_claim_if_present() {
        let body = br#"{"sub": "user|auth0|123", "other": "ok"}"#;
        let redacted = redact_pii_json(body);
        assert!(!redacted.contains("user|auth0|123"));
        assert!(redacted.contains("REDACTED-sub"));
        assert!(redacted.contains("ok"));
    }

    #[test]
    fn redact_pii_non_json_falls_back_to_token_redactor() {
        let body = b"<html>500 internal sk-ant-oat01-really-long-token-goes-here</html>";
        let redacted = redact_pii_json(body);
        assert!(!redacted.contains("sk-ant-oat01-really-long-token-goes-here"));
    }

    // ── Golden fixture assertions ─────────────────────────────────

    /// The committed golden fixture MUST NOT contain any real email
    /// address or `acct_*` identifier. H5 pre-commit assertion.
    #[test]
    fn golden_fixture_has_no_real_pii() {
        let text = std::str::from_utf8(WHAM_GOLDEN).expect("golden is utf8");
        assert!(
            !text.contains("acct_"),
            "golden fixture has an acct_ identifier"
        );
        // The only allowed email shape is a fixed REDACTED@example.invalid
        // sentinel. Any other `@` bearing string is suspicious.
        for line in text.lines() {
            if line.contains('@') {
                assert!(
                    line.contains("REDACTED@example.invalid"),
                    "golden fixture has an unexpected email-shaped string: {line}"
                );
            }
        }
    }

    #[test]
    fn golden_fixture_parses_into_wham_snapshot() {
        let snap = parse_wham_response(200, WHAM_GOLDEN).expect("golden parses");
        assert_eq!(snap.plan_type, "plus");
        assert!(snap.rate_limit.allowed);
        assert_eq!(snap.rate_limit.primary_window.used_percent, 42.5);
        assert_eq!(
            snap.rate_limit.secondary_window.limit_window_seconds,
            604_800
        );
    }

    // ── Write-path tests ──────────────────────────────────────────

    #[test]
    fn write_wham_to_quota_persists_both_windows_and_extras() {
        let dir = TempDir::new().unwrap();
        let snap = parse_wham_response(200, WHAM_GOLDEN).unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        write_wham_to_quota(dir.path(), account, &snap).unwrap();

        let state = quota_state::load_state(dir.path()).unwrap();
        let q = state.get(5).expect("account present");
        assert_eq!(q.surface, "codex");
        assert_eq!(q.kind, "utilization");
        assert!((q.five_hour_pct() - 42.5).abs() < 0.01);
        assert!((q.seven_day_pct() - 12.5).abs() < 0.01);
        let extras = q.extras.as_ref().expect("extras set");
        assert_eq!(
            extras.get("plan_type").and_then(|v| v.as_str()),
            Some("plus")
        );
    }

    #[test]
    fn write_unknown_to_quota_degrades_cleanly() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();
        write_unknown_to_quota(dir.path(), account).unwrap();

        let state = quota_state::load_state(dir.path()).unwrap();
        let q = state.get(6).expect("account present");
        assert_eq!(q.kind, "unknown");
        assert!(q.five_hour.is_none());
        assert!(q.seven_day.is_none());
    }

    #[test]
    fn write_raw_capture_redacts_pii_and_sets_permissions() {
        let dir = TempDir::new().unwrap();
        let body = br#"{
            "user_id": "u_real_leak",
            "account_id": "acct_real_leak",
            "email": "leak@secret.example",
            "plan_type": "plus",
            "rate_limit": {
                "allowed": true, "limit_reached": false,
                "primary_window": {"used_percent":0,"limit_window_seconds":18000,"reset_after_seconds":18000,"reset_at":4102444800},
                "secondary_window": {"used_percent":0,"limit_window_seconds":604800,"reset_after_seconds":604800,"reset_at":4102444900}
            }
        }"#;
        write_raw_capture(dir.path(), body).unwrap();

        let path = raw_capture_path(dir.path());
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains("u_real_leak"));
        assert!(!written.contains("acct_real_leak"));
        assert!(!written.contains("leak@secret.example"));
        assert!(written.contains("plus"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "raw-capture must be 0o600, got {mode:o}");
        }
    }

    // ── Tick integration tests ────────────────────────────────────

    fn install_codex_account(base: &Path, account: u16, access_token: &str) {
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct_test".into()),
                access_token: access_token.into(),
                refresh_token: Some("rt_test".into()),
                id_token: None,
                extra: Default::default(),
            },
            last_refresh: None,
            extra: Default::default(),
        });
        let path = cred_file::canonical_path_for(base, num, Surface::Codex);
        credentials::save(&path, &creds).unwrap();
    }

    fn mock_wham_success(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((200, WHAM_GOLDEN.to_vec()))
        })
    }

    fn mock_wham_drift(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            // 200 OK but wrong shape — triggers Drift branch
            Ok((200, br#"{"unexpected":"shape"}"#.to_vec()))
        })
    }

    fn mock_wham_401(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((401, b"unauthorized".to_vec()))
        })
    }

    #[tokio::test]
    async fn tick_polls_codex_account_and_writes_quota() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 3, "test-access-token");
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_wham_success(Arc::clone(&counter));
        let breakers: BreakerMap = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &breakers).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let state = quota_state::load_state(dir.path()).unwrap();
        let q = state.get(3).expect("codex account 3 quota");
        assert_eq!(q.surface, "codex");
        assert!((q.five_hour_pct() - 42.5).abs() < 0.01);

        // Raw capture exists and is redacted.
        let raw = std::fs::read_to_string(raw_capture_path(dir.path())).unwrap();
        assert!(raw.contains("plus"));
        assert!(!raw.contains("REDACTED-user-id") == false); // contains the redaction sentinel
    }

    #[tokio::test]
    async fn tick_drift_writes_unknown_quota_and_drift_capture() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 4, "test-access-token");
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_wham_drift(Arc::clone(&counter));
        let breakers: BreakerMap = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &breakers).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let state = quota_state::load_state(dir.path()).unwrap();
        let q = state.get(4).expect("codex account 4 quota present");
        assert_eq!(q.kind, "unknown");

        assert!(drift_capture_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn tick_401_records_failure() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 7, "test-access-token");
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_wham_401(Arc::clone(&counter));
        let breakers: BreakerMap = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &breakers).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let guard = breakers.lock().unwrap();
        assert_eq!(guard.get(&7).map(|s| s.fails).unwrap_or(0), 1);
    }

    #[tokio::test]
    async fn tick_breaker_open_skips_poll() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 8, "test-access-token");
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_wham_success(Arc::clone(&counter));
        let breakers: BreakerMap = Arc::new(Mutex::new(HashMap::new()));

        // Manually trip breaker
        {
            let mut g = breakers.lock().unwrap();
            let entry = g.entry(8).or_default();
            for _ in 0..CODEX_BREAKER_FAIL_THRESHOLD {
                entry.record_failure(Instant::now());
            }
        }

        tick(dir.path(), &http, &breakers).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "breaker must skip the poll"
        );
    }

    #[tokio::test]
    async fn tick_success_clears_breaker_state() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 9, "test-access-token");
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_wham_success(Arc::clone(&counter));
        let breakers: BreakerMap = Arc::new(Mutex::new(HashMap::new()));

        // Prime with a few failures (below threshold, breaker still closed)
        {
            let mut g = breakers.lock().unwrap();
            let entry = g.entry(9).or_default();
            entry.record_failure(Instant::now());
            entry.record_failure(Instant::now());
        }

        tick(dir.path(), &http, &breakers).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let guard = breakers.lock().unwrap();
        assert_eq!(guard.get(&9).map(|s| s.fails).unwrap_or(0), 0);
    }
}
