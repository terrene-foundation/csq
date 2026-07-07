//! DeepSeek account balance polling.
//!
//! Polls `GET https://api.deepseek.com/user/balance` for the remaining
//! account balance. DeepSeek is a pay-per-token provider — it has no
//! account-level % quota and its Anthropic-bridge emits no
//! `anthropic-ratelimit-*` headers. This endpoint returns a remaining USD
//! balance that csq renders in place of a usage bar.

use crate::quota::{state as quota_state, AccountQuota, BalanceInfo, QuotaFile};
use tracing::debug;

use super::{HttpGetFn, PollError};

/// DeepSeek balance endpoint — hardcoded because it is NOT the Anthropic-bridge
/// base URL stored in per-slot settings (that is `api.deepseek.com/anthropic`).
const BALANCE_URL: &str = "https://api.deepseek.com/user/balance";

/// Polls DeepSeek's balance API and returns the first balance entry.
///
/// Endpoint: `GET https://api.deepseek.com/user/balance`
/// Auth: `Authorization: Bearer <API_KEY>`
///
/// Response shape (abridged):
/// ```json
/// {
///   "is_available": true,
///   "balance_infos": [
///     {
///       "currency": "USD",
///       "total_balance": "197.15",
///       "granted_balance": "0.00",
///       "topped_up_balance": "197.15"
///     }
///   ]
/// }
/// ```
///
/// `total_balance` is the authoritative remaining credit (a string —
/// parsed to `f64`). The `granted_balance` (promotional credit) and
/// `topped_up_balance` (purchased credit) fields are ignored; only the
/// aggregate `total_balance` matters for display.
pub(crate) fn poll_deepseek_balance(
    api_key: &str,
    http_get: &HttpGetFn,
) -> Result<BalanceInfo, PollError> {
    let extra_headers = [("Accept", "application/json")];

    let (status, body) =
        http_get(BALANCE_URL, api_key, &extra_headers).map_err(PollError::Transport)?;

    match status {
        429 => return Err(PollError::RateLimited),
        401 => return Err(PollError::Unauthorized),
        200 => {}
        other => return Err(PollError::HttpError(other)),
    }

    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| PollError::Parse(e.to_string()))?;

    let balance_infos = json
        .get("balance_infos")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PollError::Parse("missing balance_infos array".into()))?;

    let entry = balance_infos
        .first()
        .ok_or_else(|| PollError::Parse("balance_infos array is empty".into()))?;

    let currency = entry
        .get("currency")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PollError::Parse("missing currency field".into()))?
        .to_string();

    let total_balance_str = entry
        .get("total_balance")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PollError::Parse("missing total_balance field".into()))?;

    let remaining: f64 = total_balance_str.parse().map_err(|_| {
        PollError::Parse(format!(
            "cannot parse total_balance as f64: {total_balance_str:?}"
        ))
    })?;

    // Reject non-finite balances at the boundary. `str::parse::<f64>` accepts
    // "NaN"/"inf"/"infinity"; a garbled response must not persist a value that
    // renders as "$NaN" / "$inf" in the statusline and desktop card (#984
    // redteam L1). Validate here so quota.json never holds a non-finite balance.
    if !remaining.is_finite() {
        return Err(PollError::Parse(format!(
            "total_balance is not finite: {total_balance_str:?}"
        )));
    }

    Ok(BalanceInfo {
        currency,
        remaining,
    })
}

/// Writes DeepSeek balance data into `quota.json`.
pub(crate) fn write_deepseek_balance(
    base_dir: &std::path::Path,
    account_id: u16,
    balance: &BalanceInfo,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota.set(
        account_id,
        AccountQuota {
            kind: "balance".into(),
            balance: Some(balance.clone()),
            updated_at: now,
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "DeepSeek poller: quota file updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn mock_get(status: u16, body: &'static str) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((status, body.as_bytes().to_vec()))
        })
    }

    // (a) Parse the exact live JSON from the endpoint.
    #[test]
    fn poll_deepseek_balance_parses_live_response() {
        let body = r#"{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"197.15","granted_balance":"0.00","topped_up_balance":"197.15"}]}"#;
        let http = mock_get(200, body);
        let result = poll_deepseek_balance("test-key", &http);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let info = result.unwrap();
        assert_eq!(info.currency, "USD");
        assert!(
            (info.remaining - 197.15).abs() < 1e-9,
            "remaining={}",
            info.remaining
        );
    }

    // (b) 401 returns Unauthorized.
    #[test]
    fn poll_deepseek_balance_401_returns_unauthorized() {
        let http = mock_get(401, r#"{"error":"Unauthorized"}"#);
        let result = poll_deepseek_balance("bad-key", &http);
        assert!(
            matches!(result, Err(PollError::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
    }

    // (b) Other error status returns HttpError.
    #[test]
    fn poll_deepseek_balance_500_returns_http_error() {
        let http = mock_get(500, "internal server error");
        let result = poll_deepseek_balance("key", &http);
        assert!(
            matches!(result, Err(PollError::HttpError(500))),
            "expected HttpError(500), got {result:?}"
        );
    }

    // (b) 429 returns RateLimited.
    #[test]
    fn poll_deepseek_balance_429_returns_rate_limited() {
        let http = mock_get(429, "too many requests");
        let result = poll_deepseek_balance("key", &http);
        assert!(
            matches!(result, Err(PollError::RateLimited)),
            "expected RateLimited, got {result:?}"
        );
    }

    // Transport error propagates as PollError::Transport.
    #[test]
    fn poll_deepseek_balance_transport_error() {
        let http: HttpGetFn =
            Arc::new(|_url, _token, _headers| Err("connection refused".to_string()));
        let result = poll_deepseek_balance("key", &http);
        assert!(
            matches!(result, Err(PollError::Transport(_))),
            "expected Transport error, got {result:?}"
        );
    }

    // #984 redteam L1: a non-finite total_balance ("NaN"/"inf") is rejected at
    // the boundary so quota.json never holds a value that renders as "$NaN".
    #[test]
    fn poll_deepseek_balance_rejects_non_finite() {
        for bad in ["NaN", "inf", "-inf", "infinity"] {
            let body: &'static str = Box::leak(
                format!(
                    r#"{{"is_available":true,"balance_infos":[{{"currency":"USD","total_balance":"{bad}"}}]}}"#
                )
                .into_boxed_str(),
            );
            let http = mock_get(200, body);
            let result = poll_deepseek_balance("key", &http);
            assert!(
                matches!(result, Err(PollError::Parse(_))),
                "non-finite {bad:?} must be rejected, got {result:?}"
            );
        }
    }

    // Missing balance_infos → Parse error.
    #[test]
    fn poll_deepseek_balance_missing_balance_infos() {
        let http = mock_get(200, r#"{"is_available":true}"#);
        let result = poll_deepseek_balance("key", &http);
        assert!(
            matches!(result, Err(PollError::Parse(_))),
            "expected Parse error, got {result:?}"
        );
    }

    // Empty balance_infos array → Parse error.
    #[test]
    fn poll_deepseek_balance_empty_balance_infos() {
        let http = mock_get(200, r#"{"is_available":true,"balance_infos":[]}"#);
        let result = poll_deepseek_balance("key", &http);
        assert!(
            matches!(result, Err(PollError::Parse(_))),
            "expected Parse error for empty array, got {result:?}"
        );
    }

    // Non-numeric total_balance → Parse error.
    #[test]
    fn poll_deepseek_balance_non_numeric_total_balance() {
        let http = mock_get(
            200,
            r#"{"balance_infos":[{"currency":"USD","total_balance":"not-a-number"}]}"#,
        );
        let result = poll_deepseek_balance("key", &http);
        assert!(
            matches!(result, Err(PollError::Parse(_))),
            "expected Parse error for non-numeric balance, got {result:?}"
        );
    }

    // Write round-trip: written balance survives load_state.
    #[test]
    fn write_deepseek_balance_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let balance = BalanceInfo {
            currency: "USD".to_string(),
            remaining: 197.15,
        };
        write_deepseek_balance(dir.path(), 7, &balance).unwrap();

        let quota = quota_state::load_state(dir.path()).unwrap();
        let q = quota.get(7).expect("account 7 should have quota");
        assert_eq!(q.kind, "balance");
        let stored = q.balance.as_ref().expect("balance field must be present");
        assert_eq!(stored.currency, "USD");
        assert!((stored.remaining - 197.15).abs() < 1e-9);
    }
}
