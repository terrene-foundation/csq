//! Third-party provider usage polling.
//!
//! Handles the `tick_3p` dispatch loop, per-slot and global settings
//! loading, the probe-based rate-limit extraction, and the generic
//! `write_3p_usage_to_quota` writer for providers without a direct
//! quota API.

use crate::accounts::{discovery, AccountSource};
use crate::providers::settings::load_settings;
use crate::quota::{state as quota_state, AccountQuota, QuotaFile, RateLimitData, UsageWindow};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, warn};

use super::{
    clear_backoff, clear_cooldown, in_cooldown, increase_backoff, set_cooldown,
    set_cooldown_with_backoff, HttpGetFn, HttpPostProbeFn, PollError, CALL_TIMEOUT,
    RATELIMIT_PREFIX,
};
use crate::daemon::usage_poller::minimax::{poll_minimax_quota, write_minimax_quota, MiniMaxQuota};
use crate::daemon::usage_poller::zai::{poll_zai_quota, write_zai_quota, ZaiQuota};

/// Anthropic API version header for 3P probe requests.
const ANTHROPIC_VERSION_HEADER: &str = "2023-06-01";

/// Builds the minimal probe request body for a given model.
///
/// Uses `max_tokens=1` to minimise cost — the goal is only to receive
/// `anthropic-ratelimit-*` response headers, not a real completion.
pub(super) fn build_probe_body(model: &str) -> String {
    serde_json::json!({
        "model": model,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}]
    })
    .to_string()
}

/// Runs a single 3P usage poller tick.
///
/// Discovers 3P accounts (Z.AI, MiniMax), reads their API keys from
/// settings files, sends a minimal `max_tokens=1` probe, and extracts
/// `anthropic-ratelimit-*` headers from the response.
///
/// Handles **both** discovery sources:
/// 1. **Per-slot bindings** — `config-N/settings.json` pointing at a
///    3P provider. Slot N is the displayed account number (e.g.
///    slot 9 = MiniMax). API key is read from the same per-slot
///    file. Quota is written to `quota.json` keyed on slot N so the
///    dashboard Accounts tab sees it without further plumbing.
/// 2. **Legacy global** — `settings-mm.json` / `settings-zai.json`
///    at the base dir level, synthetic slots 901/902. Still
///    supported for backward compat but suppressed by `discover_all`
///    when a per-slot binding exists for the same provider.
pub(crate) async fn tick_3p(
    base_dir: &std::path::Path,
    http_get: &HttpGetFn,
    http_post_probe: &HttpPostProbeFn,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
) {
    debug!("3P usage poller tick starting");

    // `discover_all` returns OAuth + per-slot 3P + legacy global 3P
    // with de-duplication. We filter to just the 3P rows here.
    let accounts: Vec<_> = discovery::discover_all(base_dir)
        .into_iter()
        .filter(|a| matches!(a.source, AccountSource::ThirdParty { .. }))
        .collect();

    let mut polled = 0usize;
    let mut skipped = 0usize;

    for info in accounts {
        let provider_id = match &info.source {
            AccountSource::ThirdParty { provider } => provider_id_from_label(provider),
            _ => continue,
        };

        let provider_id = match provider_id {
            Some(id) => id,
            None => continue,
        };

        // Cooldown check
        if in_cooldown(cooldowns, info.id) {
            skipped += 1;
            continue;
        }

        // Load API key. For per-slot bindings (info.id < 900) the
        // canonical source is `config-<info.id>/settings.json`.
        // For legacy global bindings (info.id >= 900 i.e. 901/902)
        // fall back to the base-dir-level `settings-{mm,zai}.json`.
        let api_key = if info.id < 900 {
            match load_3p_api_key_for_slot(base_dir, info.id, provider_id) {
                Some(key) => key,
                None => {
                    debug!(
                        account = info.id,
                        provider = provider_id,
                        "3P poller: per-slot API key not found"
                    );
                    continue;
                }
            }
        } else {
            match load_3p_api_key(base_dir, provider_id) {
                Some(key) => key,
                None => {
                    debug!(
                        account = info.id,
                        provider = provider_id,
                        "3P poller: global API key not found"
                    );
                    continue;
                }
            }
        };

        // Load base URL and default model from the provider catalog
        // as a fallback, then override BOTH the base URL and the
        // model with the per-slot binding's env.* values if set.
        // A user may be hitting a non-default host or a non-default
        // model (e.g. `MiniMax-M2.7-highspeed` vs catalog's
        // `MiniMax-M2`). Both overrides are needed — probing the
        // catalog model on a retired alias 404s and leaves the user
        // with no quota data.
        let (catalog_base_url, default_model) =
            match crate::providers::catalog::get_provider(provider_id) {
                Some(p) => (
                    p.default_base_url.unwrap_or("https://api.anthropic.com"),
                    p.default_model,
                ),
                None => continue,
            };
        let (base_url_owned, model_owned) = if info.id < 900 {
            (
                load_3p_base_url_for_slot(base_dir, info.id)
                    .unwrap_or_else(|| catalog_base_url.to_string()),
                load_3p_model_for_slot(base_dir, info.id)
                    .unwrap_or_else(|| default_model.to_string()),
            )
        } else {
            (catalog_base_url.to_string(), default_model.to_string())
        };

        // Poll in spawn_blocking (blocking HTTP client).
        // expose_secret() at the HTTP boundary — raw key lives only
        // for the duration of the blocking probe.
        //
        // For MiniMax: use the direct quota API endpoint first
        // (`/v1/api/openplatform/coding_plan/remains`), which returns
        // authoritative usage data without the `max_tokens=1` probe hack.
        // For Z.AI: no direct API exists, fall back to the probe.
        let http_probe = Arc::clone(http_post_probe);
        let http_get = Arc::clone(http_get);
        let url = format!("{}/v1/messages", base_url_owned);
        let model = model_owned;
        let raw_key = api_key.expose_secret().to_string();
        let pid = provider_id.to_string();

        // Load MiniMax GroupId from per-slot or global settings
        let group_id = if pid == "mm" {
            if info.id < 900 {
                load_3p_env_string_for_slot(base_dir, info.id, "MINIMAX_GROUP_ID")
            } else {
                // Global settings: check settings-mm.json
                load_settings(base_dir, "mm")
                    .ok()
                    .and_then(|s| s.get_group_id().map(|s| s.to_string()))
            }
        } else {
            None
        };

        // MiniMax and Z.AI return richer structures (both 5h and 7d),
        // so they get their own result types. Others use RateLimitData.
        enum PollResult3P {
            RateLimits(RateLimitData),
            MiniMax(MiniMaxQuota),
            Zai(ZaiQuota),
        }

        let join_handle = tokio::task::spawn_blocking(move || {
            if pid == "mm" {
                poll_minimax_quota(&raw_key, group_id.as_deref(), &model, &http_get)
                    .map(PollResult3P::MiniMax)
            } else if pid == "zai" {
                poll_zai_quota(&raw_key, &http_get).map(PollResult3P::Zai)
            } else {
                poll_3p_usage(&url, &raw_key, &model, &http_probe).map(PollResult3P::RateLimits)
            }
        });
        let poll_result = match tokio::time::timeout(CALL_TIMEOUT, join_handle).await {
            Ok(inner) => inner,
            Err(_elapsed) => {
                warn!(account = info.id, "3P poller: call timed out after 30s");
                set_cooldown(cooldowns, info.id);
                continue;
            }
        };

        match poll_result {
            Ok(Ok(PollResult3P::MiniMax(mm_quota))) => {
                let base = base_dir.to_path_buf();
                if let Err(e) = write_minimax_quota(&base, info.id, &mm_quota) {
                    warn!(
                        account = info.id,
                        "3P poller: failed to write MiniMax quota"
                    );
                    let _ = e;
                }
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
                polled += 1;
            }
            Ok(Ok(PollResult3P::Zai(zai_quota))) => {
                let base = base_dir.to_path_buf();
                if let Err(e) = write_zai_quota(&base, info.id, &zai_quota) {
                    warn!(account = info.id, "3P poller: failed to write Z.AI quota");
                    let _ = e;
                }
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
                polled += 1;
            }
            Ok(Ok(PollResult3P::RateLimits(rate_limits))) => {
                let base = base_dir.to_path_buf();
                if let Err(e) = write_3p_usage_to_quota(&base, info.id, &rate_limits) {
                    warn!(account = info.id, "3P poller: failed to write quota");
                    let _ = e;
                }
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
                polled += 1;
            }
            Ok(Err(PollError::RateLimited)) => {
                warn!(account = info.id, "3P poller: 429 rate limited");
                increase_backoff(backoffs, info.id);
                set_cooldown_with_backoff(cooldowns, backoffs, info.id);
            }
            Ok(Err(PollError::Unauthorized)) => {
                warn!(account = info.id, "3P poller: 401 unauthorized");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::Transport(_))) => {
                debug!(account = info.id, "3P poller: transport error");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::Parse(_))) => {
                debug!(account = info.id, "3P poller: parse error");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::HttpError(status))) => {
                debug!(account = info.id, status, "3P poller: non-200 response");
                set_cooldown(cooldowns, info.id);
            }
            Err(_join_err) => {
                warn!(account = info.id, "3P poller: task panicked");
                set_cooldown(cooldowns, info.id);
            }
        }
    }

    debug!(polled, skipped, "3P usage poller tick complete");
}

/// Maps a 3P provider display label to its catalog ID.
fn provider_id_from_label(label: &str) -> Option<&'static str> {
    match label {
        "Z.AI" => Some("zai"),
        "MiniMax" => Some("mm"),
        _ => None,
    }
}

/// Loads the API key for a 3P provider from its global settings
/// file (`{base}/settings-{mm,zai}.json`).
///
/// Returns the key wrapped in [`ApiKey`] so the raw value is never
/// held as a plain `String`. Callers expose at the HTTP boundary
/// via [`ApiKey::expose_secret`].
fn load_3p_api_key(base_dir: &std::path::Path, provider_id: &str) -> Option<crate::types::ApiKey> {
    let settings = load_settings(base_dir, provider_id).ok()?;
    settings.get_api_key()
}

/// Loads the API key for a per-slot 3P provider binding from
/// `{base}/config-<slot>/settings.json`.
///
/// Returns `None` if the file is missing, malformed, or does not
/// contain `env.ANTHROPIC_AUTH_TOKEN`. The key env var is shared
/// between MiniMax and Z.AI (both use the same bearer-in-env-var
/// convention) so the caller's `provider_id` is used only to
/// validate that the caller's intent matches the catalog — not to
/// pick a different env var.
pub(crate) fn load_3p_api_key_for_slot(
    base_dir: &std::path::Path,
    slot: u16,
    _provider_id: &str,
) -> Option<crate::types::ApiKey> {
    let path = base_dir
        .join(format!("config-{slot}"))
        .join("settings.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    // Canonical location is `env.ANTHROPIC_AUTH_TOKEN`; top-level
    // `ANTHROPIC_AUTH_TOKEN` is a fallback for hand-edited files.
    let token = json
        .get("env")
        .and_then(|e| e.get("ANTHROPIC_AUTH_TOKEN"))
        .or_else(|| json.get("ANTHROPIC_AUTH_TOKEN"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?;
    Some(crate::types::ApiKey::new(token.to_string()))
}

/// Reads the `env.ANTHROPIC_BASE_URL` override from a per-slot
/// `config-<slot>/settings.json`. Returns `None` when the file is
/// missing or the field is not set, letting the caller fall back
/// to the provider catalog default.
pub(crate) fn load_3p_base_url_for_slot(base_dir: &std::path::Path, slot: u16) -> Option<String> {
    load_3p_env_string_for_slot(base_dir, slot, "ANTHROPIC_BASE_URL")
}

/// Reads the `env.ANTHROPIC_MODEL` override from a per-slot
/// `config-<slot>/settings.json`. Returns `None` when missing.
///
/// ### Why the probe model must match the user's configured model
///
/// Journal 0026 design question 3: the catalog default is
/// `MiniMax-M2`, but the user's actual `config-9/settings.json`
/// says `ANTHROPIC_MODEL=MiniMax-M2.7-highspeed`. If the poller
/// probes with the catalog default, the probe either:
///
/// 1. Succeeds against a model the user doesn't actually use,
///    producing rate-limit headers that reflect the wrong tier
///    (e.g. M2 has different quotas than M2.7), or
/// 2. Fails with 404 when MiniMax retires M2 (already likely
///    given the M2.7 rollout), leaving the user with no quota
///    data at all.
///
/// Reading `ANTHROPIC_MODEL` from the same settings.json the user
/// configured means the probe always matches what the user's
/// actual terminal session runs — and when the user upgrades to a
/// new model in iTerm, the poller follows automatically on the
/// next tick without a csq code change.
pub(crate) fn load_3p_model_for_slot(base_dir: &std::path::Path, slot: u16) -> Option<String> {
    load_3p_env_string_for_slot(base_dir, slot, "ANTHROPIC_MODEL")
}

/// Generic helper: reads a single string value from
/// `env.<key>` in a per-slot `config-<slot>/settings.json`.
/// Accepts the top-level `<key>` as a legacy fallback.
pub(crate) fn load_3p_env_string_for_slot(
    base_dir: &std::path::Path,
    slot: u16,
    key: &str,
) -> Option<String> {
    let path = base_dir
        .join(format!("config-{slot}"))
        .join("settings.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("env")
        .and_then(|e| e.get(key))
        .or_else(|| json.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Polls a 3P provider by sending a minimal `max_tokens=1` request.
///
/// Extracts `anthropic-ratelimit-*` headers from the response (even
/// on error responses, since 3P providers often include rate-limit
/// headers on 4xx).
///
/// `model` is the provider's configured model (from the catalog's
/// `default_model` field). It is injected here so the probe body is
/// never hardcoded in source and survives model-ID deprecations.
pub(crate) fn poll_3p_usage(
    url: &str,
    api_key: &str,
    model: &str,
    http_post: &HttpPostProbeFn,
) -> Result<RateLimitData, PollError> {
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("x-api-key".to_string(), api_key.to_string()),
        (
            "anthropic-version".to_string(),
            ANTHROPIC_VERSION_HEADER.to_string(),
        ),
        ("Accept".to_string(), "application/json".to_string()),
    ];

    let probe_body = build_probe_body(model);
    let (status, resp_headers, _body) =
        http_post(url, &headers, &probe_body).map_err(PollError::Transport)?;

    // Extract rate-limit headers even on non-200 responses
    let rate_limits = extract_rate_limit_headers(&resp_headers);

    // If we got rate-limit data, return it regardless of status
    if rate_limits.has_data() {
        return Ok(rate_limits);
    }

    // No rate-limit headers — classify by status
    match status {
        200..=299 => Ok(rate_limits), // empty but successful
        429 => Err(PollError::RateLimited),
        401 => Err(PollError::Unauthorized),
        other => Err(PollError::HttpError(other)),
    }
}

/// Extracts `anthropic-ratelimit-*` headers into a [`RateLimitData`].
///
/// Header keys must be lowercase (as returned by `http::post_json_with_headers`).
pub(crate) fn extract_rate_limit_headers(headers: &HashMap<String, String>) -> RateLimitData {
    let get_u64 = |suffix: &str| -> Option<u64> {
        headers
            .get(&format!("{RATELIMIT_PREFIX}{suffix}"))
            .and_then(|v| v.parse::<u64>().ok())
    };

    RateLimitData {
        requests_limit: get_u64("requests-limit"),
        requests_remaining: get_u64("requests-remaining"),
        tokens_limit: get_u64("tokens-limit"),
        tokens_remaining: get_u64("tokens-remaining"),
        input_tokens_limit: get_u64("input-tokens-limit"),
        output_tokens_limit: get_u64("output-tokens-limit"),
    }
}

/// Writes 3P rate-limit data into the local `quota.json`.
pub(crate) fn write_3p_usage_to_quota(
    base_dir: &std::path::Path,
    account_id: u16,
    rate_limits: &RateLimitData,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    // Compute token usage percentage for the five_hour display slot
    // so that existing statusline formatting works for 3P accounts.
    // Use far-future resets_at so clear_expired() never removes it;
    // the poller refreshes every 15 min so stale data is replaced
    // naturally.
    let five_hour = rate_limits.token_usage_pct().map(|pct| UsageWindow {
        used_percentage: pct,
        resets_at: 4_102_444_800, // 2100-01-01T00:00:00Z
    });

    quota.set(
        account_id,
        AccountQuota {
            five_hour,
            seven_day: None,
            rate_limits: Some(rate_limits.clone()),
            updated_at: now,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "3P poller: quota file updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn install_3p_account(base: &std::path::Path, provider: &str, key: &str) {
        let filename = match provider {
            "zai" => "settings-zai.json",
            "mm" => "settings-mm.json",
            _ => panic!("unknown provider"),
        };
        // Discovery checks for top-level ANTHROPIC_AUTH_TOKEN.
        // ProviderSettings::get_api_key() reads from env.ANTHROPIC_AUTH_TOKEN.
        // Write both locations so discovery finds the account AND the
        // API key is loadable.
        let content = format!(
            r#"{{"ANTHROPIC_AUTH_TOKEN":"{}","ANTHROPIC_BASE_URL":"https://api.example.com","env":{{"ANTHROPIC_AUTH_TOKEN":"{}","ANTHROPIC_BASE_URL":"https://api.example.com"}}}}"#,
            key, key
        );
        std::fs::write(base.join(filename), content).unwrap();
    }

    fn write_slot_settings(base: &std::path::Path, slot: u16, base_url: &str, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"{base_url}","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
        );
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    fn write_slot_settings_with_model(base: &std::path::Path, slot: u16, model: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"https://api.minimax.io/anthropic","ANTHROPIC_AUTH_TOKEN":"tok","ANTHROPIC_MODEL":"{model}"}}}}"#
        );
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    /// Mock HttpGetFn that returns a MiniMax-like quota response.
    /// Timestamps use 2100-01-01 in ms for consistency with the
    /// other mocks (see mock_zai_get). Currently inert because
    /// `tick_3p_no_accounts_does_nothing` installs no accounts, but
    /// kept in sync so a future test reusing this fixture doesn't
    /// silently time-bomb.
    fn mock_get_noop() -> HttpGetFn {
        Arc::new(|_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((200, br#"{"model_remains":[{"model_name":"MiniMax-M2","current_interval_total_count":1000,"current_interval_usage_count":800,"end_time":4102444800000,"current_weekly_total_count":7000,"current_weekly_usage_count":6000,"weekly_end_time":4102444800000}]}"#.to_vec()))
        })
    }

    fn mock_3p_success(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut headers = HashMap::new();
                headers.insert(
                    "anthropic-ratelimit-requests-limit".to_string(),
                    "1000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-requests-remaining".to_string(),
                    "800".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-tokens-limit".to_string(),
                    "100000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-tokens-remaining".to_string(),
                    "60000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-input-tokens-limit".to_string(),
                    "50000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-output-tokens-limit".to_string(),
                    "50000".to_string(),
                );
                Ok((200, headers, r#"{"id":"msg_test"}"#.to_string()))
            },
        )
    }

    fn mock_3p_429(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                // 429 with no rate-limit headers
                Ok((429, HashMap::new(), "rate limited".to_string()))
            },
        )
    }

    fn mock_3p_401(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok((401, HashMap::new(), "unauthorized".to_string()))
            },
        )
    }

    fn mock_3p_429_with_headers(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut headers = HashMap::new();
                headers.insert(
                    "anthropic-ratelimit-tokens-limit".to_string(),
                    "100000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-tokens-remaining".to_string(),
                    "0".to_string(),
                );
                Ok((429, headers, "rate limited".to_string()))
            },
        )
    }

    // nextResetTime values are intentionally far in the future (2100-01-01
    // in ms) so `clear_expired` on load does not null them out as real time
    // advances. Pinning to plausible "today + few hours" dates turns these
    // tests into time-bombs that silently start failing once the clock
    // passes the hardcoded reset.
    fn mock_zai_get() -> HttpGetFn {
        Arc::new(|_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((200, br#"{"code":200,"data":{"limits":[{"type":"TOKENS_LIMIT","unit":3,"percentage":6,"nextResetTime":4102444800000},{"type":"TOKENS_LIMIT","unit":6,"percentage":11,"nextResetTime":4102444800000}],"level":"max"}}"#.to_vec()))
        })
    }

    fn mock_get_combined() -> HttpGetFn {
        Arc::new(|url: &str, _token: &str, _headers: &[(&str, &str)]| {
            if url.contains("z.ai") {
                // Z.AI quota response — far-future reset times (see mock_zai_get)
                Ok((200, br#"{"code":200,"data":{"limits":[{"type":"TOKENS_LIMIT","unit":3,"percentage":6,"nextResetTime":4102444800000},{"type":"TOKENS_LIMIT","unit":6,"percentage":11,"nextResetTime":4102444800000}],"level":"max"}}"#.to_vec()))
            } else {
                // MiniMax quota response — end_time/weekly_end_time
                // bumped to 2100-01-01 so `quota::clear_expired` never
                // nulls the windows as real time passes. Older literals
                // (1776*) bit the test suite in 2026-04 when real time
                // drifted past them — see journal 0036.
                Ok((200, br#"{"model_remains":[{"model_name":"MiniMax-M2","current_interval_total_count":1000,"current_interval_usage_count":800,"end_time":4102444800000,"current_weekly_total_count":7000,"current_weekly_usage_count":6000,"weekly_end_time":4102444800000}]}"#.to_vec()))
            }
        })
    }

    // ─── extract_rate_limit_headers tests ────────────────────

    #[test]
    fn extract_full_rate_limit_headers() {
        let mut headers = HashMap::new();
        headers.insert("anthropic-ratelimit-requests-limit".into(), "1000".into());
        headers.insert(
            "anthropic-ratelimit-requests-remaining".into(),
            "800".into(),
        );
        headers.insert("anthropic-ratelimit-tokens-limit".into(), "100000".into());
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".into(),
            "60000".into(),
        );
        headers.insert(
            "anthropic-ratelimit-input-tokens-limit".into(),
            "50000".into(),
        );
        headers.insert(
            "anthropic-ratelimit-output-tokens-limit".into(),
            "50000".into(),
        );

        let rl = extract_rate_limit_headers(&headers);
        assert_eq!(rl.requests_limit, Some(1000));
        assert_eq!(rl.requests_remaining, Some(800));
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(60000));
        assert_eq!(rl.input_tokens_limit, Some(50000));
        assert_eq!(rl.output_tokens_limit, Some(50000));
        assert!(rl.has_data());
    }

    #[test]
    fn extract_partial_rate_limit_headers() {
        let mut headers = HashMap::new();
        headers.insert("anthropic-ratelimit-tokens-limit".into(), "100000".into());
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".into(),
            "75000".into(),
        );

        let rl = extract_rate_limit_headers(&headers);
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(75000));
        assert!(rl.requests_limit.is_none());
        assert!(rl.has_data());
    }

    #[test]
    fn extract_empty_headers() {
        let headers = HashMap::new();
        let rl = extract_rate_limit_headers(&headers);
        assert!(!rl.has_data());
    }

    #[test]
    fn extract_ignores_non_numeric() {
        let mut headers = HashMap::new();
        headers.insert(
            "anthropic-ratelimit-tokens-limit".into(),
            "not_a_number".into(),
        );

        let rl = extract_rate_limit_headers(&headers);
        assert!(rl.tokens_limit.is_none());
        assert!(!rl.has_data());
    }

    // ─── RateLimitData helper tests ─────────────────────────

    #[test]
    fn token_usage_pct_computes_correctly() {
        let rl = RateLimitData {
            requests_limit: None,
            requests_remaining: None,
            tokens_limit: Some(100000),
            tokens_remaining: Some(60000),
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        let pct = rl.token_usage_pct().unwrap();
        assert!((pct - 40.0).abs() < 0.01);
    }

    #[test]
    fn token_usage_pct_fully_used() {
        let rl = RateLimitData {
            requests_limit: None,
            requests_remaining: None,
            tokens_limit: Some(100000),
            tokens_remaining: Some(0),
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        let pct = rl.token_usage_pct().unwrap();
        assert!((pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn token_usage_pct_none_when_missing() {
        let rl = RateLimitData {
            requests_limit: Some(1000),
            requests_remaining: Some(800),
            tokens_limit: None,
            tokens_remaining: None,
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        assert!(rl.token_usage_pct().is_none());
    }

    #[test]
    fn request_usage_pct_computes_correctly() {
        let rl = RateLimitData {
            requests_limit: Some(1000),
            requests_remaining: Some(800),
            tokens_limit: None,
            tokens_remaining: None,
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        let pct = rl.request_usage_pct().unwrap();
        assert!((pct - 20.0).abs() < 0.01);
    }

    // ─── build_probe_body tests ─────────────────────────────

    #[test]
    fn build_probe_body_contains_model() {
        let body = build_probe_body("test-model");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("build_probe_body must produce valid JSON");
        assert_eq!(parsed["model"], "test-model");
        assert_eq!(parsed["max_tokens"], 1);
        assert_eq!(parsed["messages"][0]["role"], "user");
        assert_eq!(parsed["messages"][0]["content"], "hi");
    }

    #[test]
    fn build_probe_body_uses_provided_model_not_hardcoded() {
        let a = build_probe_body("model-a");
        let b = build_probe_body("model-b");
        let pa: serde_json::Value = serde_json::from_str(&a).unwrap();
        let pb: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(pa["model"], "model-a");
        assert_eq!(pb["model"], "model-b");
        assert_ne!(pa["model"], pb["model"]);
    }

    // ─── poll_3p_usage unit tests ───────────────────────────

    #[test]
    fn poll_3p_success_extracts_headers() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(result.is_ok());
        let rl = result.unwrap();
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(60000));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poll_3p_429_no_headers_returns_ratelimited() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_429(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(matches!(result, Err(PollError::RateLimited)));
    }

    #[test]
    fn poll_3p_429_with_headers_returns_data() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_429_with_headers(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        // Even on 429, if headers are present, return them
        assert!(result.is_ok());
        let rl = result.unwrap();
        assert_eq!(rl.tokens_remaining, Some(0));
    }

    #[test]
    fn poll_3p_401_returns_unauthorized() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_401(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(matches!(result, Err(PollError::Unauthorized)));
    }

    #[test]
    fn poll_3p_transport_error() {
        let http: HttpPostProbeFn =
            Arc::new(|_url: &str, _headers: &[(String, String)], _body: &str| {
                Err("connection refused".to_string())
            });
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(matches!(result, Err(PollError::Transport(_))));
    }

    // ─── tick_3p integration tests ──────────────────────────

    use crate::quota::state as quota_state;

    #[tokio::test]
    async fn tick_3p_zai_polls_and_writes_quota() {
        // Z.AI now uses direct quota API (live-verified: API key works)
        let dir = TempDir::new().unwrap();
        install_3p_account(dir.path(), "zai", "test-api-key");

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &mock_zai_get(), &http, &cooldowns, &backoffs).await;

        // Z.AI uses GET, not POST probe
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "Z.AI should use GET, not POST"
        );

        // Verify quota was written
        let quota = quota_state::load_state(dir.path()).unwrap();
        let q = quota.get(901).expect("Z.AI account 901 should have quota");
        assert!((q.five_hour_pct() - 6.0).abs() < 0.01);
        assert!((q.seven_day_pct() - 11.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn tick_3p_429_enters_cooldown() {
        // Use MiniMax (which still actually polls) for 429 cooldown test.
        // MiniMax uses GET, so we mock the GET to return 429.
        let dir = TempDir::new().unwrap();
        install_3p_account(dir.path(), "mm", "test-api-key");

        let counter = Arc::new(AtomicU32::new(0));
        let http_get: HttpGetFn =
            Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok((429, b"rate limited".to_vec()))
            });
        let http_post = mock_3p_success(Arc::new(AtomicU32::new(0)));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &http_get, &http_post, &cooldowns, &backoffs).await;
        assert!(in_cooldown(&cooldowns, 902));

        // Second tick: cooldown blocks the poll
        tick_3p(dir.path(), &http_get, &http_post, &cooldowns, &backoffs).await;
        // still in cooldown
        assert!(in_cooldown(&cooldowns, 902));
    }

    #[tokio::test]
    async fn tick_3p_no_accounts_does_nothing() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &mock_get_noop(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tick_3p_multiple_providers() {
        let dir = TempDir::new().unwrap();
        install_3p_account(dir.path(), "zai", "zai-key");
        install_3p_account(dir.path(), "mm", "mm-key");

        let post_counter = Arc::new(AtomicU32::new(0));
        let http_post = mock_3p_success(Arc::clone(&post_counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // Both MiniMax and Z.AI use direct GET endpoints now
        tick_3p(
            dir.path(),
            &mock_get_combined(),
            &http_post,
            &cooldowns,
            &backoffs,
        )
        .await;
        assert_eq!(
            post_counter.load(Ordering::SeqCst),
            0,
            "Both use GET, no POST probe calls"
        );

        let quota = quota_state::load_state(dir.path()).unwrap();
        assert!(quota.get(901).is_some(), "Z.AI should have quota (via GET)");
        assert!(
            quota.get(902).is_some(),
            "MiniMax should have quota (via GET)"
        );
    }

    // ─── quota round-trip with rate_limits field ────────────

    #[test]
    fn quota_rate_limits_serialization_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut qf = crate::quota::QuotaFile::empty();
        qf.set(
            901,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: 40.0,
                    resets_at: 4_102_444_800,
                }),
                seven_day: None,
                rate_limits: Some(RateLimitData {
                    requests_limit: Some(1000),
                    requests_remaining: Some(800),
                    tokens_limit: Some(100000),
                    tokens_remaining: Some(60000),
                    input_tokens_limit: Some(50000),
                    output_tokens_limit: Some(50000),
                }),
                updated_at: 100.0,
            },
        );

        quota_state::save_state(dir.path(), &qf).unwrap();
        let loaded = quota_state::load_state(dir.path()).unwrap();

        let q = loaded.get(901).expect("account 901 should exist");
        let rl = q.rate_limits.as_ref().expect("rate_limits should exist");
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(60000));
        assert!((q.five_hour_pct() - 40.0).abs() < 0.01);
    }

    #[test]
    fn quota_without_rate_limits_deserializes() {
        // Backward compat: old quota.json without rate_limits field
        let json = r#"{"accounts":{"1":{"five_hour":{"used_percentage":42.0,"resets_at":9999999999},"seven_day":null,"updated_at":100.0}}}"#;
        let qf: crate::quota::QuotaFile = serde_json::from_str(json).unwrap();
        let q = qf.get(1).unwrap();
        assert!(q.rate_limits.is_none());
        assert!((q.five_hour_pct() - 42.0).abs() < 0.01);
    }

    // ── per-slot 3P key / base-url loaders ─────────────────

    #[test]
    fn load_3p_api_key_for_slot_reads_per_slot_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings(
            tmp.path(),
            9,
            "https://api.minimax.io/anthropic",
            "tok-mm-9",
        );
        let key = load_3p_api_key_for_slot(tmp.path(), 9, "mm").unwrap();
        assert_eq!(key.expose_secret(), "tok-mm-9");
    }

    #[test]
    fn load_3p_api_key_for_slot_returns_none_on_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(load_3p_api_key_for_slot(tmp.path(), 9, "mm").is_none());
    }

    #[test]
    fn load_3p_api_key_for_slot_returns_none_on_empty_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Empty string is treated as "not set" — otherwise the
        // poller would emit 401 for every tick on a stub slot.
        write_slot_settings(tmp.path(), 9, "https://api.minimax.io/anthropic", "");
        assert!(load_3p_api_key_for_slot(tmp.path(), 9, "mm").is_none());
    }

    #[test]
    fn load_3p_base_url_for_slot_reads_per_slot_url() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings(tmp.path(), 10, "https://api.z.ai/api/anthropic", "tok");
        let url = load_3p_base_url_for_slot(tmp.path(), 10).unwrap();
        assert_eq!(url, "https://api.z.ai/api/anthropic");
    }

    #[test]
    fn load_3p_base_url_for_slot_returns_none_on_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(load_3p_base_url_for_slot(tmp.path(), 7).is_none());
    }

    #[test]
    fn load_3p_base_url_for_slot_accepts_non_default_host() {
        // Whatever's in settings.json wins — the loader must not
        // second-guess the per-slot base URL, even if it differs
        // from the catalog default.
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings(
            tmp.path(),
            9,
            "https://api.minimax.example/anthropic",
            "tok",
        );
        assert_eq!(
            load_3p_base_url_for_slot(tmp.path(), 9).unwrap(),
            "https://api.minimax.example/anthropic"
        );
    }

    // ── load_3p_model_for_slot ─────────────────────────────

    #[test]
    fn load_3p_model_for_slot_reads_per_slot_model() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings_with_model(tmp.path(), 9, "MiniMax-M2.7-highspeed");
        assert_eq!(
            load_3p_model_for_slot(tmp.path(), 9).unwrap(),
            "MiniMax-M2.7-highspeed"
        );
    }

    #[test]
    fn load_3p_model_for_slot_returns_none_when_unset() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Settings with no ANTHROPIC_MODEL field.
        write_slot_settings(tmp.path(), 10, "https://api.z.ai/api/anthropic", "tok");
        assert!(load_3p_model_for_slot(tmp.path(), 10).is_none());
    }

    #[test]
    fn load_3p_model_for_slot_returns_none_on_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(load_3p_model_for_slot(tmp.path(), 7).is_none());
    }

    #[test]
    fn load_3p_model_for_slot_handles_glm_model_too() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings_with_model(tmp.path(), 10, "glm-5.1");
        assert_eq!(load_3p_model_for_slot(tmp.path(), 10).unwrap(), "glm-5.1");
    }
}
