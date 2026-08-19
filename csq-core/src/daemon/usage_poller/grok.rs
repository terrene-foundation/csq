//! Grok (xAI) native-CLI billing polling.
//!
//! Polls the grok CLI's own billing endpoint for the slot's remaining
//! credit and writes a balance-shape row to `quota.json`, so a native
//! Grok slot renders real numbers instead of `native-cli — not
//! quota-polled`.
//!
//! # Shape: credits + monthly cycle, NOT 5h/7d
//!
//! Grok does **not** expose 5-hour / 7-day utilization windows. Its
//! billing surface is a monthly credit cycle, so this poller maps to
//! [`BalanceInfo`] (the DeepSeek pay-per-token shape), never to
//! `five_hour` / `seven_day`. Forcing a monthly figure into a 7-day
//! window would be a fabrication.
//!
//! # Endpoint — verified live 2026-08-01
//!
//! ```text
//! GET {base}/billing?format=credits
//! Authorization: Bearer {oidc_access_token}
//! x-grok-client-mode: cli
//! Accept: application/json
//! ```
//!
//! `{base}` is the grok CLI's chat-proxy base — `$GROK_CLI_CHAT_PROXY_BASE_URL`
//! when set (the vendor's documented override for self-hosted proxies),
//! else [`DEFAULT_CHAT_PROXY_BASE`].
//!
//! A live probe against `https://cli-chat-proxy.grok.com/v1/billing?format=credits`
//! with a real slot's OIDC token (headers as above) returned **HTTP 200**.
//! The path, `Bearer` scheme, and `x-grok-client-mode` header — all
//! originally recovered from the shipped `grok` binary — are now
//! CONFIRMED against a real response, not just field names.
//!
//! # Response shape — verbatim capture, 2026-08-01
//!
//! ```text
//! config.currentPeriod.type   = "USAGE_PERIOD_TYPE_WEEKLY"
//! config.currentPeriod.start  = "2026-07-31T11:12:35.900538+00:00"
//! config.currentPeriod.end    = "2026-08-07T11:12:35.900538+00:00"
//! config.onDemandCap.val      = 0
//! config.onDemandUsed.val     = 0
//! config.isUnifiedBillingUser = true
//! config.prepaidBalance.val   = 0
//! config.topUpMethod          = "TOP_UP_METHOD_SAVED_PAYMENT_METHOD"
//! config.billingPeriodStart   = "2026-07-31T11:12:35.900538+00:00"
//! config.billingPeriodEnd     = "2026-08-07T11:12:35.900538+00:00"
//! ```
//!
//! Two structural surprises against the field-names-only contract this
//! module previously shipped with (recovered from the binary, never
//! checked against a real response):
//!
//! 1. **Every field lives under a top-level `config` object**, not at
//!    the response root.
//! 2. **Numerics are wrapped**: `"prepaidBalance": {"val": 0}`, not
//!    `"prepaidBalance": 0`.
//!
//! The previous parser read only the flat/root shape, so every one of
//! its nine field lookups returned `None` against this real response —
//! `is_empty()` was unconditionally true and every tick failed with
//! `billing response carried no recognised credit field`, silently, at
//! default log level. This was **every tick**, not an edge case.
//!
//! Of the nine fields the original parser looked for: `prepaidBalance`,
//! `onDemandUsed`, `onDemandCap` DO exist (nested, `.val`-wrapped).
//! `creditUsagePercent`, `monthlyLimit`, `includedUsed`, `totalUsed`,
//! `billingCycle`, `subscriptionTier` are ABSENT from this response
//! entirely — they may be real fields under a different account/plan
//! shape, or may never have existed; unconfirmed either way, so they
//! stay in the schema and stay optional.
//!
//! `config.currentPeriod` is the only genuinely meaningful usage signal
//! a subscription account gets from this endpoint — a weekly reset
//! window. Previously discarded entirely; now carried as
//! `current_period_type` / `current_period_start` / `current_period_end`.
//!
//! # Parsing strategy — tolerant of both shapes
//!
//! The flat/root shape was never actually observed live — it was
//! inferred from binary strings, not a response — while the nested
//! `config`-wrapped shape now IS observed live. The parser therefore
//! accepts BOTH rather than replacing one guess with another: a field
//! lookup checks the response root first, then falls back to
//! `config.<name>`; a numeric or text leaf is accepted as a bare JSON
//! value OR as `{"val": ...}` at whichever level it was found. This is
//! not hedging for its own sake — a different account type or a future
//! `format=` value may still emit the flat shape, and there is no live
//! evidence it doesn't.
//!
//! Precedence when both levels carry a non-null value for the same
//! field: root wins — silently in the returned figure, but logged at
//! `debug!` when the two disagree (see [`field`]). No live response has
//! ever carried the same field at both levels, so this is defensive,
//! not observed behavior. A root-level JSON `null`, by contrast, does
//! NOT shadow a valid nested value: it is treated as absent and the
//! parser falls through to `config.<name>` (C-L1, an internal ticket redteam —
//! see `root_null_falls_through_to_config_fallback`).
//!
//! **This tolerance does NOT extend to the period window.** Unlike the
//! credit/numeric/text fields above, `config.currentPeriod` is read by
//! [`current_period_field`] directly at `config.currentPeriod.<key>` —
//! never at the response root. The live capture only ever nested it,
//! and no root-level `currentPeriod` has been observed; widening the
//! tolerance to an unobserved shape now would be exactly the
//! fabrication this module's docs argue against elsewhere (C-N2, PR
//! an internal ticket redteam). If a flat `currentPeriod` ever appears live, widen
//! [`current_period_field`] then — not before.
//!
//! # Zero credits is real data, not "nothing to report"
//!
//! The live capture's `prepaidBalance` / `onDemandUsed` / `onDemandCap`
//! are all `0`, and `isUnifiedBillingUser` is `true`. Two credible
//! readings exist for this combination: treat it as "nothing to report"
//! (write no row / render the vendor-managed placeholder), or write a
//! real row carrying the period window. **Decision: write a real
//! `$0.00` balance row, with the period window in `extras`.** The
//! endpoint was asked and it answered `0` — that is genuine,
//! API-confirmed data, not a missing value, so rendering it faithfully
//! is not a fabrication (contrast with
//! `absent_prepaid_balance_yields_no_balance_row`, where the field is
//! genuinely MISSING and rendering `$0.00` there WOULD be a
//! fabrication). `isUnifiedBillingUser` is carried into `extras` as
//! context only — csq has no confirmed semantics for that flag beyond
//! its name, and suppressing a real API-reported number based on an
//! unverified inference would itself be a form of fabrication.
//! `is_empty()` now also counts the period window as usable data, so a
//! hypothetical response carrying ONLY `config.currentPeriod` (no
//! credit numerics at all) still parses instead of erroring.
//!
//! This is the structural fix for the bug class the poller kept
//! hitting: a parse FAILURE (no recognised field at all) is
//! `Err(PollError::Parse(..))` and writes no row (the slot keeps its
//! previous row); a genuine zero is `Ok(GrokBilling { .. })` and writes
//! a real row. The two are never collapsed into the same outcome — see
//! `genuine_zero_response_and_parse_failure_are_distinguishable`.
//!
//! # Token channel
//!
//! The access token is read from the slot's OWN per-slot vendor home
//! (`native-homes/grok-<N>/auth.json`), never from the user-global
//! `~/.grok/auth.json` — reading a user-global file as a proxy for a
//! specific slot's credentials is the GH an internal ticket bug class that
//! `account-terminal-separation.md` MUST NOT Rule 4 blocks.
//!
//! Per the journal-0135 design lock csq does **not** refresh native
//! tokens (the vendor CLI self-refreshes in place). This poller is
//! therefore read-only: an expired token yields `401` →
//! [`PollError::Unauthorized`] → the slot keeps its previous row and
//! enters cooldown. It never writes a fabricated zero.

use crate::quota::{state as quota_state, AccountQuota, BalanceInfo};
use std::path::Path;
use tracing::debug;

use super::{classify_transport_error, HttpGetFn, PollError, MAX_ACCOUNTS_PER_TICK};

/// Default grok chat-proxy base. Verbatim from `~/.grok/models_cache.json`
/// (`"base_url"`) and the vendor README's "defaults to cli-chat-proxy".
pub(crate) const DEFAULT_CHAT_PROXY_BASE: &str = "https://cli-chat-proxy.grok.com/v1";

/// Vendor-documented override for the chat-proxy base (README §Custom
/// endpoints: `export GROK_CLI_CHAT_PROXY_BASE_URL="https://.../v1"`).
pub(crate) const CHAT_PROXY_BASE_ENV: &str = "GROK_CLI_CHAT_PROXY_BASE_URL";

/// Path + query appended to the base. Verbatim binary literal.
pub(crate) const BILLING_PATH: &str = "/billing?format=credits";

/// Builds the billing URL, honouring the vendor's base-URL override.
///
/// Trailing slashes on the base are trimmed so
/// `https://proxy.example.com/v1/` and `https://proxy.example.com/v1`
/// produce the same URL (the README's own example carries a trailing
/// slash in one place and not another).
pub(crate) fn billing_url() -> String {
    let base = std::env::var(CHAT_PROXY_BASE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CHAT_PROXY_BASE.to_string());
    format!("{}{}", base.trim_end_matches('/'), BILLING_PATH)
}

/// Parsed Grok billing response. Every field is optional — see the
/// module docs on why no field is assumed present.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct GrokBilling {
    /// Remaining prepaid credit. The only field named as a *stock*, so
    /// the only one promoted to the displayed balance. `Some(0.0)` is a
    /// REAL API-reported zero (see module docs "Zero credits is real
    /// data") — never conflated with "field absent".
    pub prepaid_balance: Option<f64>,
    /// Percent of the credit allowance consumed this cycle (0–100).
    pub credit_usage_percent: Option<f64>,
    pub monthly_limit: Option<f64>,
    pub included_used: Option<f64>,
    pub total_used: Option<f64>,
    pub on_demand_used: Option<f64>,
    pub on_demand_cap: Option<f64>,
    pub billing_cycle: Option<String>,
    pub subscription_tier: Option<String>,
    /// `config.currentPeriod.type`, e.g. `"USAGE_PERIOD_TYPE_WEEKLY"`.
    /// Live-verified 2026-08-01 — see module docs.
    pub current_period_type: Option<String>,
    /// `config.currentPeriod.start`, ISO-8601.
    pub current_period_start: Option<String>,
    /// `config.currentPeriod.end`, ISO-8601.
    pub current_period_end: Option<String>,
    /// `config.isUnifiedBillingUser`. Carried into `extras` as context
    /// only — see module docs "Zero credits is real data" for why this
    /// does NOT gate [`GrokBilling::balance`].
    pub is_unified_billing_user: Option<bool>,
}

impl GrokBilling {
    /// True when the response carried no field this poller understands —
    /// the signal to treat the payload as unusable rather than write an
    /// all-absent row. The period window counts as usable data (module
    /// docs "Zero credits is real data"), so a response carrying ONLY
    /// `config.currentPeriod` still parses instead of erroring.
    fn is_empty(&self) -> bool {
        self.prepaid_balance.is_none()
            && self.credit_usage_percent.is_none()
            && self.monthly_limit.is_none()
            && self.included_used.is_none()
            && self.total_used.is_none()
            && self.on_demand_used.is_none()
            && self.on_demand_cap.is_none()
            && self.current_period_type.is_none()
            && self.current_period_start.is_none()
            && self.current_period_end.is_none()
    }

    /// The usage WINDOW csq renders, or `None` when the response carried
    /// no period data.
    ///
    /// Grok subscriptions meter a recurring period (`USAGE_PERIOD_TYPE_WEEKLY`
    /// on the live account this was verified against, 2026-08-02), not a
    /// prepaid stock. For those accounts `prepaidBalance` is a REAL but
    /// meaningless `0.0` — they never bought credit — so rendering it as
    /// "$0.00" reads to an operator as "out of money" while the number they
    /// actually need (`creditUsagePercent`) sits unrendered in `extras`.
    /// That is what shipped, and what this exists to correct: the period is
    /// promoted to a first-class window so it renders on the SAME bar as
    /// codex's and Anthropic's, and the dollar figure becomes the fallback
    /// for genuinely prepaid accounts.
    ///
    /// Mapped to the LONG window slot because Grok exposes exactly one
    /// period and every observed `current_period_type` is a multi-day cycle;
    /// the short slot stays `None` rather than duplicating it.
    pub(crate) fn window(&self) -> Option<crate::quota::UsageWindow> {
        let used = self.credit_usage_percent?;
        if !used.is_finite() {
            return None;
        }
        let end = self.current_period_end.as_deref()?;
        // `try_into`, NOT the `.unwrap()` rustc suggests: `resets_at` is
        // `u64` and chrono yields `i64`, so a pre-epoch or garbage period
        // end would PANIC the daemon's poll tick. A window we cannot
        // represent is simply absent.
        let resets_at: u64 = chrono::DateTime::parse_from_rfc3339(end)
            .ok()?
            .timestamp()
            .try_into()
            .ok()?;
        Some(crate::quota::UsageWindow {
            used_percentage: used,
            resets_at,
        })
    }

    /// The balance row csq renders, or `None` when the response carried
    /// no `prepaidBalance`. A present `prepaidBalance` of exactly `0.0`
    /// DOES render as `$0.00` — the endpoint answered, and `0` is what
    /// it said (module docs "Zero credits is real data"). Non-finite
    /// values are rejected so quota.json never holds a figure that
    /// renders as `$NaN` / `$inf`.
    fn balance(&self) -> Option<BalanceInfo> {
        let remaining = self.prepaid_balance?;
        if !remaining.is_finite() {
            return None;
        }
        Some(BalanceInfo {
            // The endpoint is queried with `format=credits` and carries no
            // currency field; xAI bills in USD. Recorded as USD so the
            // existing balance renderer has a unit to print.
            currency: "USD".to_string(),
            remaining,
        })
    }

    /// Surface-specific figures preserved verbatim under `extras`. Keeps
    /// the data csq cannot yet render (monthly cycle has no window in the
    /// quota schema) without fabricating a 5h/7d value for it.
    fn extras(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        let mut put_num = |k: &str, v: Option<f64>| {
            if let Some(n) = v.filter(|n| n.is_finite()) {
                if let Some(j) = serde_json::Number::from_f64(n) {
                    map.insert(k.to_string(), serde_json::Value::Number(j));
                }
            }
        };
        put_num("credit_usage_percent", self.credit_usage_percent);
        put_num("monthly_limit", self.monthly_limit);
        put_num("included_used", self.included_used);
        put_num("total_used", self.total_used);
        put_num("on_demand_used", self.on_demand_used);
        put_num("on_demand_cap", self.on_demand_cap);
        for (k, v) in [
            ("billing_cycle", self.billing_cycle.as_ref()),
            ("subscription_tier", self.subscription_tier.as_ref()),
            ("current_period_type", self.current_period_type.as_ref()),
            ("current_period_start", self.current_period_start.as_ref()),
            ("current_period_end", self.current_period_end.as_ref()),
        ] {
            if let Some(s) = v {
                map.insert(k.to_string(), serde_json::Value::String(s.clone()));
            }
        }
        if let Some(b) = self.is_unified_billing_user {
            map.insert(
                "is_unified_billing_user".to_string(),
                serde_json::Value::Bool(b),
            );
        }
        serde_json::Value::Object(map)
    }
}

/// Looks up `key` at the response root first (the original,
/// binary-inferred flat shape), then falls back to `config.<key>` (the
/// live-verified nested shape, 2026-08-01). See module docs "Parsing
/// strategy".
///
/// A root-level JSON `null` is treated as absent, not present — it does
/// NOT shadow a valid `config.<key>` value (C-L1, an internal ticket redteam).
///
/// Precedence when BOTH levels carry a non-null value: root wins. No
/// live response has ever carried the same field at both levels with
/// different values; if one ever does, the disagreement is logged at
/// `debug!` so the shape drift is visible instead of silently discarded
/// (C-N1, an internal ticket redteam).
fn field<'a>(json: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    let root = json.get(key).filter(|v| !v.is_null());
    let nested = json.get("config").and_then(|c| c.get(key));
    if let (Some(r), Some(n)) = (root, nested) {
        if r != n {
            debug!(
                field_name = key,
                "Grok poller: root and config both carry this field with different values — root wins"
            );
        }
    }
    root.or(nested)
}

/// Unwraps a numeric leaf that may be a bare JSON number, a decimal
/// string, or wrapped as `{"val": N}` — the live-verified shape for
/// `prepaidBalance` / `onDemandUsed` / `onDemandCap`. Recurses so the
/// unwrap applies at whichever level [`field`] found the value.
fn num_scalar(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse::<f64>().ok(),
        serde_json::Value::Object(_) => v.get("val").and_then(num_scalar),
        _ => None,
    }
}

/// Text counterpart of [`num_scalar`].
fn text_scalar(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(_) => v.get("val").and_then(text_scalar),
        _ => None,
    }
}

/// Reads a JSON number that the API may encode as a JSON number, a
/// decimal string, or `{"val": N}`, at the response root OR nested
/// under `config`. Returns `None` for absent, null, or unparseable.
fn num(v: &serde_json::Value, key: &str) -> Option<f64> {
    num_scalar(field(v, key)?)
}

/// Text counterpart of [`num`] — same root-then-`config` fallback and
/// `{"val": ...}` unwrap.
fn text(v: &serde_json::Value, key: &str) -> Option<String> {
    text_scalar(field(v, key)?)
}

/// Boolean counterpart of [`num`]/[`text`] — same root-then-`config`
/// fallback. Booleans are never `.val`-wrapped in the live capture.
fn boolean(v: &serde_json::Value, key: &str) -> Option<bool> {
    field(v, key).and_then(|f| f.as_bool())
}

/// Reads `config.currentPeriod.<key>` — the period window is always
/// nested two levels deep and is never `.val`-wrapped in the live
/// capture, so this bypasses [`field`] / [`text_scalar`].
fn current_period_field(json: &serde_json::Value, key: &str) -> Option<String> {
    json.get("config")?
        .get("currentPeriod")?
        .get(key)?
        .as_str()
        .map(|s| s.to_string())
}

/// Parses a Grok billing response body.
///
/// Tolerant of both the original binary-inferred flat/root shape and
/// the live-verified `config`-nested, `{"val": N}`-wrapped shape (see
/// module docs "Parsing strategy"). Both camelCase and snake_case are
/// accepted for the two fields the binary emitted in snake_case
/// (`on_demand_enabled`, `subscription_tier` appeared adjacent to the
/// camelCase run, so the casing convention at that boundary is not
/// certain).
pub(crate) fn parse_grok_billing(body: &[u8]) -> Result<GrokBilling, PollError> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| PollError::Parse(e.to_string()))?;

    let pick_num = |camel: &str, snake: &str| num(&json, camel).or_else(|| num(&json, snake));
    let pick_txt = |camel: &str, snake: &str| text(&json, camel).or_else(|| text(&json, snake));

    let billing = GrokBilling {
        prepaid_balance: pick_num("prepaidBalance", "prepaid_balance"),
        credit_usage_percent: pick_num("creditUsagePercent", "credit_usage_percent"),
        monthly_limit: pick_num("monthlyLimit", "monthly_limit"),
        included_used: pick_num("includedUsed", "included_used"),
        total_used: pick_num("totalUsed", "total_used"),
        on_demand_used: pick_num("onDemandUsed", "on_demand_used"),
        on_demand_cap: pick_num("onDemandCap", "on_demand_cap"),
        billing_cycle: pick_txt("billingCycle", "billing_cycle"),
        subscription_tier: pick_txt("subscriptionTier", "subscription_tier"),
        current_period_type: current_period_field(&json, "type"),
        current_period_start: current_period_field(&json, "start"),
        current_period_end: current_period_field(&json, "end"),
        is_unified_billing_user: boolean(&json, "isUnifiedBillingUser"),
    };

    if billing.is_empty() {
        return Err(PollError::Parse(
            "billing response carried no recognised credit field".into(),
        ));
    }
    Ok(billing)
}

/// Polls the Grok billing endpoint with `token` (the slot's OWN OIDC
/// access token) and returns the parsed figures.
pub(crate) fn poll_grok_billing(
    token: &str,
    http_get: &HttpGetFn,
) -> Result<GrokBilling, PollError> {
    let extra_headers = [
        ("Accept", "application/json"),
        // Header NAME is a verbatim binary literal; the value is the
        // CLI-mode discriminator this poller identifies itself with.
        ("x-grok-client-mode", "cli"),
    ];

    // MED-3 (an internal ticket redteam): `billing_url()` is built from the
    // operator-supplied `GROK_CLI_CHAT_PROXY_BASE_URL` env var — the
    // one production URL in this poller that can trip the outbound
    // char guard. Classify so a rejected override logs a distinct,
    // actionable `error_kind` instead of "transport error".
    let (status, body) =
        http_get(&billing_url(), token, &extra_headers).map_err(classify_transport_error)?;

    match status {
        429 => return Err(PollError::RateLimited),
        // 402 is grok's own "run out of credits" status (verbatim
        // `run out of credits` / `status 402` in the binary). It is an
        // authorization-shaped answer, not a usable billing payload.
        401 | 403 => return Err(PollError::Unauthorized),
        200 => {}
        other => return Err(PollError::HttpError(other)),
    }

    parse_grok_billing(&body)
}

/// Reads slot `N`'s OIDC access token from its OWN per-slot vendor home
/// (`native-homes/grok-<N>/auth.json`).
///
/// The vendor keys `auth.json` by `"{issuer}::{client_id}"`, so the
/// entry name is not predictable; the first entry carrying a non-empty
/// `key` wins. Returns `None` when the home does not exist yet (the slot
/// has been bound but never launched), which the caller treats as
/// "nothing to poll" rather than an error.
pub(crate) fn read_slot_access_token(
    base_dir: &Path,
    slot: crate::types::AccountNum,
) -> Option<String> {
    let path = crate::providers::native::native_home_path(
        base_dir,
        slot,
        crate::providers::catalog::Surface::Grok,
    )
    .join("auth.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
    json.as_object()?.values().find_map(|entry| {
        entry
            .get("key")
            .and_then(|k| k.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    })
}

/// Writes Grok billing data into `quota.json` for `account_id`.
///
/// `account_id` is supplied by the caller from the slot-discovery
/// enumeration (`accounts::discovery::discover_native`) — an authoritative
/// slot-lifecycle channel. It is never derived from terminal state
/// (`account-terminal-separation.md` MUST Rule 1).
pub(crate) fn write_grok_billing(
    base_dir: &Path,
    account_id: u16,
    billing: &GrokBilling,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    // MED-1 (an internal ticket redteam): load_state_or_skip fails closed instead of
    // falling back to QuotaFile::empty() — a load failure here must SKIP
    // the write, not persist a one-row file that wipes every sibling
    // account's row (mirrors usage_poller::gemini_oauth::write_quota).
    let mut quota = match quota_state::load_state_or_skip(base_dir) {
        Ok(qf) => qf,
        Err(e) => {
            tracing::warn!(
                account = account_id,
                error_kind = "quota_load_failed",
                reason = %crate::error::redact_tokens(&e.to_string()),
                "Grok poller: quota.json unreadable, skipping write to avoid clobbering sibling rows"
            );
            return Ok(());
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let balance = billing.balance();
    let window = billing.window();
    let extras = billing.extras();

    quota.set(
        account_id,
        AccountQuota {
            surface: "grok".into(),
            // A subscription's PERIOD wins over its prepaid stock. Those
            // accounts report a real-but-meaningless `prepaidBalance: 0.0`
            // (they never bought credit), so preferring the balance renders
            // "$0.00" — indistinguishable from "out of money" — while the
            // live figure sits unrendered in `extras`. Balance is the
            // fallback for genuinely prepaid accounts; `unknown` keeps the
            // non-polled suffix. Never a fake zero on either axis.
            kind: if window.is_some() {
                "utilization".into()
            } else if balance.is_some() {
                "balance".into()
            } else {
                "unknown".into()
            },
            seven_day: window,
            balance,
            extras: extras
                .as_object()
                .filter(|m| !m.is_empty())
                .map(|_| extras.clone()),
            updated_at: now,
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "Grok poller: quota file updated");
    Ok(())
}

/// One Grok poll tick: every native Grok slot, each polled with its OWN
/// token, each written under its OWN discovered slot id.
pub(crate) async fn tick(
    base_dir: &Path,
    http_get: &HttpGetFn,
    cooldowns: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>,
    >,
) {
    use crate::accounts::AccountSource;
    use crate::providers::catalog::Surface;

    let slots: Vec<(u16, crate::types::AccountNum)> = crate::accounts::discovery::discover_native(
        base_dir,
    )
    .into_iter()
    .filter(|a| matches!(a.source, AccountSource::Native { surface } if surface == Surface::Grok))
    .filter_map(|a| {
        crate::types::AccountNum::try_from(a.id)
            .ok()
            .map(|n| (a.id, n))
    })
    // Bound the per-tick HTTP fan-out (see `kimi::tick` for the rationale).
    // Applied after the surface filter so the budget counts slots this poller
    // actually calls.
    .take(MAX_ACCOUNTS_PER_TICK)
    .collect();

    for (id, slot) in slots {
        if super::in_cooldown(cooldowns, id) {
            continue;
        }
        // Slot has been bound but never launched — the vendor home (and
        // therefore the token) does not exist yet. Nothing to poll; not
        // a failure, so no cooldown.
        let Some(token) = read_slot_access_token(base_dir, slot) else {
            debug!(
                account = id,
                "Grok poller: no per-slot vendor home yet — skipping"
            );
            continue;
        };

        let http = std::sync::Arc::clone(http_get);
        let join_handle = tokio::task::spawn_blocking(move || poll_grok_billing(&token, &http));
        // CALL_TIMEOUT wrap per the house pattern (anthropic.rs): a
        // wedged upstream trickling bytes under the inactivity floor
        // must not stall the ENTIRE poller loop — the bare await this
        // replaces blocked every other surface's ticks until daemon
        // restart (redteam R1 MED, same class as the kimi.rs fix).
        let result = match tokio::time::timeout(super::CALL_TIMEOUT, join_handle).await {
            Ok(inner) => inner,
            Err(_elapsed) => {
                tracing::warn!(account = id, "Grok poller: call timed out after 30s");
                super::set_cooldown(cooldowns, id);
                continue;
            }
        };

        match result {
            Ok(Ok(billing)) => {
                super::clear_cooldown(cooldowns, id);
                if let Err(e) = write_grok_billing(base_dir, id, &billing) {
                    // Message is fixed vocabulary; the error value is
                    // discarded rather than formatted (security.md §2 —
                    // error bodies can echo token material), matching the
                    // 3P poller's identical `let _ = e;` convention.
                    tracing::warn!(account = id, "Grok poller: failed to write billing data");
                    let _ = e;
                }
            }
            Ok(Err(PollError::RateLimited)) => {
                tracing::warn!(account = id, "Grok poller: 429 rate limited");
                super::set_cooldown(cooldowns, id);
            }
            Ok(Err(PollError::Unauthorized)) => {
                // Expected whenever the vendor CLI has not refreshed this
                // slot's token recently — csq does not refresh native
                // tokens (0135 design lock).
                tracing::warn!(account = id, "Grok poller: 401/403 unauthorized");
                super::set_cooldown(cooldowns, id);
            }
            Ok(Err(PollError::Transport(_))) => {
                debug!(account = id, "Grok poller: transport error");
                super::set_cooldown(cooldowns, id);
            }
            Ok(Err(PollError::BadUrl(_))) => {
                // Operator misconfiguration (GROK_CLI_CHAT_PROXY_BASE_URL
                // tripped the outbound char guard), not a network
                // failure — logged at WARN so it's visible without
                // debug logging, and distinct from "transport error" so
                // the operator isn't left guessing which axis broke.
                tracing::warn!(
                    account = id,
                    error_kind = "grok_poll_bad_url",
                    "Grok poller: outbound url rejected — check GROK_CLI_CHAT_PROXY_BASE_URL"
                );
                super::set_cooldown(cooldowns, id);
            }
            Ok(Err(PollError::Parse(_))) => {
                tracing::warn!(account = id, "Grok poller: unparseable billing response");
                super::set_cooldown(cooldowns, id);
            }
            Ok(Err(PollError::HttpError(status))) => {
                tracing::warn!(account = id, status, "Grok poller: billing HTTP error");
                super::set_cooldown(cooldowns, id);
            }
            Err(join_err) => {
                tracing::warn!(
                    account = id,
                    panicked = join_err.is_panic(),
                    "Grok poller: poll task did not complete"
                );
                super::set_cooldown(cooldowns, id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Verbatim-field fixture. Field NAMES are exactly the contiguous
    /// serde run recovered from the shipped grok binary following
    /// `Failed to parse billing data:`. The VALUES are synthetic — no
    /// live response was captured (see module docs), so this fixture
    /// asserts the parser's field mapping, not upstream semantics.
    const FIXTURE: &str = r#"{
        "month": "2026-07",
        "creditUsagePercent": 42.5,
        "currentPeriod": "2026-07",
        "monthlyLimit": 500.0,
        "onDemandCap": 100.0,
        "onDemandUsed": 12.25,
        "prepaidBalance": 187.5,
        "isUnifiedBillingUser": true,
        "billingPeriodStart": "2026-07-01T00:00:00Z",
        "billingCycle": "monthly",
        "includedUsed": 312.5,
        "totalUsed": 324.75,
        "subscriptionTier": "SuperGrok"
    }"#;

    fn mock_get(status: u16, body: &'static str) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((status, body.as_bytes().to_vec()))
        })
    }

    #[test]
    fn parses_verbatim_field_fixture() {
        let b = parse_grok_billing(FIXTURE.as_bytes()).expect("fixture must parse");
        assert_eq!(b.prepaid_balance, Some(187.5));
        assert_eq!(b.credit_usage_percent, Some(42.5));
        assert_eq!(b.monthly_limit, Some(500.0));
        assert_eq!(b.included_used, Some(312.5));
        assert_eq!(b.total_used, Some(324.75));
        assert_eq!(b.on_demand_used, Some(12.25));
        assert_eq!(b.on_demand_cap, Some(100.0));
        assert_eq!(b.billing_cycle.as_deref(), Some("monthly"));
        assert_eq!(b.subscription_tier.as_deref(), Some("SuperGrok"));
    }

    #[test]
    fn prepaid_balance_becomes_the_rendered_balance() {
        let b = parse_grok_billing(FIXTURE.as_bytes()).unwrap();
        let bal = b.balance().expect("prepaidBalance must yield a balance");
        assert_eq!(bal.currency, "USD");
        assert!((bal.remaining - 187.5).abs() < 1e-9);
    }

    /// Grok has no 5h/7d windows. The poller must never populate them —
    /// mapping a monthly credit figure into a 7-day window would be a
    /// fabrication (task requirement: render absent, never fake).
    #[test]
    fn never_populates_five_hour_or_seven_day_windows() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = parse_grok_billing(FIXTURE.as_bytes()).unwrap();
        write_grok_billing(dir.path(), 17, &b).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(17).expect("slot 17 row");
        assert!(row.five_hour.is_none(), "5h window must stay absent");
        assert!(row.seven_day.is_none(), "7d window must stay absent");
    }

    #[test]
    fn snake_case_field_names_also_parse() {
        let body = r#"{"prepaid_balance":10.0,"credit_usage_percent":5.0,"subscription_tier":"x"}"#;
        let b = parse_grok_billing(body.as_bytes()).unwrap();
        assert_eq!(b.prepaid_balance, Some(10.0));
        assert_eq!(b.credit_usage_percent, Some(5.0));
        assert_eq!(b.subscription_tier.as_deref(), Some("x"));
    }

    /// Upstream may encode money as a decimal string (DeepSeek does).
    #[test]
    fn string_encoded_numbers_parse() {
        let body = r#"{"prepaidBalance":"187.50","totalUsed":"324.75"}"#;
        let b = parse_grok_billing(body.as_bytes()).unwrap();
        assert_eq!(b.prepaid_balance, Some(187.5));
        assert_eq!(b.total_used, Some(324.75));
    }

    /// An absent window must render absent — never a fabricated 0.
    #[test]
    fn absent_prepaid_balance_yields_no_balance_row() {
        let body = r#"{"creditUsagePercent":42.5,"monthlyLimit":500.0}"#;
        let b = parse_grok_billing(body.as_bytes()).unwrap();
        assert!(
            b.balance().is_none(),
            "absent prepaidBalance must not become $0.00"
        );

        let dir = tempfile::TempDir::new().unwrap();
        write_grok_billing(dir.path(), 17, &b).unwrap();
        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(17).unwrap();
        assert!(row.balance.is_none(), "must not fabricate a zero balance");
        assert_eq!(row.kind, "unknown");
    }

    /// MED-1 (an internal ticket redteam): a schema-drifted `quota.json` must NOT
    /// be clobbered by this write leg. Before the fix,
    /// `load_state_or_warn`'s `QuotaFile::empty()` fallback let this
    /// write persist a one-row file, wiping every sibling account's row.
    #[test]
    fn write_grok_billing_skips_on_poisoned_file_preserving_siblings() {
        let dir = tempfile::TempDir::new().unwrap();
        let poisoned = r#"{
            "schema_version": 99,
            "accounts": {
                "1": {"five_hour": {"used_percentage": 50.0, "resets_at": 4102444800}, "updated_at": 1.0},
                "2": {"five_hour": {"used_percentage": 80.0, "resets_at": 4102444800}, "updated_at": 1.0}
            }
        }"#;
        std::fs::write(quota_state::quota_path(dir.path()), poisoned).unwrap();

        let b = parse_grok_billing(FIXTURE.as_bytes()).unwrap();
        let result = write_grok_billing(dir.path(), 3, &b);
        assert!(result.is_ok(), "skip must be Ok(()), not an error");

        let raw = std::fs::read_to_string(quota_state::quota_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            v["accounts"]["1"]["five_hour"]["used_percentage"].as_f64(),
            Some(50.0)
        );
        assert_eq!(
            v["accounts"]["2"]["five_hour"]["used_percentage"].as_f64(),
            Some(80.0)
        );
        assert!(v["accounts"].get("3").is_none());
    }

    /// A SUBSCRIPTION account must render its period window, not its
    /// meaningless zero balance.
    ///
    /// Built from the shape a live account actually returned (2026-08-02):
    /// `prepaidBalance: 0.0` (real, but the user never bought credit),
    /// `creditUsagePercent: 6.0`, weekly period ending 2026-08-07. What
    /// shipped rendered "$0.00" — which reads as "out of money" — while
    /// the 6% sat unrendered in `extras`. The operator reported it as
    /// "why is it showing balance instead of the quota".
    #[test]
    fn subscription_period_window_wins_over_a_zero_prepaid_balance() {
        let b = GrokBilling {
            prepaid_balance: Some(0.0),
            credit_usage_percent: Some(6.0),
            current_period_type: Some("USAGE_PERIOD_TYPE_WEEKLY".into()),
            current_period_end: Some("2026-08-07T11:12:35.900538+00:00".into()),
            ..Default::default()
        };
        let w = b.window().expect("a period window must be produced");
        assert_eq!(w.used_percentage, 6.0);
        // 2026-08-07T11:12:35Z. Derived independently, NOT copied from what
        // the code emitted: `python3 -c "from datetime import datetime;
        // print(int(datetime.fromisoformat('2026-08-07T11:12:35.900538+00:00')
        // .timestamp()))"` -> 1786101155. (First draft hand-guessed
        // 1786187555 — exactly one day out — and the test caught the guess,
        // not the code.)
        assert_eq!(w.resets_at, 1786101155);
        // The zero balance is still REAL data and still parsed — it simply
        // must not be what the operator sees.
        assert_eq!(b.balance().map(|x| x.remaining), Some(0.0));
    }

    /// A genuinely PREPAID account (no period) keeps the dollar figure —
    /// the window preference must not delete the balance path.
    #[test]
    fn prepaid_account_without_a_period_still_renders_its_balance() {
        let b = GrokBilling {
            prepaid_balance: Some(42.5),
            ..Default::default()
        };
        assert!(b.window().is_none(), "no period => no window");
        assert_eq!(b.balance().map(|x| x.remaining), Some(42.5));
    }

    /// An unparseable period end yields NO window rather than panicking
    /// the poll tick (the `.unwrap()` rustc suggests would abort it).
    #[test]
    fn garbage_period_end_yields_no_window_instead_of_panicking() {
        let b = GrokBilling {
            credit_usage_percent: Some(6.0),
            current_period_end: Some("not-a-date".into()),
            ..Default::default()
        };
        assert!(b.window().is_none());
    }

    #[test]
    fn null_prepaid_balance_is_treated_as_absent() {
        let body = r#"{"prepaidBalance":null,"creditUsagePercent":1.0}"#;
        let b = parse_grok_billing(body.as_bytes()).unwrap();
        assert!(b.prepaid_balance.is_none());
        assert!(b.balance().is_none());
    }

    /// C-L1 (an internal ticket redteam): a root-level `null` must not SHADOW a
    /// valid NESTED value. Before the fix, `field()`'s `or_else` treated
    /// `json.get(key)` returning `Some(Value::Null)` as present, so the
    /// `config` fallback never ran — a live, valid 42 would have been
    /// silently discarded and the tick misreported as "no recognised
    /// credit field". This is the fallback-pinning sibling of
    /// `null_prepaid_balance_is_treated_as_absent` above (which pins the
    /// no-config case): together they hold both properties — a root
    /// `null` with nothing to fall back to stays absent, and a root
    /// `null` with a valid nested sibling falls through to it.
    #[test]
    fn root_null_falls_through_to_config_fallback() {
        let body = r#"{"prepaidBalance":null,"config":{"prepaidBalance":{"val":42.0}}}"#;
        let b = parse_grok_billing(body.as_bytes()).unwrap();
        assert_eq!(b.prepaid_balance, Some(42.0));
        assert_eq!(b.balance().unwrap().remaining, 42.0);
    }

    /// C-N1 (an internal ticket redteam): root-then-config precedence is
    /// intentional (module docs "Parsing strategy") but was previously
    /// undocumented at the point of use and unlogged when the two
    /// values actually disagree. Pins the precedence itself; the
    /// disagreement additionally emits a `debug!` from `field()` so a
    /// future shape migration is visible rather than silent.
    #[test]
    fn root_wins_over_config_when_both_present_and_disagree() {
        let body = r#"{"prepaidBalance":1.0,"config":{"prepaidBalance":{"val":42.0}}}"#;
        let b = parse_grok_billing(body.as_bytes()).unwrap();
        assert_eq!(b.prepaid_balance, Some(1.0));
    }

    #[test]
    fn non_finite_balance_is_rejected() {
        for bad in ["NaN", "inf", "-inf", "infinity"] {
            let body: &'static str =
                Box::leak(format!(r#"{{"prepaidBalance":"{bad}"}}"#).into_boxed_str());
            let b = parse_grok_billing(body.as_bytes()).unwrap();
            assert!(
                b.balance().is_none(),
                "non-finite {bad:?} must not become a balance"
            );
        }
    }

    #[test]
    fn unrecognised_payload_is_a_parse_error() {
        let result = parse_grok_billing(br#"{"somethingElse":1}"#);
        assert!(
            matches!(result, Err(PollError::Parse(_))),
            "expected Parse error, got {result:?}"
        );
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let result = parse_grok_billing(b"not json");
        assert!(matches!(result, Err(PollError::Parse(_))));
    }

    #[test]
    fn http_401_and_403_are_unauthorized() {
        for status in [401u16, 403] {
            let http = mock_get(status, r#"{"error":"denied"}"#);
            let result = poll_grok_billing("tok", &http);
            assert!(
                matches!(result, Err(PollError::Unauthorized)),
                "status {status} must map to Unauthorized, got {result:?}"
            );
        }
    }

    #[test]
    fn http_429_is_rate_limited() {
        let http = mock_get(429, "slow down");
        assert!(matches!(
            poll_grok_billing("tok", &http),
            Err(PollError::RateLimited)
        ));
    }

    #[test]
    fn http_402_out_of_credits_is_an_http_error() {
        let http = mock_get(402, "run out of credits");
        assert!(matches!(
            poll_grok_billing("tok", &http),
            Err(PollError::HttpError(402))
        ));
    }

    #[test]
    fn transport_error_propagates() {
        let http: HttpGetFn = Arc::new(|_u, _t, _h| Err("connection refused".to_string()));
        assert!(matches!(
            poll_grok_billing("tok", &http),
            Err(PollError::Transport(_))
        ));
    }

    #[test]
    fn bad_url_error_classifies_distinctly_from_transport_error() {
        // MED-3 (an internal ticket redteam): a GROK_CLI_CHAT_PROXY_BASE_URL that
        // trips the outbound char guard must classify as BadUrl, not
        // Transport — so the poller's tick match logs a distinct,
        // actionable error_kind instead of "transport error".
        let http: HttpGetFn =
            Arc::new(|_u, _t, _h| Err(crate::http::ERR_URL_UNSAFE_CHARS.to_string()));
        assert!(matches!(
            poll_grok_billing("tok", &http),
            Err(PollError::BadUrl(_))
        ));
    }

    #[tokio::test]
    async fn tick_bad_url_sets_cooldown() {
        // Tick-level companion to `bad_url_error_classifies_distinctly_from_transport_error`
        // (round-2 redteam, code-review lens): that test proves
        // `poll_grok_billing` classifies correctly, but this module had NO
        // `#[tokio::test]` at all — so the `Ok(Err(PollError::BadUrl(_)))`
        // arm's WARN + `set_cooldown` wiring in `tick` (added alongside
        // MED-3) was untested one layer above the already-tested
        // classification. Seeds a real native Grok slot with
        // `write_binding` (same fixture helper
        // `discover_native_finds_kimi_and_grok_markers` uses) plus a real
        // vendor-home `auth.json` so `read_slot_access_token` succeeds and
        // the poll actually runs end-to-end through `tick`.
        use crate::providers::catalog::Surface;
        use crate::providers::native::{native_home_path, write_binding};
        use std::collections::HashMap;
        use std::sync::Mutex;

        let dir = tempfile::TempDir::new().unwrap();
        let slot = crate::types::AccountNum::try_from(8u16).unwrap();
        write_binding(dir.path(), slot, Surface::Grok).unwrap();
        let home = native_home_path(dir.path(), slot, Surface::Grok);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("auth.json"),
            r#"{"issuer::client":{"key":"tok"}}"#,
        )
        .unwrap();

        let http: HttpGetFn =
            Arc::new(|_u, _t, _h| Err(crate::http::ERR_URL_UNSAFE_CHARS.to_string()));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns).await;

        assert!(
            crate::daemon::usage_poller::in_cooldown(&cooldowns, 8),
            "BadUrl must set cooldown for the grok tick loop, same as any other poll failure"
        );
    }

    #[test]
    fn poll_success_maps_through_to_balance() {
        let http = mock_get(200, r#"{"prepaidBalance":42.0}"#);
        let b = poll_grok_billing("tok", &http).expect("must succeed");
        assert_eq!(b.balance().unwrap().remaining, 42.0);
    }

    #[test]
    fn write_round_trips_balance_and_extras() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = parse_grok_billing(FIXTURE.as_bytes()).unwrap();
        write_grok_billing(dir.path(), 17, &b).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(17).expect("slot 17 row");
        assert_eq!(row.surface, "grok");
        assert_eq!(row.kind, "balance");
        assert!((row.balance.as_ref().unwrap().remaining - 187.5).abs() < 1e-9);

        let extras = row.extras.as_ref().expect("extras must be present");
        assert_eq!(extras["credit_usage_percent"], 42.5);
        assert_eq!(extras["monthly_limit"], 500.0);
        assert_eq!(extras["subscription_tier"], "SuperGrok");
    }

    // ── Live-verified capture, 2026-08-01 (issue: parser read root/flat
    // ── fields; the real endpoint nests under `config` and wraps
    // ── numerics as `{"val": N}` — every tick failed silently) ───────

    /// Verbatim capture from `GET .../billing?format=credits` against a
    /// live slot token, 2026-08-01. See module docs "Response shape".
    const LIVE_CAPTURE_FIXTURE: &str = r#"{
        "config": {
            "currentPeriod": {
                "type": "USAGE_PERIOD_TYPE_WEEKLY",
                "start": "2026-07-31T11:12:35.900538+00:00",
                "end": "2026-08-07T11:12:35.900538+00:00"
            },
            "onDemandCap": {"val": 0},
            "onDemandUsed": {"val": 0},
            "isUnifiedBillingUser": true,
            "prepaidBalance": {"val": 0},
            "topUpMethod": "TOP_UP_METHOD_SAVED_PAYMENT_METHOD",
            "billingPeriodStart": "2026-07-31T11:12:35.900538+00:00",
            "billingPeriodEnd": "2026-08-07T11:12:35.900538+00:00"
        }
    }"#;

    #[test]
    fn live_capture_nested_config_shape_parses() {
        let b = parse_grok_billing(LIVE_CAPTURE_FIXTURE.as_bytes())
            .expect("live-verified nested `config` shape must parse");
        assert_eq!(b.prepaid_balance, Some(0.0));
        assert_eq!(b.on_demand_used, Some(0.0));
        assert_eq!(b.on_demand_cap, Some(0.0));
        assert_eq!(b.is_unified_billing_user, Some(true));
        assert_eq!(
            b.current_period_type.as_deref(),
            Some("USAGE_PERIOD_TYPE_WEEKLY")
        );
        assert_eq!(
            b.current_period_start.as_deref(),
            Some("2026-07-31T11:12:35.900538+00:00")
        );
        assert_eq!(
            b.current_period_end.as_deref(),
            Some("2026-08-07T11:12:35.900538+00:00")
        );
    }

    /// A live-reported zero is REAL data (the endpoint answered `0`),
    /// not a missing field — it must render as an actual `$0.00`
    /// balance, never silently disappear. Module docs "Zero credits is
    /// real data".
    #[test]
    fn live_capture_zero_credit_is_a_real_balance_not_a_parse_failure() {
        let b = parse_grok_billing(LIVE_CAPTURE_FIXTURE.as_bytes())
            .expect("a genuine zero-credit response must parse, not error");
        let bal = b
            .balance()
            .expect("API-reported 0 is a real balance and must render");
        assert_eq!(bal.remaining, 0.0);
        assert_eq!(bal.currency, "USD");
    }

    #[test]
    fn live_capture_writes_row_carrying_period_window() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = parse_grok_billing(LIVE_CAPTURE_FIXTURE.as_bytes()).unwrap();
        write_grok_billing(dir.path(), 17, &b).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(17).expect("slot 17 row");
        assert_eq!(row.kind, "balance");
        assert_eq!(row.balance.as_ref().unwrap().remaining, 0.0);

        let extras = row
            .extras
            .as_ref()
            .expect("period window must be carried in extras");
        assert_eq!(extras["current_period_type"], "USAGE_PERIOD_TYPE_WEEKLY");
        assert_eq!(
            extras["current_period_start"],
            "2026-07-31T11:12:35.900538+00:00"
        );
        assert_eq!(
            extras["current_period_end"],
            "2026-08-07T11:12:35.900538+00:00"
        );
        assert_eq!(extras["is_unified_billing_user"], true);
    }

    /// Regression: the ORIGINAL (unconfirmed, binary-derived) flat/root
    /// shape must still parse — a different account type or a future
    /// `format=` value may still emit it. Module docs "Parsing strategy".
    #[test]
    fn top_level_flat_shape_still_parses_no_regression() {
        let body = r#"{
            "prepaidBalance": 42.0,
            "onDemandUsed": 3.5,
            "onDemandCap": 10.0,
            "creditUsagePercent": 35.0,
            "monthlyLimit": 100.0,
            "includedUsed": 12.0,
            "totalUsed": 15.5,
            "billingCycle": "monthly",
            "subscriptionTier": "SuperGrok"
        }"#;
        let b = parse_grok_billing(body.as_bytes()).expect("flat top-level shape must still parse");
        assert_eq!(b.prepaid_balance, Some(42.0));
        assert_eq!(b.on_demand_used, Some(3.5));
        assert_eq!(b.on_demand_cap, Some(10.0));
        let bal = b.balance().expect("must render a balance");
        assert_eq!(bal.remaining, 42.0);
    }

    /// If `is_empty()` did not count the period window, a response
    /// carrying ONLY `config.currentPeriod` (no credit numerics at all)
    /// would incorrectly error as unusable, discarding the one usage
    /// signal it carries.
    #[test]
    fn period_window_alone_prevents_false_parse_failure() {
        let body = r#"{"config":{"currentPeriod":{
            "type":"USAGE_PERIOD_TYPE_WEEKLY",
            "start":"2026-07-31T00:00:00Z",
            "end":"2026-08-07T00:00:00Z"
        }}}"#;
        let b = parse_grok_billing(body.as_bytes())
            .expect("period-window-only payload must not be treated as unusable");
        assert_eq!(
            b.current_period_type.as_deref(),
            Some("USAGE_PERIOD_TYPE_WEEKLY")
        );
        assert!(
            b.balance().is_none(),
            "no credit field present -> no balance, but not an error"
        );
    }

    /// Pins the distinction the bug class hinges on: a genuine all-zero
    /// credit response (the endpoint answered "0") parses to `Ok` with a
    /// real balance; a payload carrying none of the recognised fields is
    /// a `Parse` error. The two must never collapse into the same
    /// outcome.
    #[test]
    fn genuine_zero_response_and_parse_failure_are_distinguishable() {
        // Genuine zero: every recognised field present with value 0
        // (nested `.val` shape) plus the period window -- this is REAL
        // data, confirmed by the endpoint.
        let zero_body = r#"{"config":{
            "prepaidBalance":{"val":0},
            "onDemandUsed":{"val":0},
            "onDemandCap":{"val":0},
            "currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY",
                              "start":"2026-07-31T00:00:00Z",
                              "end":"2026-08-07T00:00:00Z"}
        }}"#;
        let zero = parse_grok_billing(zero_body.as_bytes());
        assert!(zero.is_ok(), "a genuine zero-credit answer must parse");
        assert_eq!(zero.unwrap().balance().unwrap().remaining, 0.0);

        // Unusable: none of the recognised fields present at all.
        let unusable_body = r#"{"config":{"someUnrelatedField": true}}"#;
        let unusable = parse_grok_billing(unusable_body.as_bytes());
        assert!(
            matches!(unusable, Err(PollError::Parse(_))),
            "a payload with no recognised field must be a Parse error, not Ok(all-zero)"
        );
    }

    // ── URL construction ────────────────────────────────────────────

    #[test]
    fn default_billing_url_joins_chat_proxy_base() {
        // Calls the function under test — a literal-only assert would
        // be vacuous (redteam R1, same class as the kimi.rs URL tests).
        // Env override removed so the default path is what fires.
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(CHAT_PROXY_BASE_ENV);
        assert_eq!(
            billing_url(),
            "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
        );
    }

    #[test]
    fn base_url_trailing_slash_does_not_double_up() {
        let _g = crate::platform::test_env::lock();
        std::env::set_var(CHAT_PROXY_BASE_ENV, "https://p.example.com/v1/");
        assert_eq!(
            billing_url(),
            "https://p.example.com/v1/billing?format=credits"
        );
        std::env::remove_var(CHAT_PROXY_BASE_ENV);
    }

    // ── Per-slot token channel (an internal ticket bug class) ───────────────

    #[test]
    fn reads_token_from_the_slots_own_vendor_home() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(17u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Grok,
        );
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("auth.json"),
            r#"{"https://auth.x.ai::client-abc":{"key":"slot-17-token","auth_mode":"oidc"}}"#,
        )
        .unwrap();

        assert_eq!(
            read_slot_access_token(dir.path(), slot).as_deref(),
            Some("slot-17-token")
        );
    }

    #[test]
    fn missing_vendor_home_yields_no_token_rather_than_erroring() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        // Slot 17 bound but never launched — exactly the maintainer's
        // current host state.
        let slot = AccountNum::try_from(17u16).unwrap();
        assert!(read_slot_access_token(dir.path(), slot).is_none());
    }

    #[test]
    fn empty_key_is_not_accepted_as_a_token() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(17u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Grok,
        );
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("auth.json"), r#"{"e":{"key":""}}"#).unwrap();
        assert!(read_slot_access_token(dir.path(), slot).is_none());
    }

    /// Two Grok slots must read two DIFFERENT tokens — the per-slot home
    /// is the whole point of the 0135 model, and cross-reading would be
    /// the issue-an internal ticket bug class.
    #[test]
    fn two_slots_read_their_own_distinct_tokens() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        for (n, tok) in [(17u16, "token-17"), (18u16, "token-18")] {
            let slot = AccountNum::try_from(n).unwrap();
            let home = crate::providers::native::native_home_path(
                dir.path(),
                slot,
                crate::providers::catalog::Surface::Grok,
            );
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(
                home.join("auth.json"),
                format!(r#"{{"iss::cid":{{"key":"{tok}"}}}}"#),
            )
            .unwrap();
        }
        assert_eq!(
            read_slot_access_token(dir.path(), AccountNum::try_from(17u16).unwrap()).as_deref(),
            Some("token-17")
        );
        assert_eq!(
            read_slot_access_token(dir.path(), AccountNum::try_from(18u16).unwrap()).as_deref(),
            Some("token-18")
        );
    }
}
