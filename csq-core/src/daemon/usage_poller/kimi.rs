//! Kimi (Moonshot AI) quota polling — Bearer-authenticated, 5h + 7d windows.
//!
//! Polls the Kimi coding-subscription `/usages` endpoint for a slot's
//! quota and writes the standard 5-hour + 7-day `UsageWindow` rows to
//! `quota.json`, so a Kimi slot renders real numbers instead of
//! `api-key — not quota-polled` / `native-cli — not quota-polled`.
//!
//! # Endpoint — verified live 2026-07-29
//!
//! ```text
//! GET {base}/v1/usages
//! Authorization: Bearer {token}
//! Accept: application/json
//! ```
//!
//! `{base}` is `https://api.kimi.com/coding` (the same host the slot's
//! own `ANTHROPIC_BASE_URL` already targets for completions), honoured
//! via the vendor's `KIMI_CODE_BASE_URL` override. The kimi-code CLI
//! binary contains the path verbatim: `return \`${kimiCodeBaseUrl()}/usages\``
//! where `kimiCodeBaseUrl()` defaults to `https://api.kimi.com/coding/v1`.
//!
//! A live probe with a real `sk-kimi-…` slot credential returned
//! **HTTP 200 with NO cookie** — Bearer alone suffices. The earlier
//! `catalog.rs` comment claiming "the Kimi coding endpoint exposes no
//! balance/utilization endpoint" was wrong: the surface exists, it just
//! was not on the public docs page csq originally consulted.
//!
//! # Response shape (verbatim capture, token redacted)
//!
//! ```json
//! {
//!   "user": { "userId": "…", "region": "REGION_OVERSEA",
//!             "membership": { "level": "LEVEL_STANDARD" } },
//!   "usage":  { "limit": "100", "used": "57", "remaining": "43",
//!               "resetTime": "2026-08-04T00:52:39.841665Z" },
//!   "limits": [
//!     { "window": { "duration": 300, "timeUnit": "TIME_UNIT_MINUTE" },
//!       "detail": { "limit": "100", "used": "34", "remaining": "66",
//!                   "resetTime": "2026-07-29T01:52:39.841665Z" } }
//!   ],
//!   "parallel": { "limit": "30", "details": ["…"] },
//!   "authentication": { "method": "METHOD_API_KEY",
//!                       "scope": "FEATURE_CODING" }
//! }
//! ```
//!
//! Two distinct windows are present:
//!
//! - **Top-level `usage`** — the 7-day window (the page's
//!   `7-day quota` pane). Maps to [`AccountQuota::seven_day`].
//! - **`limits[i]` whose `window.duration == 300` and
//!   `window.timeUnit == "TIME_UNIT_MINUTE"`** — the 5-hour window
//!   (300 minutes = 5 hours). Maps to [`AccountQuota::five_hour`].
//!
//! All quota numerics are encoded as **JSON strings** (`"100"`, not
//! `100`). The parser accepts both numbers and strings.
//!
//! `used_percentage` is computed as `used / limit * 100`. The endpoint
//! does not return a percentage directly; this is the same convention
//! the Anthropic poller already uses (`utilization` is 0-100).
//!
//! # Token channels — slot 13 (3P API key) AND slot 14 (native OAuth)
//!
//! Two distinct Kimi identities exist in csq's model and each polls
//! with its own credential per `account-terminal-separation.md`:
//!
//! - **3P bearer slot** (e.g. slot 13): `sk-kimi-…` API key read from
//!   `config-<N>/settings.json` (`env.ANTHROPIC_AUTH_TOKEN`) via
//!   [`super::third_party::load_3p_api_key_for_slot`]. Discovered via
//!   `accounts::discovery::discover_all` filtered to
//!   `ThirdParty { provider: "Kimi" }`.
//! - **Native kimi-code CLI slot** (e.g. slot 14): OAuth `access_token`
//!   read from the slot's OWN per-slot vendor home
//!   (`native-homes/kimi-<N>/credentials/kimi-code.json`). Discovered
//!   via `accounts::discovery::discover_native` filtered to
//!   `Surface::Kimi`. csq does NOT refresh native tokens (journal-0135
//!   design lock — the vendor CLI self-refreshes in place); an expired
//!   token yields `401` → cooldown.
//!
//! Both slots poll the SAME account quota (same `userId`) with their
//! OWN tokens — they are distinct identities in csq's model and never
//! share a credential.

use crate::quota::{state as quota_state, AccountQuota, UsageWindow};
use std::path::Path;
use tracing::debug;

use super::{classify_transport_error, HttpGetFn, PollError, MAX_ACCOUNTS_PER_TICK};

/// Default Kimi coding-subscription base. Matches the catalog's
/// `default_base_url` for the 3P `kimi` provider AND slot 13's live
/// `ANTHROPIC_BASE_URL` (verified 2026-07-29).
pub(crate) const DEFAULT_BASE: &str = "https://api.kimi.com/coding";

/// Vendor-documented override for the base URL (the kimi-code binary
/// reads `KIMI_CODE_BASE_URL`; same convention).
pub(crate) const BASE_ENV: &str = "KIMI_CODE_BASE_URL";

/// Path appended to the base. Verbatim binary literal — the kimi-code
/// CLI's usage module returns `\`${kimiCodeBaseUrl()}/usages\``.
pub(crate) const USAGES_PATH: &str = "/v1/usages";

/// `window.duration` value identifying the 5-hour sub-window inside
/// `limits[]` (300 minutes = 5 hours, confirmed against the live
/// response's per-window `resetTime` delta).
pub(crate) const FIVE_HOUR_DURATION_MINUTES: u64 = 300;

/// `window.timeUnit` value the endpoint uses for minute-granularity
/// windows. Verbatim string from the live response.
pub(crate) const TIME_UNIT_MINUTE: &str = "TIME_UNIT_MINUTE";

/// Builds the usages URL with no slot context: the vendor's env
/// override, else the default. Prefer [`usages_url_for`] at poll sites
/// so a slot's OWN configured base keeps token and target consistent.
pub(crate) fn usages_url() -> String {
    usages_url_for(None)
}

/// Builds the usages URL, honouring an explicit slot-configured base
/// first, then the vendor's `KIMI_CODE_BASE_URL` override, then the
/// default.
///
/// `base_override` is the slot's OWN configured base
/// (`config-<N>/settings.json` env.ANTHROPIC_BASE_URL), passed only
/// when it still classifies as a Kimi host — the caller filters. This
/// mirrors tick_3p, which re-reads the slot's CURRENT base at probe
/// time (third_party.rs) so a relay/regional endpoint's token is only
/// ever sent to its own host.
///
/// Every override source is normalized: trailing `/` AND a trailing
/// `/v1` are stripped before [`USAGES_PATH`] is appended. The vendor's
/// `kimiCodeBaseUrl()` convention INCLUDES `/v1`, so an operator who
/// copies the vendor value into `KIMI_CODE_BASE_URL` must not produce
/// `.../coding/v1/v1/usages` (404 → cooldown, silently stale slot).
pub(crate) fn usages_url_for(base_override: Option<&str>) -> String {
    let raw = base_override
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var(BASE_ENV)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_BASE.to_string());
    let normalized = raw.trim_end_matches('/');
    let normalized = normalized.strip_suffix("/v1").unwrap_or(normalized);
    format!("{normalized}{USAGES_PATH}")
}

/// Reads a u64 field that the API may encode as a JSON string (`"300"`),
/// a bare integer (`300`), or — Finding C — a JSON **float** (`300.0`).
/// serde_json stores every bare number as `f64` internally, so
/// `Number::as_u64()` returns `None` for a float-typed `300.0` even
/// though it is a whole, non-negative number; without the `as_f64`
/// fallback a vendor emitting `"duration": 300.0` would silently fail
/// the 5h-window match with no error — the response still has a 7d
/// window, so `is_empty()` stays false and the row is written missing
/// just the 5h bar, indistinguishable from "no 5h limit configured".
/// The endpoint string-encodes every OTHER numeric (`"limit": "100"`),
/// so `window.duration` gets the same tolerance even though the live
/// capture showed a bare integer — a future harmonization to `"300"` or
/// `300.0` must not silently drop the 5h window.
fn u64_str_or_num(v: &serde_json::Value, key: &str) -> Option<u64> {
    let field = v.get(key)?;
    match field {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite() && f.fract() == 0.0 && *f >= 0.0)
                .map(|f| f as u64)
        }),
        serde_json::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
}

/// Parsed Kimi `/usages` response. Each window is optional — an absent
/// window renders absent, never a fabricated 0%.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct KimiUsages {
    /// 5-hour window, sourced from `limits[i]` whose
    /// `window.duration == 300 && window.timeUnit == "TIME_UNIT_MINUTE"`.
    pub five_hour: Option<UsageWindow>,
    /// 7-day window, sourced from the top-level `usage` object.
    pub seven_day: Option<UsageWindow>,
    /// Membership level (e.g. `LEVEL_STANDARD`) preserved verbatim
    /// under `extras` for the dashboard's hover detail.
    pub membership_level: Option<String>,
    /// `authentication.method` (e.g. `METHOD_API_KEY`) preserved
    /// verbatim under `extras`.
    pub auth_method: Option<String>,
}

impl KimiUsages {
    /// True when the response carried no quota window this poller
    /// understands — the signal to treat the payload as unusable
    /// rather than write an all-absent row.
    fn is_empty(&self) -> bool {
        self.five_hour.is_none() && self.seven_day.is_none()
    }

    /// Surface-specific figures preserved verbatim under `extras`.
    /// Keeps the metadata (membership level, auth method) without
    /// fabricating any quota value.
    fn extras(&self) -> Option<serde_json::Value> {
        let mut map = serde_json::Map::new();
        if let Some(s) = &self.membership_level {
            map.insert(
                "membership_level".to_string(),
                serde_json::Value::String(s.clone()),
            );
        }
        if let Some(s) = &self.auth_method {
            map.insert(
                "authentication_method".to_string(),
                serde_json::Value::String(s.clone()),
            );
        }
        if map.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(map))
        }
    }
}

/// Reads a numeric field that the API encodes as a JSON **string**
/// (`"57"`) but tolerates a JSON number for forward compatibility.
fn num_str_or_num(v: &serde_json::Value, key: &str) -> Option<f64> {
    let field = v.get(key)?;
    match field {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn text(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(|s| s.to_string())
}

/// Builds a [`UsageWindow`] from a `{limit, used, resetTime}` blob.
/// Returns `None` when any field is missing, non-finite, `limit <= 0`
/// (division guard), `used < 0` (redteam finding A + R13 correction,
/// see below), or the COMPUTED percentage is still negative after that
/// (defense in depth). `used` MAY exceed `limit` when the account is
/// throttled — the percentage may be >100, mirroring how CC's own
/// statusline reports.
///
/// # `used < 0` is a REQUIRED input guard, not dead code (R13 correction)
///
/// An earlier version of this doc comment claimed a `used < 0` input
/// check would be "permanently-unobservable dead code" layered on top
/// of the `pct < 0.0` computed-ratio guard below, on the theory that —
/// given `limit <= 0` is already rejected — `used < 0` and `pct < 0`
/// are the SAME condition for any surviving (positive) `limit`. **That
/// claim is FALSE at the subnormal-underflow boundary**, verified
/// numerically (IEEE-754 f64 bit patterns; same representation in
/// Python and Rust):
///
/// ```text
/// used  = -5e-324   (smallest-magnitude negative f64 subnormal)
/// limit = 100.0
/// used / limit  = -5e-326 → underflows below the smallest subnormal,
///                 flushing to -0.0 (sign preserved, magnitude to zero)
/// pct = (used / limit) * 100.0 = -0.0
/// pct < 0.0    → false   (IEEE-754: -0.0 == 0.0, so `<` is false)
/// used < 0.0   → true
/// ```
///
/// So for this input the division-then-multiply underflows a
/// genuinely negative `used` all the way to signed zero BEFORE
/// `pct < 0.0` ever sees it — the two conditions are NOT equivalent,
/// and `used < 0` is folded into the input-level guard below rather
/// than treated as redundant. The prior "verified empirically" claim
/// rested on a single non-boundary case (`"used": "-5"`, see
/// `negative_used_is_rejected`) — one data point cannot establish a
/// universal claim; `used_underflows_to_negative_zero_is_still_rejected`
/// pins the boundary case this comment now documents, and contrasts it
/// against `negative_used_is_rejected` to prove the two guards are
/// genuinely distinct, not the same check exercised twice.
fn window_from_detail(detail: &serde_json::Value) -> Option<UsageWindow> {
    let limit = num_str_or_num(detail, "limit")?;
    // `used` is no longer guaranteed. Verified live against a real slot
    // credential on 2026-08-05: BOTH window sources — the top-level `usage`
    // object (7d) and `limits[].detail` (5h) — now return exactly
    // `{limit, remaining, resetTime}`. The `used` field this parser was
    // written against (and which the module doc's captured response still
    // shows) is simply gone.
    //
    // Requiring it made BOTH windows unparseable, so `KimiUsages::is_empty`
    // was true on every poll, the poll was discarded as
    // `NO_RECOGNISED_WINDOW_MSG`, a cooldown was set, and NOTHING was
    // written — freezing `updated_at` while the credential stayed perfectly
    // healthy (`csq probe 13` → 2/2 OK). The slot then renders
    // `api-key — not quota-polled` and an ever-growing "stale Nd" forever.
    //
    // `remaining` is a first-class field of the SAME object, so the used
    // figure is still fully determined — derive it rather than throw the
    // poll away. This is not papering over an upstream defect: it is
    // reading the payload the API actually returns. Clamped at 0 because a
    // `remaining > limit` response (vendor rounding, or a mid-window quota
    // raise) must not yield a negative `used` that the guards below would
    // reject outright.
    let used = match num_str_or_num(detail, "used") {
        Some(u) => u,
        None => {
            let remaining = num_str_or_num(detail, "remaining")?;
            if !remaining.is_finite() || remaining < 0.0 {
                return None;
            }
            (limit - remaining).max(0.0)
        }
    };
    let reset_str = text(detail, "resetTime")?;
    let resets_at = super::anthropic::parse_iso8601_to_epoch(&reset_str)?;
    if !limit.is_finite() || !used.is_finite() || limit <= 0.0 || used < 0.0 {
        return None;
    }
    // Guard the COMPUTED ratio too, not just the inputs: used="1e307",
    // limit="1" overflows to f64::INFINITY, and serde_json serializes a
    // non-finite f64 as null — writing that row would make the whole
    // quota.json unparseable on next load, and every writer's
    // `unwrap_or_else(|_| QuotaFile::empty())` fallback would then wipe
    // all sibling accounts' rows (redteam R1 LOW). grok.rs guards its
    // output side identically. This is defense-in-depth alongside the
    // `used < 0.0` input guard above, NOT a substitute for it — see the
    // doc comment above for why the two diverge at the subnormal
    // underflow boundary.
    let pct = (used / limit) * 100.0;
    if !pct.is_finite() || pct < 0.0 {
        return None;
    }
    // NIT-1 (redteam): `used: "-0"` computes `pct = -0.0`, which is
    // finite and NOT `< 0.0` (IEEE-754 `-0.0 == 0.0`), so it survives
    // both guards above and would render as a `-0%` usage bar. This is
    // DISTINCT from the `used < 0.0` input guard above: `"-0"` parses
    // to `-0.0`, and `-0.0 < 0.0` is false, so it is a legitimate zero
    // (not a rejected negative) — normalize the sign, don't reject it.
    let pct = if pct == 0.0 { 0.0 } else { pct };
    Some(UsageWindow {
        used_percentage: pct,
        resets_at,
    })
}

/// The fixed message `parse_kimi_usages` returns when the body parsed as
/// valid JSON but carried neither a recognised 5h nor 7d window.
///
/// Finding D: this is the ONLY thing distinguishing that case from a
/// genuinely malformed body inside the shared `PollError::Parse(String)`
/// variant — `handle_poll_result` compares against this constant rather
/// than adding a new `PollError` variant (which every sibling poller's
/// match arms would then need to handle) or logging the raw message
/// (parser error strings can echo body fragments — security.md §2).
pub(crate) const NO_RECOGNISED_WINDOW_MSG: &str =
    "usages response carried no recognised 5h or 7d window";

/// Parses a Kimi `/usages` response body.
///
/// - 5-hour: the `limits[i]` entry whose `window.duration == 300` and
///   `window.timeUnit == "TIME_UNIT_MINUTE"`.
/// - 7-day: the top-level `usage` object.
/// - Both are optional; absent windows stay absent.
///
/// Returns `Err(PollError::Parse)` in two DISTINCT cases (Finding D):
/// the body is not JSON (message is `serde_json::Error::to_string()`),
/// or the body parsed fine but NEITHER window could be recognised
/// (message is exactly [`NO_RECOGNISED_WINDOW_MSG`]) — i.e. the response
/// carried no usable quota signal at all. `handle_poll_result`
/// distinguishes the two so an API contract drift (valid JSON, renamed
/// fields) is not misreported as "unparseable".
pub(crate) fn parse_kimi_usages(body: &[u8]) -> Result<KimiUsages, PollError> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| PollError::Parse(e.to_string()))?;

    // 5-hour: scan limits[] for the 300-minute entry.
    let five_hour = json
        .get("limits")
        .and_then(|l| l.as_array())
        .and_then(|arr| {
            arr.iter().find(|entry| {
                let w = entry.get("window");
                let duration = w.and_then(|w| u64_str_or_num(w, "duration"));
                let unit = w.and_then(|w| w.get("timeUnit")).and_then(|u| u.as_str());
                duration == Some(FIVE_HOUR_DURATION_MINUTES) && unit == Some(TIME_UNIT_MINUTE)
            })
        })
        .and_then(|entry| entry.get("detail"))
        .and_then(window_from_detail);

    // 7-day: the top-level `usage` object.
    let seven_day = json.get("usage").and_then(window_from_detail);

    let membership_level = json
        .get("user")
        .and_then(|u| u.get("membership"))
        .and_then(|m| text(m, "level"));
    let auth_method = json.get("authentication").and_then(|a| text(a, "method"));

    let usages = KimiUsages {
        five_hour,
        seven_day,
        membership_level,
        auth_method,
    };

    if usages.is_empty() {
        return Err(PollError::Parse(NO_RECOGNISED_WINDOW_MSG.into()));
    }
    Ok(usages)
}

/// Polls the Kimi `/usages` endpoint at `url` with `token` (the slot's
/// OWN bearer credential — `sk-kimi-…` for 3P, OAuth access_token for
/// native) and returns the parsed windows. `url` comes from
/// [`usages_url_for`] so the token is only ever sent to the host the
/// slot itself is configured against.
pub(crate) fn poll_kimi_usages(
    token: &str,
    http_get: &HttpGetFn,
    url: &str,
) -> Result<KimiUsages, PollError> {
    let extra_headers = [("Accept", "application/json")];

    let (status, body) = http_get(url, token, &extra_headers).map_err(classify_transport_error)?;

    match status {
        429 => return Err(PollError::RateLimited),
        401 | 403 => return Err(PollError::Unauthorized),
        200 => {}
        other => return Err(PollError::HttpError(other)),
    }

    parse_kimi_usages(&body)
}

/// Outcome of reading a native slot's vendor credential file. The
/// three states are semantically distinct and MUST NOT be collapsed
/// into one Option (redteam R1 MED): a silent skip is honest ONLY for
/// the never-launched case; present-but-unusable is the vendor
/// layout-drift signal and must surface.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NativeTokenRead {
    /// File absent — slot bound but never launched. Honest, transient,
    /// self-resolving on the first vendor CLI run. Skip at debug, NO
    /// cooldown.
    NotFound,
    /// File present but unparseable JSON, or the `access_token` key is
    /// absent/empty/renamed/nested. The key shape is inference (never
    /// live-probed — the 3P endpoint has a verbatim binary citation,
    /// this file's SCHEMA has none), so this is the drift case: warn +
    /// cooldown surfaces the failure in the DAEMON LOG, not on any CLI
    /// surface — like every other non-success path in
    /// [`handle_poll_result`] (rate-limited, unauthorized, transport,
    /// call-timeout, parse/contract-drift, HTTP error, a discarded write
    /// failure), no quota row is written, so `csq ls`/statusline render
    /// the same pre-existing "not quota-polled" placeholder either way.
    /// The daemon log is the only discriminator (LOW-3 correction — an
    /// earlier draft of this comment overstated this as
    /// "operator-visible").
    Unusable,
    /// A usable bearer token.
    Token(String),
}

/// Reads the OAuth access_token for a native kimi-code CLI slot from
/// its OWN per-slot vendor home (`native-homes/kimi-<N>/` +
/// `descriptor.cred_relpath` — the descriptor is the single source of
/// truth for the vendor credential path; do not re-hardcode it here).
///
/// csq does NOT refresh native tokens (journal-0135 design lock); an
/// expired token yields 401 → cooldown.
pub(crate) fn read_native_access_token(
    base_dir: &Path,
    slot: crate::types::AccountNum,
) -> NativeTokenRead {
    use crate::providers::catalog::Surface;
    let Some(d) = crate::providers::native::descriptor(Surface::Kimi) else {
        // Unreachable today (Kimi is a registered native surface); treat
        // as the honest skip rather than guess a path.
        return NativeTokenRead::NotFound;
    };
    let path = crate::providers::native::native_home_path(base_dir, slot, Surface::Kimi)
        .join(d.cred_relpath);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        // R2 LOW-1: only a genuinely-absent file is the honest
        // never-launched skip. PermissionDenied (a mode-000 cred file)
        // or IsADirectory (a `kimi-code.json/` dir — plausible vendor
        // layout drift) are the PRESENT-but-unusable drift case the
        // tri-state exists to surface; mapping them to NotFound would
        // re-open the silent-skip class the R1 MED fix closed.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return NativeTokenRead::NotFound;
        }
        Err(_) => return NativeTokenRead::Unusable,
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return NativeTokenRead::Unusable;
    };
    json.get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| NativeTokenRead::Token(s.to_string()))
        .unwrap_or(NativeTokenRead::Unusable)
}

/// Bound on the quota-file lock wait for the write leg (redteam finding
/// E). `handle_poll_result` now runs on tokio's blocking-thread pool via
/// [`handle_poll_result_blocking`] (redteam MED-1 — see that function's
/// doc comment), so this retry no longer parks a runtime worker; it
/// still matters because the worst case below is real wall-clock time
/// on a blocking-pool thread, and that pool is finite too. An unbounded
/// `flock(LOCK_EX)` (the previous `lock_file` call) would otherwise
/// stall the write leg forever if `csq logout`/`csq move-slot` held the
/// same `quota.json` lock and stalled. [`acquire_quota_lock_bounded`]
/// retries the non-blocking `try_lock_file_bounded` instead.
///
/// The worst case is platform-specific, NOT the simple
/// `LOCK_RETRY_ATTEMPTS * LOCK_RETRY_DELAY` product a prior draft of
/// this comment claimed (NIT-1 correction). On Unix
/// ([`crate::platform::lock`]'s `imp` module) the lock file is opened
/// ONCE, then `flock` is retried up to `LOCK_RETRY_ATTEMPTS` times with
/// a sleep only BETWEEN attempts (the last attempt never sleeps) — i.e.
/// `LOCK_RETRY_ATTEMPTS - 1` sleeps, not `LOCK_RETRY_ATTEMPTS`. Real
/// worst case is `open_latency + (LOCK_RETRY_ATTEMPTS - 1) *
/// LOCK_RETRY_DELAY` ≈ 950ms of sleep plus one `open(2)` — on the
/// slow-FUSE home this fix targets, a >50ms open pushes the real
/// wall-clock PAST the naive ~1s figure (the fix still improves matters
/// over the previous per-attempt-reopening `try_lock_file` loop —
/// 20 × (open latency + 50ms), redteam NIT-2 — it just does not land on
/// exactly 1s). Windows (same module) takes a DIFFERENT path: one
/// `CreateMutexW`, then a SINGLE native
/// `WaitForSingleObject(handle, LOCK_RETRY_ATTEMPTS * LOCK_RETRY_DELAY)`
/// — no poll loop, so its bound genuinely IS the simple product (~1s)
/// plus the one-time mutex-creation cost.
///
/// The identical unbounded-blocking-lock shape exists in the write legs
/// of 8 sibling pollers — bounding all nine uniformly is a separate
/// shard; this fix bounds kimi's write leg only. Enumerate the current
/// adoption surface with the grep below rather than trusting a
/// hard-coded line list (`security.md` §5a /
/// `account-terminal-separation.md` MUST-1 precedent — a hard-coded
/// list here already needed correcting once, LOW-1 above):
///
/// ```text
/// grep -n 'lock::lock_file(' csq-core/src/daemon/usage_poller/*.rs
/// ```
///
/// Classify each hit as production (a blocking write-leg acquisition)
/// or test-only (inside `#[cfg(test)] mod tests`). 9 production sites
/// as of 2026-07-30: anthropic.rs:336, codex.rs:373, codex.rs:438,
/// deepseek.rs:110, gemini_oauth.rs:495, grok.rs:304, minimax.rs:168,
/// third_party.rs:527, zai.rs:95. `third_party.rs` also has an
/// unrelated, already-non-blocking `try_lock_file` call in its slot-key
/// loader — out of scope. kimi.rs's own three hits and gemini.rs:1069
/// are test-only.
const LOCK_RETRY_ATTEMPTS: u32 = 20;
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Acquires the quota-file lock with a bounded retry instead of blocking
/// indefinitely (see [`LOCK_RETRY_ATTEMPTS`]). Returns
/// `PlatformError::LockContention` (wrapped as `CsqError`) once every
/// attempt has failed. Delegates the actual open-once-retry-the-lock
/// mechanics to [`crate::platform::lock::try_lock_file_bounded`]
/// (redteam NIT-2) rather than looping `try_lock_file` (which reopens
/// the file on every attempt).
fn acquire_quota_lock_bounded(
    lock_path: &Path,
) -> Result<crate::platform::lock::FileLockGuard, crate::error::CsqError> {
    crate::platform::lock::try_lock_file_bounded(lock_path, LOCK_RETRY_ATTEMPTS, LOCK_RETRY_DELAY)?
        .ok_or_else(|| {
            crate::error::PlatformError::LockContention {
                path: lock_path.to_path_buf(),
            }
            .into()
        })
}

/// Writes Kimi usage data into `quota.json` for `account_id`.
///
/// `account_id` is supplied by the caller from slot discovery — an
/// authoritative slot-lifecycle channel. It is never derived from
/// terminal state (`account-terminal-separation.md` MUST Rule 1).
///
/// `surface` is the persisted quota-row surface string: `"kimi"` for
/// the 3P API-key slot, `"kimi-cli"` for the native CLI slot. The
/// status tagger NEVER reads this field — it tags on the ACCOUNT's
/// `Surface`/`AccountSource`: the native slot renders ` [KIMI]`
/// (`Surface::Kimi`), the 3P slot renders ` [kimi]`
/// (`ThirdParty{provider}` lowercased) — the C5/journal-0135 convention
/// (uppercase = native self-authenticating, lowercase = csq-managed).
/// The row's `surface` field is informational only.
///
/// A slot dual-bound to BOTH Kimi shapes (a `config-<N>` 3P key AND a
/// `credentials/kimi-<N>.json` native marker) yields ONLY the native
/// entry from `discover_all` — it is first-source-wins (native markers
/// claim the id at the native priority and the per-slot 3P entry is
/// deduped out), so the 3P loop never polls it and the row's surface
/// is deterministically `"kimi-cli"`. (R5 F2: an earlier draft of this
/// comment described an alternation between the two writers each
/// tick — that race is impossible under the dedupe.)
///
/// A DIFFERENT dual-bind shape — a slot bound to a Kimi native marker
/// AND a DIFFERENT PROVIDER's native marker (e.g. Grok) — is NOT deduped
/// by anything in this module: `discover_native` is called independently
/// by each surface's own tick, so both surfaces enumerate the same slot
/// and each performs its own full-row overwrite (`QuotaFile::set` has no
/// merge — quota/mod.rs). Whichever surface's tick runs LAST in
/// `usage_poller::mod`'s per-cycle ordering wins; the loser's row is
/// silently discarded every tick. This function warns when THIS write
/// clobbers a different surface's row (redteam finding F) — but the
/// detector lives ONLY inside this function's own SUCCESS path
/// (NIT-2 correction: an earlier draft of this comment said "warns
/// loudly instead of staying silent" without qualifying that). Whenever
/// kimi is the FAILING side instead (cooldown skip, `Unusable`, 401/403,
/// 429, timeout, contract drift), `write_kimi_usages` is never called,
/// so a clobber it would have caused goes undetected — exactly the case
/// an operator investigating a missing row is likely to hit. `grok.rs`
/// has no counterpart read-back either, so a kimi-wins clobber of a
/// grok row is symmetrically undetectable from grok's side. Detection,
/// when it fires at all, lags up to one ~15-minute poll cycle (kimi's
/// next successful tick).
pub(crate) fn write_kimi_usages(
    base_dir: &Path,
    account_id: u16,
    surface: &str,
    usages: &KimiUsages,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = acquire_quota_lock_bounded(&lock_path)?;
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
                "Kimi poller: quota.json unreadable, skipping write to avoid clobbering sibling rows"
            );
            return Ok(());
        }
    };

    // Finding F: `QuotaFile::set` is a full-row overwrite with no merge —
    // last writer wins. A slot dual-bound to a Kimi marker AND a
    // DIFFERENT provider's native marker (reachable only via
    // legacy/pre-guard installs or manual filesystem surgery — see the
    // dual-bound test below) would otherwise silently lose the other
    // surface's row every tick this write runs after it. `"kimi"` and
    // `"kimi-cli"` are this poller's OWN two surface strings (3P vs
    // native) and do not trip the warning — only a genuinely different
    // provider's row does. No token/body content is logged
    // (security.md §2) — surface names and the slot id are scalars.
    if let Some(existing) = quota.get(account_id) {
        if existing.surface != "kimi" && existing.surface != "kimi-cli" {
            // LOW-2 (redteam): a bare "dual-bound slot?" diagnosis is a
            // false positive on the expected, one-time transition after
            // a rebind that goes THROUGH `csq logout` — `csq logout`
            // deletes the quota row outright (`remove_quota_entry`,
            // accounts/logout.rs, pinned by the
            // `logout_removes_quota_entry` test), so this branch never
            // observes a stale row from THAT path. It still fires,
            // correctly, on the first tick after any OTHER rebind that
            // does not go through logout — also a one-time, expected
            // transition, not evidence of a standing dual-bind. State
            // the observation rather than asserting a cause, and point
            // at the remediation surface instead of repeating an
            // unactionable question every ~15-minute cycle.
            //
            // LOW-2 correction (redteam): the original remediation text
            // told the operator to run `csq doctor` "to check for a slot
            // bound to two native providers" — `csq doctor`
            // (csq/src/cli/commands/doctor.rs) has no such check; that
            // pointer led nowhere. The message below instead names the
            // concrete on-disk state that genuinely distinguishes this
            // case: a slot with more than one `credentials/<provider>-
            // <N>.json` native binding marker for the same `<N>`
            // (`crate::providers::native::marker_path`).
            tracing::warn!(
                account = account_id,
                previous_surface = %existing.surface,
                new_surface = surface,
                "Kimi poller: overwriting a quota row previously written by a different surface \
                 — expected once after a provider rebind; if this repeats every cycle, check \
                 whether this slot has more than one native binding marker on disk \
                 (`credentials/kimi-<N>.json` and `credentials/grok-<N>.json` etc. for the \
                 same <N>)"
            );
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota.set(
        account_id,
        AccountQuota {
            surface: surface.into(),
            kind: "utilization".into(),
            five_hour: usages.five_hour.clone(),
            seven_day: usages.seven_day.clone(),
            extras: usages.extras(),
            updated_at: now,
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "Kimi poller: quota file updated");
    Ok(())
}

/// One Kimi poll tick: every 3P Kimi slot AND every native kimi-code
/// slot, each polled with its OWN token, each written under its OWN
/// discovered slot id.
///
/// Rides the 3P cadence (15 min) — the quota numbers move slowly and
/// the maintainer's 5h window has 300-minute granularity, so the 5-min
/// Anthropic cadence would be wasted calls.
pub(crate) async fn tick(
    base_dir: &Path,
    http_get: &HttpGetFn,
    cooldowns_3p: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>,
    >,
    cooldowns_native: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>,
    >,
) {
    use crate::accounts::AccountSource;
    use crate::providers::catalog::Surface;

    // ── 3P bearer Kimi slots (slot 13 — sk-kimi- API key) ────────────
    let third_party_slots: Vec<(u16, crate::types::AccountNum)> =
        crate::accounts::discovery::discover_all(base_dir)
            .into_iter()
            .filter(|a| match &a.source {
                AccountSource::ThirdParty { provider } => {
                    crate::providers::catalog::id_from_display_name(provider) == Some("kimi")
                }
                _ => false,
            })
            .filter_map(|a| {
                crate::types::AccountNum::try_from(a.id)
                    .ok()
                    .map(|n| (a.id, n))
            })
            // Bound the per-tick HTTP fan-out. `MAX_ACCOUNTS` is 999, so an
            // unbounded tick can issue that many vendor calls every 5 minutes.
            // Applied AFTER the provider filter (unlike `anthropic.rs`, which
            // truncates the raw discovery result before filtering) so the
            // budget counts slots this poller will actually call, and unrelated
            // rows cannot consume it.
            .take(MAX_ACCOUNTS_PER_TICK)
            .collect();

    for (id, slot) in third_party_slots {
        if crate::daemon::usage_poller::in_cooldown(cooldowns_3p, id) {
            continue;
        }
        // Reuse the existing 3P per-slot key loader — it reads
        // `config-<N>/settings.json` env.ANTHROPIC_AUTH_TOKEN under the
        // bind/unbind RMW try-lock.
        let Some(api_key) =
            super::third_party::load_3p_api_key_for_slot(base_dir, slot.get(), "kimi")
        else {
            debug!(account = id, "Kimi poller: no 3P API key for slot");
            continue;
        };

        // Token and target stay consistent (tick_3p's invariant): poll
        // the slot's OWN configured base when it still classifies as a
        // Kimi host, so a relay/regional endpoint's token is only sent
        // to its own host. A reconfigured base that no longer mentions
        // kimi.com falls back to the default rather than leak the token
        // to an unrelated host. Lowercased to match discovery's own
        // classifier (discovery.rs) — the two kimi.com checks in this
        // dataflow must agree (R2 NIT-1).
        let slot_base = super::third_party::load_3p_base_url_for_slot(base_dir, id)
            .filter(|b| b.to_ascii_lowercase().contains("kimi.com"));
        let url = usages_url_for(slot_base.as_deref());

        let token = api_key.expose_secret().to_string();
        let http = std::sync::Arc::clone(http_get);
        let join_handle =
            tokio::task::spawn_blocking(move || poll_kimi_usages(&token, &http, &url));
        // CALL_TIMEOUT wrap per the house pattern (anthropic.rs): a
        // wedged upstream trickling bytes under the inactivity floor
        // must not stall the ENTIRE poller loop (redteam R1 MED — the
        // bare await blocks anthropic/codex/gemini/3P ticks until
        // daemon restart).
        let result = match tokio::time::timeout(super::CALL_TIMEOUT, join_handle).await {
            Ok(inner) => inner,
            Err(_elapsed) => {
                tracing::warn!(account = id, "Kimi poller: call timed out after 30s");
                crate::daemon::usage_poller::set_cooldown(cooldowns_3p, id);
                continue;
            }
        };

        handle_poll_result_blocking(
            base_dir.to_path_buf(),
            id,
            "kimi",
            result,
            std::sync::Arc::clone(cooldowns_3p),
        )
        .await;
    }

    // ── Native kimi-code CLI slots (slot 14 — OAuth access_token) ────
    //
    // Base-channel asymmetry (R5 F4): the native loop polls the default
    // host (or the process-global KIMI_CODE_BASE_URL) — it has NO
    // per-slot base channel like the 3P loop's slot-base preference,
    // because the vendor home's own config is the vendor CLI's, not
    // csq's, to read. A native slot whose home targets a regional
    // endpoint fails SAFE: 401 → warn + cooldown, never fabricated
    // data; the slot simply does not render quota.

    let native_slots: Vec<(u16, crate::types::AccountNum)> =
        crate::accounts::discovery::discover_native(base_dir)
            .into_iter()
            .filter(|a| matches!(a.source, AccountSource::Native { surface } if surface == Surface::Kimi))
            .filter_map(|a| {
                crate::types::AccountNum::try_from(a.id)
                    .ok()
                    .map(|n| (a.id, n))
            })
            // Bounded independently of the 3P loop above: the two enumerations
            // are disjoint slot sets, so each gets its own per-tick budget.
            .take(MAX_ACCOUNTS_PER_TICK)
            .collect();

    for (id, slot) in native_slots {
        if crate::daemon::usage_poller::in_cooldown(cooldowns_native, id) {
            continue;
        }
        let token = match read_native_access_token(base_dir, slot) {
            NativeTokenRead::Token(t) => t,
            // Slot bound but never launched — the vendor home (and
            // therefore the access_token) does not exist yet. Nothing
            // to poll; not a failure, so no cooldown.
            NativeTokenRead::NotFound => {
                debug!(
                    account = id,
                    "Kimi poller: no per-slot vendor home yet — skipping"
                );
                continue;
            }
            // The vendor cred file EXISTS but yields no usable
            // access_token — the layout-drift case (the key shape is
            // inference, never live-probed). Warn + cooldown surfaces
            // the failure in the DAEMON LOG only (redteam R1 MED) — NOT
            // on any CLI surface; see `NativeTokenRead::Unusable`'s doc
            // comment (LOW-3 correction) for why `csq ls`/statusline
            // render unchanged.
            // NB: at the 15-min 3P cadence the 10-min cooldown has
            // already expired by the next tick, so the warn is the
            // operative signal and fires at most once per tick —
            // the cooldown marks intent; it does not throttle (R2 NIT-2,
            // an inherited cooldown-vs-cadence shape shared with the
            // 3P/grok pollers).
            NativeTokenRead::Unusable => {
                tracing::warn!(
                    account = id,
                    "Kimi poller: native vendor credential file present but no usable access_token — vendor layout drift?"
                );
                crate::daemon::usage_poller::set_cooldown(cooldowns_native, id);
                continue;
            }
        };

        let url = usages_url();
        let http = std::sync::Arc::clone(http_get);
        let join_handle =
            tokio::task::spawn_blocking(move || poll_kimi_usages(&token, &http, &url));
        // Same CALL_TIMEOUT wrap as the 3P loop (redteam R1 MED).
        let result = match tokio::time::timeout(super::CALL_TIMEOUT, join_handle).await {
            Ok(inner) => inner,
            Err(_elapsed) => {
                tracing::warn!(account = id, "Kimi poller: call timed out after 30s");
                crate::daemon::usage_poller::set_cooldown(cooldowns_native, id);
                continue;
            }
        };

        handle_poll_result_blocking(
            base_dir.to_path_buf(),
            id,
            "kimi-cli",
            result,
            std::sync::Arc::clone(cooldowns_native),
        )
        .await;
    }
}

/// Runs [`handle_poll_result`] on tokio's blocking-thread pool instead
/// of bare on the calling async task (redteam MED-1).
///
/// `handle_poll_result`'s success path calls [`write_kimi_usages`],
/// whose [`acquire_quota_lock_bounded`] retries a non-blocking file
/// lock with real `std::thread::sleep` calls between attempts — up to
/// `LOCK_RETRY_ATTEMPTS * LOCK_RETRY_DELAY` (~1s) of genuine thread
/// parking under contention. The daemon's tokio runtime is built with
/// only `worker_threads(2)` (`csq/src/cli/commands/daemon.rs`), so a
/// bare synchronous call from `tick`'s async body would park one of
/// those two workers for up to ~1s per contended slot (3 kimi slots ⇒
/// ~3s) — starving the IPC accept loop, the refresher, and every other
/// poller's tick for that window. `tokio::task::spawn_blocking` moves
/// the call onto tokio's separate blocking-thread pool, matching the
/// house convention already used for Gemini's synchronous filesystem
/// drain (`usage_poller/mod.rs`'s `gemini::drain_all` call).
///
/// Both `tick` call sites (3P and native loops) route through this one
/// function so the wrap cannot drift between them, and so a test can
/// pin the behavior without duplicating it —
/// see `write_leg_does_not_block_the_async_worker`.
async fn handle_poll_result_blocking(
    base_dir: std::path::PathBuf,
    id: u16,
    surface: &'static str,
    result: Result<Result<KimiUsages, PollError>, tokio::task::JoinError>,
    cooldowns: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>>,
) {
    let _ = tokio::task::spawn_blocking(move || {
        handle_poll_result(&base_dir, id, surface, result, &cooldowns);
    })
    .await;
}

/// Discriminates a [`write_kimi_usages`] failure into a fixed-vocabulary
/// log tag (security.md §2 — never the path or the error body). Pulled
/// into a pure function so the mapping itself is pinned by a direct
/// unit test without needing a tracing-capture harness (redteam LOW-1).
fn write_failure_kind(e: &crate::error::CsqError) -> &'static str {
    match e {
        crate::error::CsqError::Platform(crate::error::PlatformError::LockContention {
            ..
        }) => "lock_contention",
        _ => "write_failed",
    }
}

/// Synchronous core of the Kimi poll-result handling — writes the quota
/// row on success, sets/clears cooldown per error class. Called ONLY
/// via [`handle_poll_result_blocking`] from `tick`, which moves this
/// call onto tokio's blocking-thread pool (redteam MED-1); do not call
/// this bare from an async context.
fn handle_poll_result(
    base_dir: &Path,
    id: u16,
    surface: &'static str,
    result: Result<Result<KimiUsages, PollError>, tokio::task::JoinError>,
    cooldowns: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>,
    >,
) {
    match result {
        Ok(Ok(usages)) => {
            super::clear_cooldown(cooldowns, id);
            if let Err(e) = write_kimi_usages(base_dir, id, surface, &usages) {
                // Finding LOW-1 (redteam): a lock-contention write
                // failure means the POLL succeeded but was discarded —
                // no cooldown is set here, so the next attempt rides the
                // ordinary ~15-min 3P cadence rather than a suppressed
                // retry. That is a materially different signal from a
                // genuine write failure (disk full, unwritable
                // quota.json), so the warn discriminates via a
                // fixed-vocabulary `error_kind` scalar — never the path
                // or the error body (security.md §2).
                tracing::warn!(
                    account = id,
                    error_kind = write_failure_kind(&e),
                    "Kimi poller: failed to write usage data"
                );
            }
        }
        Ok(Err(PollError::RateLimited)) => {
            tracing::warn!(account = id, "Kimi poller: 429 rate limited");
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
        Ok(Err(PollError::Unauthorized)) => {
            // Expected whenever the vendor CLI has not refreshed a
            // native slot's token recently — csq does not refresh
            // native tokens (journal-0135 design lock). Also fires if
            // the 3P API key was rotated out-of-band.
            tracing::warn!(account = id, "Kimi poller: 401/403 unauthorized");
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
        Ok(Err(PollError::Transport(_))) => {
            debug!(account = id, "Kimi poller: transport error");
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
        Ok(Err(PollError::BadUrl(_))) => {
            // Operator misconfiguration, not a network failure: the slot's
            // own base override (`KIMI_CODE_BASE_URL` or the slot's
            // `ANTHROPIC_BASE_URL`) was rejected by the outbound character
            // guard. Reachable precisely because this poller honours a
            // per-slot base — WARN so it is visible by default, distinct
            // from the `debug!` transport arm above, and never echoing the
            // rejected URL (it is operator-supplied; `security.md` §2).
            tracing::warn!(
                account = id,
                error_kind = "kimi_poll_bad_url",
                "Kimi poller: outbound url rejected — check the slot's base URL setting"
            );
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
        Ok(Err(PollError::Parse(msg))) => {
            // Finding D: distinguish "body was not JSON" from "valid JSON,
            // no recognised window" (API contract drift) without a new
            // shared PollError variant and without logging the raw
            // message (may echo body fragments — security.md §2).
            if msg == NO_RECOGNISED_WINDOW_MSG {
                tracing::warn!(
                    account = id,
                    "Kimi poller: usages response had no recognised 5h/7d window — possible API contract drift"
                );
            } else {
                tracing::warn!(
                    account = id,
                    "Kimi poller: usages response body was not valid JSON"
                );
            }
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
        Ok(Err(PollError::HttpError(status))) => {
            tracing::warn!(account = id, status, "Kimi poller: usages HTTP error");
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
        Err(join_err) => {
            tracing::warn!(
                account = id,
                panicked = join_err.is_panic(),
                "Kimi poller: poll task did not complete"
            );
            crate::daemon::usage_poller::set_cooldown(cooldowns, id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Verbatim live capture from 2026-07-29, slot 13's `sk-kimi-`
    /// Bearer, HTTP 200. userId and the parallel.details UUID are
    /// redacted; quota numerics are the real returned values.
    const FIXTURE: &str = r#"{
        "user": {
            "userId": "d9de795qip65adaj77eg",
            "region": "REGION_OVERSEA",
            "membership": { "level": "LEVEL_STANDARD" },
            "businessId": ""
        },
        "usage": {
            "limit": "100",
            "used": "57",
            "remaining": "43",
            "resetTime": "2026-08-04T00:52:39.841665Z"
        },
        "limits": [
            {
                "window": { "duration": 300, "timeUnit": "TIME_UNIT_MINUTE" },
                "detail": {
                    "limit": "100",
                    "used": "34",
                    "remaining": "66",
                    "resetTime": "2026-07-29T01:52:39.841665Z"
                }
            }
        ],
        "parallel": {
            "limit": "30",
            "details": ["d5ceab9a-6a94-45d9-9431-c6009f6d23d8"]
        },
        "totalQuota": {},
        "authentication": { "method": "METHOD_API_KEY", "scope": "FEATURE_CODING" },
        "subType": "TYPE_PURCHASE",
        "domain": "DOMAIN_NEXUS"
    }"#;

    fn mock_get(status: u16, body: &'static str) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((status, body.as_bytes().to_vec()))
        })
    }

    #[test]
    fn parses_verbatim_live_fixture() {
        let u = parse_kimi_usages(FIXTURE.as_bytes()).expect("fixture must parse");

        let fh = u.five_hour.expect("5h window present");
        assert!((fh.used_percentage - 34.0).abs() < 1e-9);
        // 2026-07-29T01:52:39Z (microseconds stripped by the parser)
        assert_eq!(fh.resets_at, 1785289959);

        let sd = u.seven_day.expect("7d window present");
        assert!((sd.used_percentage - 57.0).abs() < 1e-9);
        // 2026-08-04T00:52:39Z
        assert_eq!(sd.resets_at, 1785804759);

        assert_eq!(u.membership_level.as_deref(), Some("LEVEL_STANDARD"));
        assert_eq!(u.auth_method.as_deref(), Some("METHOD_API_KEY"));
    }

    /// The shape the LIVE endpoint returns as of 2026-08-05, captured from a
    /// real slot credential: BOTH window sources now carry
    /// `{limit, remaining, resetTime}` and NO `used`.
    ///
    /// Before the fallback, `used` was required, so both windows returned
    /// `None`, `is_empty()` was true, and every poll was discarded as
    /// `NO_RECOGNISED_WINDOW_MSG` — freezing `updated_at` while the
    /// credential was healthy. The slot rendered `api-key — not
    /// quota-polled` with an ever-growing "stale Nd".
    ///
    /// Non-vacuity: drop the `remaining` fallback in `window_from_detail`
    /// and this test fails at the first `expect`.
    #[test]
    fn used_is_derived_from_remaining_when_the_vendor_omits_it() {
        // 5h: limit 100, remaining 66 → used 34. 7d: limit 100, remaining 43 → 57.
        // Same figures as the verbatim fixture above, expressed the new way, so
        // the two tests pin identical output across the contract change.
        let body = r#"{
            "usage": {"limit":"100","remaining":"43","resetTime":"2099-01-01T00:00:00Z"},
            "limits": [{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},
                        "detail":{"limit":"100","remaining":"66","resetTime":"2099-01-01T00:00:00Z"}}]
        }"#;
        let u = parse_kimi_usages(body.as_bytes()).expect("must parse without `used`");
        let fh = u
            .five_hour
            .expect("5h window must survive the missing `used`");
        assert!((fh.used_percentage - 34.0).abs() < 1e-9, "got {fh:?}");
        let sd = u
            .seven_day
            .expect("7d window must survive the missing `used`");
        assert!((sd.used_percentage - 57.0).abs() < 1e-9, "got {sd:?}");
    }

    #[test]
    fn explicit_used_still_wins_over_the_remaining_fallback() {
        // The fallback must not shadow a vendor-supplied `used`. If both are
        // present and disagree, `used` is authoritative — it is the field the
        // API documents as the measurement; `remaining` is the derived one.
        let body = r#"{"usage":{"limit":"100","used":"42","remaining":"1",
                                "resetTime":"2099-01-01T00:00:00Z"}}"#;
        let sd = parse_kimi_usages(body.as_bytes())
            .unwrap()
            .seven_day
            .unwrap();
        assert!(
            (sd.used_percentage - 42.0).abs() < 1e-9,
            "explicit `used` must win, not limit-remaining (=99): {sd:?}"
        );
    }

    #[test]
    fn remaining_greater_than_limit_clamps_to_zero_not_negative() {
        // A `remaining > limit` response (vendor rounding, or a quota raise
        // mid-window) would derive a NEGATIVE used, which the `used < 0.0`
        // guard would reject outright — silently dropping the whole poll and
        // re-freezing the row. Clamp instead: 0% used is the truthful reading.
        let body = r#"{"usage":{"limit":"100","remaining":"120",
                                "resetTime":"2099-01-01T00:00:00Z"}}"#;
        let sd = parse_kimi_usages(body.as_bytes())
            .expect("must still parse")
            .seven_day
            .expect("window must survive remaining > limit");
        assert_eq!(sd.used_percentage, 0.0);
    }

    #[test]
    fn neither_used_nor_remaining_is_still_unparseable() {
        // The fallback must not turn a genuinely window-less payload into a
        // fabricated 0%. With neither field there is no measurement, and the
        // parser must still say so.
        let body = r#"{"usage":{"limit":"100","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let err = parse_kimi_usages(body.as_bytes()).expect_err("must not fabricate a window");
        match err {
            PollError::Parse(m) => assert_eq!(m, NO_RECOGNISED_WINDOW_MSG),
            other => panic!("expected the no-window parse error, got {other:?}"),
        }
    }

    #[test]
    fn string_encoded_numerics_parse() {
        // The live API returns numbers as strings; ensure the parser
        // does not silently drop them.
        let body = r#"{"usage":{"limit":"100","used":"42","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        let sd = u.seven_day.unwrap();
        assert!((sd.used_percentage - 42.0).abs() < 1e-9);
        assert_eq!(sd.resets_at, 4070908800); // 2099-01-01T00:00:00Z — far-future, never expires mid-test
    }

    #[test]
    fn numeric_fields_also_parse() {
        // Forward compatibility: if the API ever emits real JSON numbers
        // instead of strings, the parser still works.
        let body = r#"{"usage":{"limit":100,"used":25,"resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!((u.seven_day.unwrap().used_percentage - 25.0).abs() < 1e-9);
    }

    /// NIT-1 (redteam): `window_from_detail` computes `pct = (used /
    /// limit) * 100.0`, but every value-asserting fixture in this file
    /// uses `limit: 100` — under which `used / 100 * 100.0 == used`, so
    /// a mutation that swapped the formula for a bare `pct = used`
    /// would pass every existing test. A `limit != 100` fixture is the
    /// only one that actually exercises the division.
    #[test]
    fn limit_other_than_100_computes_a_real_ratio() {
        let body = r#"{"usage":{"limit":"200","used":"50","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!(
            (u.seven_day.unwrap().used_percentage - 25.0).abs() < 1e-9,
            "50/200 * 100 = 25%, not 50% (which is what a bare `pct = used` mutation would yield)"
        );
    }

    #[test]
    fn absent_5h_window_stays_absent() {
        let body = r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!(u.five_hour.is_none(), "5h must stay absent, never 0%");
        assert!(u.seven_day.is_some());
    }

    #[test]
    fn absent_7d_window_stays_absent() {
        let body = r#"{"limits":[{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":"100","used":"34","resetTime":"2099-01-01T00:00:00Z"}}]}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!(u.five_hour.is_some());
        assert!(u.seven_day.is_none(), "7d must stay absent, never 0%");
    }

    #[test]
    fn unrecognised_limits_entry_is_skipped_not_misparsed() {
        // A 60-minute entry must NOT be misclassified as the 5h window.
        let body = r#"{
            "usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"},
            "limits":[
                {"window":{"duration":60,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":"100","used":"5","resetTime":"2099-01-01T00:00:00Z"}}
            ]
        }"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!(u.five_hour.is_none(), "60-min entry must not become 5h");
        assert!(u.seven_day.is_some());
    }

    #[test]
    fn empty_payload_is_a_parse_error() {
        let result = parse_kimi_usages(br#"{"user":{"userId":"x"}}"#);
        assert!(matches!(result, Err(PollError::Parse(_))));
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let result = parse_kimi_usages(b"not json");
        assert!(matches!(result, Err(PollError::Parse(_))));
    }

    /// Finding D (redteam): "malformed JSON body" and "valid JSON, no
    /// recognised window" are DISTINCT failure classes that both surface
    /// as `PollError::Parse`. `handle_poll_result` tells them apart by
    /// comparing the message against [`NO_RECOGNISED_WINDOW_MSG`] — pin
    /// that the two inputs actually produce different message content,
    /// so that comparison stays meaningful (and doesn't silently degrade
    /// to always-the-same-branch if a future edit changes either
    /// message).
    #[test]
    fn parse_error_and_empty_window_error_are_distinguishable() {
        let malformed = match parse_kimi_usages(b"not json") {
            Err(PollError::Parse(msg)) => msg,
            other => panic!("expected Parse, got {other:?}"),
        };
        let no_window = match parse_kimi_usages(br#"{"user":{"userId":"x"}}"#) {
            Err(PollError::Parse(msg)) => msg,
            other => panic!("expected Parse, got {other:?}"),
        };
        assert_ne!(
            malformed, no_window,
            "malformed-JSON and no-recognised-window messages must differ"
        );
        assert_eq!(no_window, NO_RECOGNISED_WINDOW_MSG);
        assert_ne!(malformed, NO_RECOGNISED_WINDOW_MSG);
    }

    #[test]
    fn zero_limit_is_rejected_to_guard_division() {
        let body = r#"{"usage":{"limit":"0","used":"0","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let result = parse_kimi_usages(body.as_bytes());
        assert!(matches!(result, Err(PollError::Parse(_))));
    }

    /// Finding B (redteam): `limit == 0` is fully subsumed by the
    /// finiteness guard (0.0/0.0 = NaN), so `zero_limit_is_rejected...`
    /// above passes identically with or without the `|| limit <= 0.0`
    /// clause — it does NOT prove that clause does anything. A NEGATIVE
    /// limit is the clause's only unique effect.
    ///
    /// `used: "0"` (not e.g. "50") is deliberate: it isolates this
    /// clause from the `pct < 0.0` check added for Finding A. limit=-100,
    /// used=50 → pct=-50.0 would ALSO be caught by that guard, making
    /// this test vacuous w.r.t. `limit <= 0.0` once both guards coexist.
    /// limit=-100, used=0 → pct = 0.0/-100.0*100.0 = -0.0, and IEEE-754
    /// `-0.0 < 0.0` is FALSE (-0.0 == 0.0) — so only `limit <= 0.0`
    /// rejects this input.
    ///
    /// Non-vacuity proof (redteam requirement): with `|| limit <= 0.0`
    /// deleted from `window_from_detail`, this test FAILS (`cargo test
    /// -p csq-core --lib daemon::usage_poller::kimi::tests::negative_limit_is_rejected_to_guard_division`
    /// — verified locally, restored, confirmed identical via `cmp`).
    #[test]
    fn negative_limit_is_rejected_to_guard_division() {
        let body = r#"{"usage":{"limit":"-100","used":"0","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let result = parse_kimi_usages(body.as_bytes());
        assert!(matches!(result, Err(PollError::Parse(_))));
    }

    /// Finding A (redteam): a vendor-side negative `used` (e.g. an
    /// upstream bug emitting `"used": "-5"`) must not compute a negative
    /// percentage. Rejected via the `used < 0.0` INPUT guard (R13
    /// correction — see `window_from_detail`'s doc comment for why this
    /// is NOT redundant with the `pct < 0.0` computed-ratio guard: the
    /// two diverge at the subnormal-underflow boundary, pinned by
    /// `used_underflows_to_negative_zero_is_still_rejected` below).
    /// Non-vacuity, by CONTRAST with that boundary test: deleting ONLY
    /// the `used < 0.0` clause from the input guard leaves THIS test
    /// passing (`pct < 0.0` still catches a non-boundary `-5`) — it is
    /// the boundary test below, not this one, that distinguishes the
    /// two guards; the pair together prove they are genuinely separate
    /// checks, not the same one exercised twice. Tests
    /// `window_from_detail` directly — a full `parse_kimi_usages` round
    /// trip with only ONE window present would collapse into the
    /// unrelated `is_empty()` → `Err(Parse)` branch (both windows
    /// absent), masking what this guard rejects.
    #[test]
    fn negative_used_is_rejected() {
        let detail = serde_json::json!({
            "limit": "100",
            "used": "-5",
            "resetTime": "2099-01-01T00:00:00Z"
        });
        assert!(
            window_from_detail(&detail).is_none(),
            "negative used must not become a negative usage bar"
        );
    }

    /// R13 correction (redteam retraction): `used = -5e-324` (the
    /// smallest-magnitude negative f64 subnormal) divided by
    /// `limit = 100.0` underflows to `-0.0` — `pct < 0.0` is FALSE for
    /// `-0.0` (IEEE-754 `-0.0 == 0.0`), so the `pct < 0.0` guard alone
    /// does NOT reject this input; only the `used < 0.0` input-level
    /// guard does. This is the counterexample to the retracted "`used
    /// < 0` and `pct < 0` are the SAME condition" claim that used to
    /// live in `window_from_detail`'s doc comment — verified
    /// numerically before the fix (Python/Rust share IEEE-754 f64):
    /// `pct < 0.0` → `false`, `used < 0.0` → `true` for this exact input.
    ///
    /// Non-vacuity, by CONTRAST with `negative_used_is_rejected`:
    /// removing ONLY the `used < 0.0` clause from `window_from_detail`'s
    /// input guard makes THIS test FAIL (`window_from_detail` returns
    /// `Some(..)` instead of `None` — the `-0.0` percentage would even
    /// get silently normalized to `+0.0` by the NIT-1 fix, i.e. a
    /// genuinely negative input rendering as a legitimate 0%) while
    /// `negative_used_is_rejected` (the non-boundary `"-5"` case) still
    /// PASSES unaffected — proving the two tests exercise genuinely
    /// different guard behavior, not the same guard twice. Verified
    /// locally, restored, confirmed identical via `cmp`.
    #[test]
    fn used_underflows_to_negative_zero_is_still_rejected() {
        let detail = serde_json::json!({
            "limit": "100",
            "used": "-5e-324",
            "resetTime": "2099-01-01T00:00:00Z"
        });
        assert!(
            window_from_detail(&detail).is_none(),
            "a genuinely negative `used` that underflows to -0.0 on \
             division must still be rejected, not silently accepted as 0%"
        );
    }

    /// NIT-1 (redteam): `"used": "-0"` computes `pct = -0.0`, which is
    /// finite and NOT `< 0.0` (IEEE-754 `-0.0 == 0.0`), so it survives
    /// both existing guards and would render as a `-0%` usage bar
    /// without normalization. `assert_eq!(.., 0.0)` alone would NOT
    /// catch a regression here (`-0.0 == 0.0` is true) — the
    /// `is_sign_positive()` check is load-bearing.
    ///
    /// Non-vacuity proof: with the `let pct = if pct == 0.0 { 0.0 }
    /// else { pct };` normalization line deleted from
    /// `window_from_detail`, this test FAILS (`used_percentage` is
    /// `-0.0`, `is_sign_positive()` returns `false`) — verified locally,
    /// restored, confirmed identical via `cmp`.
    #[test]
    fn negative_zero_used_normalizes_to_positive_zero() {
        let detail = serde_json::json!({
            "limit": "100",
            "used": "-0",
            "resetTime": "2099-01-01T00:00:00Z"
        });
        let window = window_from_detail(&detail).expect("-0 used is a legitimate 0%, not rejected");
        assert!(
            window.used_percentage.is_sign_positive(),
            "used_percentage must normalize to +0.0, not -0.0 \
             (is_sign_positive distinguishes them; == does not)"
        );
        assert_eq!(window.used_percentage, 0.0);
    }

    #[test]
    fn http_401_and_403_are_unauthorized() {
        for status in [401u16, 403] {
            let http = mock_get(status, r#"{"error":"denied"}"#);
            let result = poll_kimi_usages("tok", &http, "https://api.kimi.com/coding/v1/usages");
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
            poll_kimi_usages("tok", &http, "https://api.kimi.com/coding/v1/usages"),
            Err(PollError::RateLimited)
        ));
    }

    #[test]
    fn transport_error_propagates() {
        let http: HttpGetFn = Arc::new(|_u, _t, _h| Err("connection refused".to_string()));
        assert!(matches!(
            poll_kimi_usages("tok", &http, "https://api.kimi.com/coding/v1/usages"),
            Err(PollError::Transport(_))
        ));
    }

    #[test]
    fn write_round_trips_both_windows() {
        let dir = tempfile::TempDir::new().unwrap();
        // Use far-future reset times so the windows do not expire between
        // write and read — `load_state` calls `clear_expired` and would
        // strip a window whose resetTime is in the past (e.g. the
        // verbatim fixture's 2026-07-29 5h reset).
        let body = r#"{
            "usage":  { "limit": "100", "used": "57", "remaining": "43",
                        "resetTime": "2099-01-08T00:00:00Z" },
            "limits": [
                { "window": { "duration": 300, "timeUnit": "TIME_UNIT_MINUTE" },
                  "detail": { "limit": "100", "used": "34", "remaining": "66",
                              "resetTime": "2099-01-01T05:00:00Z" } }
            ],
            "user": { "membership": { "level": "LEVEL_STANDARD" } },
            "authentication": { "method": "METHOD_API_KEY" }
        }"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        write_kimi_usages(dir.path(), 13, "kimi", &u).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(13).expect("slot 13 row");
        assert_eq!(row.surface, "kimi");
        assert_eq!(row.kind, "utilization");

        let fh = row.five_hour.as_ref().expect("5h written");
        assert!((fh.used_percentage - 34.0).abs() < 1e-9);

        let sd = row.seven_day.as_ref().expect("7d written");
        assert!((sd.used_percentage - 57.0).abs() < 1e-9);

        let extras = row.extras.as_ref().expect("extras present");
        assert_eq!(extras["membership_level"], "LEVEL_STANDARD");
        assert_eq!(extras["authentication_method"], "METHOD_API_KEY");
    }

    /// MED-1 (an internal ticket redteam): a schema-drifted `quota.json` must NOT
    /// be clobbered by this write leg. Before the fix,
    /// `load_state_or_warn`'s `QuotaFile::empty()` fallback let this
    /// write persist a one-row file, wiping every sibling account's row.
    #[test]
    fn write_kimi_usages_skips_on_poisoned_file_preserving_siblings() {
        let dir = tempfile::TempDir::new().unwrap();
        let poisoned = r#"{
            "schema_version": 99,
            "accounts": {
                "1": {"five_hour": {"used_percentage": 50.0, "resets_at": 4102444800}, "updated_at": 1.0},
                "2": {"five_hour": {"used_percentage": 80.0, "resets_at": 4102444800}, "updated_at": 1.0}
            }
        }"#;
        std::fs::write(quota_state::quota_path(dir.path()), poisoned).unwrap();

        let body = r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        let result = write_kimi_usages(dir.path(), 3, "kimi", &u);
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

    #[test]
    fn write_never_fabricates_zero_when_window_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        // Far-future resetTime so the written 7d window survives the
        // read path's `clear_expired` sweep.
        let body = r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        write_kimi_usages(dir.path(), 13, "kimi", &u).unwrap();

        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(13).unwrap();
        assert!(
            row.five_hour.is_none(),
            "absent 5h must NOT become 0% in the row"
        );
        assert!(row.seven_day.is_some());
    }

    /// Finding E (redteam): `write_kimi_usages` must not block forever
    /// behind an unbounded `flock(LOCK_EX)` — a concurrent `csq
    /// logout`/`csq move-slot` holding the same `quota.json.lock` must
    /// not stall the poller forever. Holds the lock on the SAME path
    /// from a second, independently-opened file descriptor (matching
    /// `platform::lock`'s own documented per-fd `flock` semantics) for
    /// LONGER than the bounded retry window
    /// (`LOCK_RETRY_ATTEMPTS * LOCK_RETRY_DELAY` ≈ 1s) and asserts the
    /// write returns within a generous wall-clock budget instead of
    /// hanging, and that it fails closed (no silent partial write) while
    /// the lock is contended.
    #[test]
    fn write_lock_is_bounded_not_indefinite() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let lock_path = quota_state::quota_path(dir.path()).with_extension("lock");
        let held = crate::platform::lock::lock_file(&lock_path).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let base = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            let body =
                r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
            let u = parse_kimi_usages(body.as_bytes()).unwrap();
            let result = write_kimi_usages(&base, 13, "kimi", &u);
            let _ = tx.send(result.is_err());
        });

        let returned_err = rx.recv_timeout(std::time::Duration::from_secs(10)).expect(
            "write_kimi_usages must return within 10s while the lock is held — \
                 not hang indefinitely behind the old unbounded flock",
        );
        assert!(
            returned_err,
            "write must fail closed (LockContention) while the lock is held, not silently succeed"
        );

        drop(held);
        handle.join().unwrap();

        // Lock released — a subsequent write must succeed normally.
        let body = r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        write_kimi_usages(dir.path(), 13, "kimi", &u).unwrap();
    }

    /// LOW-1 (redteam): the write-failure `error_kind` discriminator
    /// must actually distinguish lock contention from any other write
    /// failure — pinned directly (no tracing-capture harness needed)
    /// since `handle_poll_result`'s `tracing::warn!` call reads this
    /// function's return value verbatim.
    #[test]
    fn write_failure_kind_discriminates_lock_contention() {
        let contention =
            crate::error::CsqError::Platform(crate::error::PlatformError::LockContention {
                path: std::path::PathBuf::from("/does/not/matter"),
            });
        assert_eq!(write_failure_kind(&contention), "lock_contention");

        let other =
            crate::error::CsqError::Platform(crate::error::PlatformError::Keychain("x".into()));
        assert_eq!(write_failure_kind(&other), "write_failed");
    }

    /// Finding LOW-1 (redteam): a poll that SUCCEEDS (parses fine) but
    /// whose WRITE fails due to lock contention must not be silently
    /// treated the same as a genuine poll failure — specifically it
    /// must NOT set a cooldown. The row is simply stale until the next
    /// ~15-min 3P cadence tick retries the write; suppressing the retry
    /// further via a cooldown would compound a transient lock hold into
    /// a much longer visible gap.
    #[test]
    fn write_contention_does_not_set_a_cooldown() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let lock_path = quota_state::quota_path(dir.path()).with_extension("lock");
        let held = crate::platform::lock::lock_file(&lock_path).unwrap();

        let cooldowns: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>,
        > = Default::default();

        // LOW-1 (redteam): the contended write MUST run on a thread
        // other than the one holding `held`. Windows named mutexes are
        // re-entrant WITHIN a single thread (`platform/lock.rs`'s
        // documented semantics) — calling `handle_poll_result` on the
        // SAME thread that holds `held` would silently SUCCEED on
        // Windows (no real contention) instead of genuinely contending,
        // so the "no cooldown" assertion below would pass for the wrong
        // reason (a successful write, not a correctly-skipped cooldown
        // on a FAILED write). Matches the cross-thread contention shape
        // `write_lock_is_bounded_not_indefinite` above already uses.
        let base = dir.path().to_path_buf();
        let cooldowns_thread = std::sync::Arc::clone(&cooldowns);
        let handle = std::thread::spawn(move || {
            let body =
                r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
            let usages = parse_kimi_usages(body.as_bytes()).unwrap();
            handle_poll_result(&base, 13, "kimi", Ok(Ok(usages)), &cooldowns_thread);
        });
        handle.join().unwrap();

        assert!(
            !cooldowns.lock().unwrap().contains_key(&13),
            "a lock-contention write failure must not set a cooldown — \
             the poll itself succeeded; only the write was contended"
        );

        drop(held);
    }

    /// MED-1 (redteam): `handle_poll_result`'s write leg must run on
    /// tokio's blocking-thread pool, not bare on an async runtime
    /// worker — a contended `quota.json` lock would otherwise park a
    /// limited worker thread for up to `LOCK_RETRY_ATTEMPTS *
    /// LOCK_RETRY_DELAY` (~1s), starving every other tick on the
    /// daemon's `worker_threads(2)` runtime.
    ///
    /// Proof shape: a CURRENT-THREAD runtime has exactly ONE async
    /// worker (the extreme case of the "few workers" hazard) plus its
    /// OWN separate blocking-thread pool. The quota lock is held on a
    /// separate OS thread for longer than the bounded retry window, and
    /// two tasks race on that single-worker runtime: (a)
    /// `handle_poll_result_blocking`'s contended write (~1.3s), and (b)
    /// a trivial 20ms timer. This is an ORDERING proof, not an
    /// elapsed-time proof: both tasks are joined and their completion
    /// order is recorded on a channel.
    ///
    /// If the write leg still ran bare on the async task (the pre-fix
    /// shape), its `poll()` would never yield until the ~1.3s of real
    /// `std::thread::sleep` calls finished — the SOLE worker thread has
    /// no other thread to hand the timer task to, so the timer cannot
    /// even begin counting until the write task's poll returns. Order
    /// would be `["write", "timer"]`. With the fix
    /// (`tokio::task::spawn_blocking`), the write task yields at a real
    /// await point immediately after handing the blocking work to the
    /// separate pool, so the 20ms timer reliably completes first:
    /// `["timer", "write"]`.
    ///
    /// Non-vacuity: replacing `handle_poll_result_blocking`'s
    /// `tokio::task::spawn_blocking(move || { ... }).await` body with a
    /// bare `handle_poll_result(&base_dir, id, surface, result,
    /// &cooldowns);` call makes this test FAIL (order flips to
    /// `["write", "timer"]`) — verified locally, restored, confirmed
    /// identical via `cmp`.
    #[test]
    fn write_leg_does_not_block_the_async_worker() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let lock_path = quota_state::quota_path(dir.path()).with_extension("lock");

        // Hold the lock comfortably longer than the bounded retry
        // budget so the write leg is contended for its full window.
        let hold_ms = u64::from(LOCK_RETRY_ATTEMPTS) * (LOCK_RETRY_DELAY.as_millis() as u64) + 300;

        // LOW-2 (redteam): acquire AND drop the guard on the SAME
        // thread. Moving an acquired `FileLockGuard` across threads (the
        // prior shape: acquire on the test thread, `drop` inside
        // `releaser`) violates Windows mutex ownership — `ReleaseMutex`
        // requires the CALLING thread to be the one that acquired the
        // mutex (`platform/lock.rs`'s Windows `Drop` impl calls
        // `ReleaseMutex` unconditionally, discarding the return value,
        // so an ownership mismatch fails silently rather than panicking
        // — but the mutex stays owned by the wrong thread). A readiness
        // channel replaces the guard hand-off: the releaser thread
        // acquires the lock itself, signals readiness, then sleeps and
        // drops it — acquire and drop never leave that one thread.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let releaser = std::thread::spawn(move || {
            let held = crate::platform::lock::lock_file(&lock_path).unwrap();
            let _ = ready_tx.send(());
            std::thread::sleep(std::time::Duration::from_millis(hold_ms));
            drop(held);
        });
        ready_rx
            .recv()
            .expect("releaser thread must signal lock acquisition before the write races it");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let body = r#"{"usage":{"limit":"100","used":"57","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let usages = parse_kimi_usages(body.as_bytes()).unwrap();
        let cooldowns: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<u16, std::time::Instant>>,
        > = Default::default();
        let base = dir.path().to_path_buf();

        let (tx, rx) = std::sync::mpsc::channel::<&'static str>();

        rt.block_on(async move {
            let tx_write = tx.clone();
            let write_task = tokio::spawn(async move {
                handle_poll_result_blocking(base, 13, "kimi", Ok(Ok(usages)), cooldowns).await;
                let _ = tx_write.send("write");
            });

            let tx_timer = tx.clone();
            let timer_task = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let _ = tx_timer.send("timer");
            });

            let _ = tokio::join!(write_task, timer_task);
        });

        let order: Vec<&str> = rx.try_iter().collect();
        assert_eq!(
            order,
            vec!["timer", "write"],
            "the 20ms timer task must complete BEFORE the ~1.3s-contended \
             write task; if it does not, the write leg is blocking the \
             sole async worker instead of running on tokio's blocking pool"
        );

        releaser.join().unwrap();
    }

    // ── URL construction ────────────────────────────────────────────

    #[test]
    fn default_usages_url() {
        // Calls the function under test (a literal-only assert would be
        // vacuous — redteam R1). Env override removed so the default
        // path is what fires.
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        assert_eq!(usages_url(), "https://api.kimi.com/coding/v1/usages");
    }

    #[test]
    fn base_url_trailing_slash_does_not_double_up() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        assert_eq!(
            usages_url_for(Some("https://api.kimi.com/coding/")),
            "https://api.kimi.com/coding/v1/usages"
        );
    }

    #[test]
    fn vendor_v1_suffix_is_stripped_before_appending() {
        // The vendor's kimiCodeBaseUrl() convention INCLUDES /v1; an
        // operator copying it must not produce .../v1/v1/usages.
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        assert_eq!(
            usages_url_for(Some("https://api.kimi.com/coding/v1")),
            "https://api.kimi.com/coding/v1/usages"
        );
        assert_eq!(
            usages_url_for(Some("https://api.kimi.com/coding/v1/")),
            "https://api.kimi.com/coding/v1/usages"
        );
    }

    #[test]
    fn slot_base_override_wins_over_env_and_default() {
        let _g = crate::platform::test_env::lock();
        std::env::set_var(BASE_ENV, "https://env-override.example.com/coding");
        assert_eq!(
            usages_url_for(Some("https://slot-relay.example.com/kimi.com.cn")),
            "https://slot-relay.example.com/kimi.com.cn/v1/usages"
        );
        // With no slot override, the env override fires.
        assert_eq!(
            usages_url_for(None),
            "https://env-override.example.com/coding/v1/usages"
        );
        std::env::remove_var(BASE_ENV);
    }

    // ── Parser robustness (redteam R1) ──────────────────────────────

    #[test]
    fn duration_as_string_still_maps_5h_window() {
        // The endpoint string-encodes every other numeric; a future
        // "300" harmonization must not silently drop the 5h window.
        let body = r#"{"limits":[{"window":{"duration":"300","timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":"100","used":"34","resetTime":"2099-01-01T00:00:00Z"}}]}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!(
            u.five_hour.is_some(),
            "string-encoded \"300\" duration must still classify as 5h"
        );
    }

    /// Finding C (redteam): serde_json stores a bare JSON number as
    /// `f64`, so `"duration": 300.0` makes `Number::as_u64()` return
    /// `None` even though it is a whole number — without the `as_f64`
    /// fallback the 5h window silently drops with no error (the 7d
    /// window still parses, so `is_empty()` stays false and the row is
    /// written missing only the 5h bar — indistinguishable from "no 5h
    /// limit configured").
    #[test]
    fn duration_as_json_float_still_maps_5h_window() {
        let body = r#"{"limits":[{"window":{"duration":300.0,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":"100","used":"34","resetTime":"2099-01-01T00:00:00Z"}}]}"#;
        let u = parse_kimi_usages(body.as_bytes()).unwrap();
        assert!(
            u.five_hour.is_some(),
            "JSON-float duration 300.0 must still classify as 5h"
        );
    }

    #[test]
    fn ratio_overflow_yields_absent_window_not_a_null_row() {
        // used=1e307, limit=1 → ratio overflows f64. The window must be
        // absent (never a non-finite percentage, which serde_json would
        // serialize as null and poison the whole quota.json on reload).
        let body = r#"{"usage":{"limit":"1","used":"1e307","resetTime":"2099-01-01T00:00:00Z"}}"#;
        let result = parse_kimi_usages(body.as_bytes());
        // Both windows absent → Parse error (no usable signal), NOT a
        // row containing null.
        assert!(matches!(result, Err(PollError::Parse(_))));
    }

    // ── Native-slot token channel (an internal ticket bug class) ────────────

    #[test]
    fn reads_token_from_the_slots_own_vendor_home() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("kimi-code.json"),
            r#"{"access_token":"slot-14-access","refresh_token":"r","token_type":"Bearer"}"#,
        )
        .unwrap();

        assert_eq!(
            read_native_access_token(dir.path(), slot),
            NativeTokenRead::Token("slot-14-access".to_string())
        );
    }

    #[test]
    fn missing_vendor_home_yields_not_found_not_unusable() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        // Never-launched: the honest, transient skip — NOT the drift case.
        assert_eq!(
            read_native_access_token(dir.path(), slot),
            NativeTokenRead::NotFound
        );
    }

    #[test]
    fn empty_access_token_is_unusable_not_not_found() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("kimi-code.json"), r#"{"access_token":""}"#).unwrap();
        assert_eq!(
            read_native_access_token(dir.path(), slot),
            NativeTokenRead::Unusable
        );
    }

    #[test]
    fn unparseable_vendor_file_is_unusable() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("kimi-code.json"), b"not json").unwrap();
        assert_eq!(
            read_native_access_token(dir.path(), slot),
            NativeTokenRead::Unusable
        );
    }

    /// R2 LOW-1: IO errors that are NOT "file absent" (EISDIR here —
    /// a `kimi-code.json/` directory, plausible vendor layout drift)
    /// must be the Unusable drift case, never the honest NotFound skip.
    #[test]
    fn cred_path_as_directory_is_unusable_not_not_found() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        // kimi-code.json as a DIRECTORY: read_to_string fails IsADirectory.
        std::fs::create_dir_all(home.join("kimi-code.json")).unwrap();
        assert_eq!(
            read_native_access_token(dir.path(), slot),
            NativeTokenRead::Unusable
        );
    }

    /// R2 LOW-1, the EACCES arm: a mode-000 cred file is present but
    /// unreadable → Unusable. Skipped where the platform ignores
    /// permission bits (root).
    #[cfg(unix)]
    #[test]
    fn unreadable_cred_file_is_unusable_not_not_found() {
        use crate::types::AccountNum;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        std::fs::create_dir_all(&home).unwrap();
        let cred = home.join("kimi-code.json");
        std::fs::write(&cred, r#"{"access_token":"x"}"#).unwrap();
        std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root ignores mode bits; only assert where they bind.
        if std::fs::read_to_string(&cred).is_err() {
            assert_eq!(
                read_native_access_token(dir.path(), slot),
                NativeTokenRead::Unusable
            );
        }
    }

    #[test]
    fn missing_access_token_key_is_unusable() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();
        let home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        std::fs::create_dir_all(&home).unwrap();
        // The layout-drift case: file parses, but the key shape is not
        // what the inference expects (camelCase here; could be nested).
        std::fs::write(home.join("kimi-code.json"), r#"{"accessToken":"x"}"#).unwrap();
        assert_eq!(
            read_native_access_token(dir.path(), slot),
            NativeTokenRead::Unusable
        );
    }

    /// Two native Kimi slots must read two DIFFERENT tokens — per-slot
    /// vendor homes are the whole point of the 0135 model, and
    /// cross-reading would be the issue-an internal ticket bug class.
    #[test]
    fn two_native_slots_read_their_own_distinct_tokens() {
        use crate::types::AccountNum;
        let dir = tempfile::TempDir::new().unwrap();
        for (n, tok) in [(14u16, "token-14"), (15u16, "token-15")] {
            let slot = AccountNum::try_from(n).unwrap();
            let home = crate::providers::native::native_home_path(
                dir.path(),
                slot,
                crate::providers::catalog::Surface::Kimi,
            )
            .join("credentials");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(
                home.join("kimi-code.json"),
                format!(r#"{{"access_token":"{tok}"}}"#),
            )
            .unwrap();
        }
        assert_eq!(
            read_native_access_token(dir.path(), AccountNum::try_from(14u16).unwrap()),
            NativeTokenRead::Token("token-14".to_string())
        );
        assert_eq!(
            read_native_access_token(dir.path(), AccountNum::try_from(15u16).unwrap()),
            NativeTokenRead::Token("token-15".to_string())
        );
    }

    // ── Tick-level integration (house standard — R3 LOW: anthropic.rs
    // and third_party.rs both pin their tick composition; kimi's dual
    // discovery + dual cooldown maps + URL strategy need the same) ────

    /// Far-future resetTimes so `load_state`'s clear_expired sweep keeps
    /// the written windows (the verbatim 2026-07-29 capture would be
    /// stripped as already-reset on read).
    const TICK_FIXTURE: &str = r#"{
        "usage":  { "limit": "100", "used": "57", "remaining": "43",
                    "resetTime": "2099-01-08T00:00:00Z" },
        "limits": [
            { "window": { "duration": 300, "timeUnit": "TIME_UNIT_MINUTE" },
              "detail": { "limit": "100", "used": "34", "remaining": "66",
                          "resetTime": "2099-01-01T05:00:00Z" } }
        ],
        "user": { "membership": { "level": "LEVEL_STANDARD" } },
        "authentication": { "method": "METHOD_API_KEY" }
    }"#;

    /// Stages a 3P Kimi slot: `config-<slot>/settings.json` whose
    /// ANTHROPIC_BASE_URL classifies as Kimi (discovery's
    /// provider_from_base_url matches "kimi.com").
    fn install_kimi_3p_slot(base: &Path, slot: u16, base_url: &str, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("settings.json"),
            format!(
                r#"{{"env":{{"ANTHROPIC_BASE_URL":"{base_url}","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
            ),
        )
        .unwrap();
    }

    /// Stages a native kimi-code slot: the binding marker
    /// (`credentials/kimi-<N>.json` — what discover_native enumerates)
    /// plus the per-slot vendor home credential file.
    fn install_kimi_native_slot(base: &Path, slot: crate::types::AccountNum, token: &str) {
        crate::providers::native::write_binding(
            base,
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .unwrap();
        let home = crate::providers::native::native_home_path(
            base,
            slot,
            crate::providers::catalog::Surface::Kimi,
        )
        .join("credentials");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("kimi-code.json"),
            format!(r#"{{"access_token":"{token}"}}"#),
        )
        .unwrap();
    }

    /// Captured (url, token) pairs from a mock HTTP layer.
    type CapturedCalls = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

    fn capturing_http(body: &'static str, status: u16) -> (HttpGetFn, CapturedCalls) {
        let calls: CapturedCalls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap = std::sync::Arc::clone(&calls);
        let http: HttpGetFn = Arc::new(move |url: &str, token: &str, _h: &[(&str, &str)]| {
            cap.lock()
                .unwrap()
                .push((url.to_string(), token.to_string()));
            Ok((status, body.as_bytes().to_vec()))
        });
        (http, calls)
    }

    // The tick tests hold `test_env::lock()` across `.await` — the lock
    // is the cross-TEST serialization primitive (it stops a sibling URL
    // test from setting KIMI_CODE_BASE_URL mid-tick), not production
    // lock discipline; the same `#[allow]` pattern as daemon/detect.rs.
    /// The per-tick fan-out is bounded by `MAX_ACCOUNTS_PER_TICK`.
    ///
    /// `MAX_ACCOUNTS` is 999, so an unbounded tick would issue up to that many
    /// vendor HTTP calls every `POLL_INTERVAL` (5 min). `anthropic.rs` has
    /// truncated its enumeration since it was written; the 3P/native pollers
    /// did not, and nothing in the tree asserted the bound for any poller.
    /// Staging one more slot than the cap is what makes this test able to fail
    /// — at exactly `MAX_ACCOUNTS_PER_TICK` slots a missing `.take` is
    /// indistinguishable from a present one.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tick_3p_fan_out_is_bounded_by_max_accounts_per_tick() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        let dir = tempfile::TempDir::new().unwrap();

        let staged = MAX_ACCOUNTS_PER_TICK + 1;
        for slot in 1..=staged {
            install_kimi_3p_slot(
                dir.path(),
                slot as u16,
                DEFAULT_BASE,
                &format!("sk-kimi-{slot}-test"),
            );
        }

        let (http, calls) = capturing_http(TICK_FIXTURE, 200);
        let cooldowns_3p =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        tick(dir.path(), &http, &cooldowns_3p, &cooldowns_native).await;

        let n = calls.lock().unwrap().len();
        assert_eq!(
            n, MAX_ACCOUNTS_PER_TICK,
            "staged {staged} kimi 3P slots; the tick must cap its vendor calls at \
             MAX_ACCOUNTS_PER_TICK ({MAX_ACCOUNTS_PER_TICK}), got {n}"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tick_3p_kimi_slot_writes_quota_with_slots_own_key_and_base() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        let dir = tempfile::TempDir::new().unwrap();
        // A kimi.com-host VARIANT: pins the slot-base preference
        // end-to-end (the slot's own configured base wins over the
        // compiled default).
        install_kimi_3p_slot(
            dir.path(),
            13,
            "https://api.kimi.com.cn/coding",
            "sk-kimi-13-test",
        );
        let (http, calls) = capturing_http(TICK_FIXTURE, 200);
        let cooldowns_3p =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        tick(dir.path(), &http, &cooldowns_3p, &cooldowns_native).await;

        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1, "exactly one poll for the one slot");
            assert_eq!(calls[0].0, "https://api.kimi.com.cn/coding/v1/usages");
            assert_eq!(calls[0].1, "sk-kimi-13-test");
        }
        let quota = quota_state::load_state(dir.path()).unwrap();
        let row = quota.get(13).expect("quota row for slot 13");
        assert_eq!(row.surface, "kimi");
        assert!((row.five_hour_pct() - 34.0).abs() < 0.01);
        assert!((row.seven_day_pct() - 57.0).abs() < 0.01);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tick_native_kimi_slot_writes_quota_from_vendor_home_token() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        let dir = tempfile::TempDir::new().unwrap();
        install_kimi_native_slot(
            dir.path(),
            crate::types::AccountNum::try_from(14u16).unwrap(),
            "native-oauth-14",
        );
        let (http, calls) = capturing_http(TICK_FIXTURE, 200);
        let cooldowns_3p =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        tick(dir.path(), &http, &cooldowns_3p, &cooldowns_native).await;

        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "https://api.kimi.com/coding/v1/usages");
            assert_eq!(calls[0].1, "native-oauth-14");
        }
        let quota = quota_state::load_state(dir.path()).unwrap();
        let row = quota.get(14).expect("quota row for slot 14");
        assert_eq!(row.surface, "kimi-cli");
        assert!((row.five_hour_pct() - 34.0).abs() < 0.01);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tick_429_enters_cooldown_and_blocks_next_poll() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        let dir = tempfile::TempDir::new().unwrap();
        install_kimi_3p_slot(
            dir.path(),
            13,
            "https://api.kimi.com/coding",
            "sk-kimi-13-test",
        );
        let (http, calls) = capturing_http("rate limited", 429);
        let cooldowns_3p =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        tick(dir.path(), &http, &cooldowns_3p, &cooldowns_native).await;
        assert!(crate::daemon::usage_poller::in_cooldown(&cooldowns_3p, 13));
        assert!(quota_state::load_state(dir.path())
            .unwrap()
            .get(13)
            .is_none());

        tick(dir.path(), &http, &cooldowns_3p, &cooldowns_native).await;
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "the cooldown blocks the second tick's poll"
        );
    }

    /// R1 sec-NIT-3 pin, SAME-ID form (R4 LOW): the independence
    /// invariant only bites at a same-id collision — a slot dual-bound
    /// to BOTH vendor homes (`credentials/kimi-<N>.json` AND
    /// `credentials/grok-<N>.json`). The login binding guard REFUSES a
    /// kimi→grok sequential bind on current installs, so the state is
    /// reachable only via legacy/pre-guard installs or manual
    /// filesystem surgery (R5 F3). With distinct ids the maps could be
    /// merged and every assertion would pass identically, so the prior
    /// version of this test could not observe a merged-map regression.
    /// Scope note (R8 NIT): this pin covers the FUNCTION-level contract
    /// only — each tick consults the map it is given. The production
    /// pairing of distinct map instances to each tick lives at the
    /// mod.rs callsite and is guarded by the field comments there,
    /// outside this test's reach (mod.rs has no test module).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tick_same_id_dual_bound_slot_maps_are_independent() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        let dir = tempfile::TempDir::new().unwrap();
        let slot = crate::types::AccountNum::try_from(17u16).unwrap();
        // Dual-bound slot 17: kimi marker + vendor home token AND grok
        // marker + vendor home token.
        install_kimi_native_slot(dir.path(), slot, "kimi-token-17");
        crate::providers::native::write_binding(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Grok,
        )
        .unwrap();
        let grok_home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Grok,
        );
        std::fs::create_dir_all(&grok_home).unwrap();
        std::fs::write(
            grok_home.join("auth.json"),
            // Grok's auth.json schema is keyed by issuer with a `key`
            // field (NOT {"access_token": ...} — that is Kimi's shape).
            r#"{"https://auth.x.ai::client-abc":{"key":"grok-token-17","auth_mode":"oidc"}}"#,
        )
        .unwrap();

        let (http, calls) = capturing_http(TICK_FIXTURE, 200);
        let cooldowns_3p =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native_kimi =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native_grok =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        // A kimi 401 cools slot 17 in KIMI's native map.
        crate::daemon::usage_poller::set_cooldown(&cooldowns_native_kimi, 17);

        // Kimi's tick skips 17 (its OWN map says cooldown)...
        tick(dir.path(), &http, &cooldowns_3p, &cooldowns_native_kimi).await;
        assert!(
            calls.lock().unwrap().is_empty(),
            "kimi's own cooldown suppresses kimi's poll of 17"
        );
        // ...but grok's tick must still poll 17 — a kimi 401 MUST NOT
        // suppress grok's poll of the same id. Under a merged map this
        // call would be suppressed and the vec would stay empty.
        crate::daemon::usage_poller::grok::tick(dir.path(), &http, &cooldowns_native_grok).await;
        {
            let calls = calls.lock().unwrap();
            assert_eq!(
                calls.len(),
                1,
                "grok must poll slot 17 despite kimi's cooldown on the same id"
            );
            assert_eq!(calls[0].1, "grok-token-17");
        }
    }

    /// Finding F (redteam): the OBSERVABLE quota.json outcome of a
    /// dual-bound slot (Kimi native marker + a DIFFERENT provider's
    /// native marker — reachable only via legacy/pre-guard installs or
    /// manual filesystem surgery, same reachability note as
    /// `tick_same_id_dual_bound_slot_maps_are_independent` above) was
    /// previously untested: that test only pinned COOLDOWN-map
    /// independence, never what ends up in `quota.json` after BOTH
    /// ticks actually run. `QuotaFile::set` (quota/mod.rs) is a full-row
    /// overwrite with no merge, so whichever tick runs LAST wins —
    /// mirrors `usage_poller::mod`'s real per-cycle ordering (grok
    /// before kimi).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tick_dual_bound_slot_last_writer_wins() {
        let _g = crate::platform::test_env::lock();
        std::env::remove_var(BASE_ENV);
        let dir = tempfile::TempDir::new().unwrap();
        let slot = crate::types::AccountNum::try_from(18u16).unwrap();
        install_kimi_native_slot(dir.path(), slot, "kimi-token-18");
        crate::providers::native::write_binding(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Grok,
        )
        .unwrap();
        let grok_home = crate::providers::native::native_home_path(
            dir.path(),
            slot,
            crate::providers::catalog::Surface::Grok,
        );
        std::fs::create_dir_all(&grok_home).unwrap();
        std::fs::write(
            grok_home.join("auth.json"),
            r#"{"https://auth.x.ai::client-abc":{"key":"grok-token-18","auth_mode":"oidc"}}"#,
        )
        .unwrap();

        // Two DIFFERENT fixtures: grok's parser recognises only its own
        // billing field names (`prepaidBalance` etc.) and would return a
        // Parse error against the Kimi-shaped `TICK_FIXTURE` — each tick
        // needs a body its own parser understands.
        let (grok_http, _grok_calls) = capturing_http(r#"{"prepaidBalance":75.0}"#, 200);
        let (kimi_http, _kimi_calls) = capturing_http(TICK_FIXTURE, 200);
        let cooldowns_3p =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native_kimi =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cooldowns_native_grok =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        // Production ordering (mod.rs): grok's tick runs BEFORE kimi's.
        crate::daemon::usage_poller::grok::tick(dir.path(), &grok_http, &cooldowns_native_grok)
            .await;
        {
            let q = quota_state::load_state(dir.path()).unwrap();
            let row = q.get(18).expect("grok wrote slot 18 first");
            assert_eq!(
                row.surface, "grok",
                "grok's row is present before kimi ticks"
            );
            assert!(
                row.balance.is_some(),
                "grok's balance is present before kimi ticks"
            );
        }

        tick(
            dir.path(),
            &kimi_http,
            &cooldowns_3p,
            &cooldowns_native_kimi,
        )
        .await;

        // Kimi's write ran last: the row is now kimi's, and grok's
        // balance/extras are gone — the observable clobber. (The
        // accompanying `tracing::warn!` naming both surfaces is not
        // captured here — this codebase has no tracing-test-capture
        // harness — but the OUTCOME the warning exists to flag is
        // pinned directly.)
        let q = quota_state::load_state(dir.path()).unwrap();
        let row = q.get(18).expect("slot 18 row must still exist");
        assert_eq!(
            row.surface, "kimi-cli",
            "kimi's write (running after grok's) clobbers the row"
        );
        assert!(
            row.balance.is_none(),
            "grok's balance must be gone — full-row overwrite, no merge"
        );
        assert!(row.five_hour.is_some(), "kimi's own 5h window is present");
    }
}
