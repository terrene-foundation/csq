pub mod claude_login_subprocess;
pub mod interactive;
pub mod race;
pub use race::RaceLoginState;

use crate::desktop::{AppState, CachedUpdateInfo};
use csq_core::accounts::discovery;
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::accounts::AccountSource;
use csq_core::capability_layer::{
    load_capability_layer_toggles, save_capability_layer_toggles, CapabilityLayerToggles,
};
use csq_core::credentials::{self, file as cred_file};
use csq_core::oauth::{exchange_code, LoginRequest, PASTE_CODE_REDIRECT_URI};
use csq_core::providers;
use csq_core::quota::state as quota_state;
use csq_core::quota::QuotaFile;
use csq_core::rotation::config as rotation_config;
use csq_core::rotation::RotationConfig;
use csq_core::sessions;
use csq_core::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_autostart::ManagerExt;

/// Per-surface map of live native (Kimi/Grok) login children, guarded by a
/// mutex. Shared type alias between `AppState.native_login_children` and
/// the desktop command helpers below that read/write it (an internal journal entry C8)
/// — keeps the nested
/// `Arc<Mutex<HashMap<Surface, Option<Arc<Mutex<Child>>>>>>` shape out of
/// every signature (clippy `type_complexity`).
///
/// A map ENTRY (regardless of its value) means "this surface is claimed
/// — refuse a second `complete_native_login` for it." The value starts
/// as a `None` **reservation** ([`reserve_native_login_slot`] inserts it
/// under the SAME lock acquisition as its presence check, closing a
/// TOCTOU where two concurrent callers for the same surface could both
/// pass the check before either registered a real child) and is
/// overwritten with `Some(child)` by [`spawn_native_device_auth_piped`]
/// once the vendor binary actually spawns.
pub type NativeLoginChildren = Arc<
    Mutex<HashMap<csq_core::providers::catalog::Surface, Option<Arc<Mutex<std::process::Child>>>>>,
>;

/// Seconds-remaining threshold below which the token badge surfaces an
/// "expiring" warning. Intentionally LOWER than the daemon's refresh
/// trigger (`csq_core::refresh::check::REFRESH_WINDOW_SECS` = 7200 / 2h):
/// the refresher tops a token up the moment it drops under 2h, so a
/// healthy slot never reaches this 1h line. Coupling the badge to the
/// 2h refresh window made the badge light up on every routine pre-refresh
/// cycle (and on synchronized slots, several at once) — crying wolf
/// instead of signaling a problem. With the 1h gap below the refresh
/// line, the badge only warns when refresh has genuinely fallen behind
/// (failed login, sustained rate-limit backoff, post-sleep catch-up
/// exceeding ~1h). Anthropic + Codex display branches both use this.
const TOKEN_WARN_SECS: u64 = 3600;

/// Public view of a single account, safe to send over IPC.
///
/// Credentials, tokens, and keys are never included.
#[derive(Serialize)]
pub struct AccountView {
    pub id: u16,
    pub label: String,
    /// "anthropic" | "codex" | "third_party" | "manual"
    pub source: String,
    /// Upstream CLI surface binding: "claude-code" | "codex".
    /// Added PR-C6 so the dashboard can badge codex-backed slots
    /// without inferring from `source` (Anthropic → claude-code,
    /// Codex → codex, ThirdParty / Manual → claude-code).
    pub surface: String,
    pub has_credentials: bool,
    pub five_hour_pct: f64,
    pub five_hour_resets_in: Option<i64>,
    pub seven_day_pct: f64,
    pub seven_day_resets_in: Option<i64>,
    pub updated_at: f64,
    /// "healthy" | "expiring" | "expired" | "missing"
    pub token_status: String,
    /// Seconds until token expires. Negative = expired N seconds ago.
    pub expires_in_secs: Option<i64>,
    /// Fixed-vocabulary tag for the most recent refresh failure,
    /// or null if the last refresh succeeded / there's no flag.
    /// Possible values: "broker_token_invalid" (needs re-login),
    /// "broker_refresh_failed" (refresh + sibling recovery both
    /// failed), "credential" / "config" / "platform" / "other".
    /// The dashboard joins this to the status to render e.g.
    /// "Expired — invalid token" so users know WHY a slot is
    /// stuck, not just that it is.
    pub last_refresh_error: Option<String>,
    /// Third-party provider id ("mm" | "zai" | "deepseek" | "ollama")
    /// for slots bound to a 3P provider, else None. Lets the
    /// frontend branch on stable ids rather than on the display
    /// label (which is localizable and could drift).
    pub provider_id: Option<String>,

    /// Billing-mode classification (Phase B of an internal journal entry). Drives
    /// the AccountList render: `subscription` shows 5h/7d quota bars,
    /// `api-key` shows "API-key billing — pay per token" with no
    /// bars, `local` shows "Local provider — no billing".
    ///
    /// Serialized as the kebab-case wire name (`subscription` /
    /// `api-key` / `local`) per `BillingMode::as_str`. Renderers MUST
    /// branch on this rather than on `provider_id` / `surface` /
    /// `source` — those are credential-origin fields, billing_mode
    /// is the user-visible-quota-shape field.
    pub billing_mode: String,
    /// Catalog-level quota signal shape: "utilization" | "counter" | "unknown".
    /// Phase B' (an internal journal entry D5): "unknown" slots render the
    /// tokens-and-cost-over-time ledger view; others keep the 5h/7d bars.
    pub quota_kind: String,
    /// True when `quota.json` holds a row for THIS slot whose `surface`
    /// matches the slot's own dispatch shape (the same predicate that
    /// gates `five_hour_pct`/`seven_day_pct` below). `false` means no
    /// row has been polled yet — the percentage fields below are `0.0`
    /// as a serialization default, NOT a measured "0% used". The
    /// frontend MUST branch on this before reading the percentage
    /// fields as real data (HIGH-1, an internal ticket redteam: a missing row
    /// rendering as a bare 0% is indistinguishable from "quota
    /// exhausted" or "genuinely unused").
    pub has_quota: bool,

    /// Formatted balance string for pay-per-token providers (e.g. DeepSeek).
    ///
    /// Populated from `quota.json::balance` when the slot's catalog
    /// `quota_kind` is `"balance"`. Rendered in the usage area instead of
    /// 5h/7d bars (which are `None` for balance-based providers).
    /// Format: `"$196.42"` for USD, `"196.42 CNY"` for other currencies.
    /// `None` for every non-balance slot (subscription, counter, unknown, gemini).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_display: Option<String>,

    // ── PR-G5 — Gemini-specific quota fields ───────────────────
    //
    // None on non-Gemini slots; populated from `quota.json` for
    // slots where `surface == "gemini"`. The frontend renders
    // counter / 429 / downgrade UI per FR-G-UI-03 only when the
    // surface chip is "gemini" — the fields are scoped to Gemini
    // by convention rather than discriminated union to keep the
    // serde shape stable across mixed-surface dashboards.
    /// Number of requests issued today on this Gemini slot, or
    /// None when no events have been drained yet (renders "quota:
    /// n/a" per FR-G-UI-03).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_counter_today: Option<u64>,
    /// ISO-8601 UTC timestamp when the active 429 retry window
    /// ends, or None when no retry is active. The frontend
    /// computes the countdown via `Date.parse(...)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_rate_limit_reset_at: Option<String>,
    /// Model the user pinned via the binding marker (`auto`,
    /// `gemini-2.5-pro`, etc). Used together with
    /// `gemini_effective_model` to render the downgrade badge
    /// when the served model differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_selected_model: Option<String>,
    /// Model Gemini actually served on the most recent response
    /// (parsed from `modelVersion`). Drives the
    /// `selected → effective` chip in the AccountCard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_effective_model: Option<String>,
}

/// Daemon status, safe to send over IPC.
#[derive(Serialize)]
pub struct DaemonStatusView {
    pub running: bool,
    pub pid: Option<u32>,
}

/// Returns the build edition this binary was compiled as: `"community"` or
/// `"enterprise"` (the compile-time `crate::BUILD_EDITION` const driven by the
/// `enterprise` Cargo feature). The header renders an edition badge from it.
/// Unspoofable (compiled in), and distinct from the runtime audit dialect.
/// Infallible by construction; returns `Result` only to satisfy the uniform
/// Tauri-command contract (`rules/tauri-commands.md` MUST Rule 1).
#[tauri::command]
pub fn get_build_edition() -> Result<&'static str, String> {
    Ok(crate::BUILD_EDITION)
}

/// Returns all configured accounts with current quota data.
///
/// `base_dir` is the Claude accounts directory (e.g. `~/.claude/accounts`).
/// Returns a validation error if the directory does not exist.
#[tauri::command]
pub fn get_accounts(base_dir: String) -> Result<Vec<AccountView>, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let accounts = discovery::discover_all(&base);
    // an internal ticket: salvage per-row — read-only IPC query, never writes back.
    let quota: QuotaFile = quota_state::load_state_salvage(&base);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Sibling-quota fallback map: email → quota of the first slot
    // for that email that has any usage data. When a freshly-added
    // duplicate-email slot has no quota entry yet (the daemon
    // polls every 5 minutes), the dashboard borrows its sibling's
    // numbers so the user sees the correct total immediately
    // instead of "0%" for up to 5 minutes. Both slots share the
    // same Anthropic backend account, so the numbers are identical
    // by construction.
    let mut sibling_quota: std::collections::HashMap<String, &csq_core::quota::AccountQuota> =
        std::collections::HashMap::new();
    for a in &accounts {
        if matches!(a.source, AccountSource::Anthropic) && !a.label.is_empty() {
            if let Some(q) = quota.get(a.id) {
                if q.five_hour.is_some() || q.seven_day.is_some() {
                    sibling_quota.entry(a.label.clone()).or_insert(q);
                }
            }
        }
    }

    let views = accounts
        .into_iter()
        .map(|a| {
            let own = quota.get(a.id);
            let q = match own {
                Some(q) if q.five_hour.is_some() || q.seven_day.is_some() => Some(q),
                _ if matches!(a.source, AccountSource::Anthropic) && !a.label.is_empty() => {
                    sibling_quota.get(a.label.as_str()).copied().or(own)
                }
                _ => own,
            };

            // Token health depends on account type:
            // - Anthropic accounts: check OAuth credential expiry
            // - 3P accounts (MiniMax, Z.AI): API-key based, no expiry
            let is_third_party = matches!(a.source, AccountSource::ThirdParty { .. });
            let (token_status, expires_in_secs, last_refresh_error) = if is_third_party {
                // 3P accounts use API keys, not OAuth tokens.
                // They're "healthy" if they have a key configured.
                let status = if a.has_credentials {
                    "healthy"
                } else {
                    "missing"
                };
                (status.to_string(), None, None)
            } else if matches!(a.source, AccountSource::Gemini) {
                // Gemini slots authenticate via API key (AI Studio), Service
                // Account (Vertex), or OAuth (Code Assist). None of those map
                // to a single JWT `exp` value the badge can count down — API
                // keys and SAs don't expire on a daemon-managed schedule, and
                // the Code Assist OAuth token is refreshed transparently by
                // the gemini OAuth path. Treat the badge like the third-party
                // branch: `healthy` when credentials are present, `missing`
                // otherwise, no countdown. Sibling of the Codex branch closing
                // the same `account-terminal-separation.md` MUST Rule 4 bug
                // class one surface over (an internal journal entry follow-up).
                let status = if a.has_credentials {
                    "healthy"
                } else {
                    "missing"
                };
                (status.to_string(), None, None)
            } else if matches!(a.source, AccountSource::Native { .. }) {
                // Native-CLI session surfaces (Kimi/Grok — Wave 3, journal
                // 0133) carry no credential of csq's own — the vendor CLI
                // (`kimi` / `grok`) self-authenticates against its own home
                // directory. `has_credentials` reflects binding-marker
                // existence (always `true` for a slot `discover_native`
                // returns), so the badge is always "healthy" with no
                // countdown — the same no-expiry shape as the
                // Gemini/ThirdParty branches above.
                let status = if a.has_credentials {
                    "healthy"
                } else {
                    "missing"
                };
                (status.to_string(), None, None)
            } else if matches!(a.source, AccountSource::Codex) {
                // Codex slots authenticate with a ChatGPT JWT, not an Anthropic
                // OAuth token — their credentials live at `credentials-codex.json`
                // (identity-keyed) or legacy `credentials/codex-<N>.json`, NEVER
                // at the Anthropic `credentials.json` the else-branch below loads.
                // Routing Codex through that branch made every Codex slot report
                // `missing` ("No token") in the desktop badge. Token validity comes
                // from the JWT `exp` claim via `http::codex::jwt_exp_secs`. Same
                // identity-store-aware bug class as discovery's codex-skip
                // (account-terminal-separation.md MUST Rule 4).
                let reason = AccountNum::try_from(a.id)
                    .ok()
                    .and_then(|num| {
                        csq_core::refresh::sentinel::read_broker_failed_reason(&base, num)
                    })
                    .filter(|s| !s.is_empty());
                let codex_path =
                    match csq_core::accounts::profiles::resolve_slot_to_uuid(&base, a.id) {
                        Some(uuid) => {
                            let p = csq_core::accounts::identity_store::credentials_codex_path_for(
                                &base, uuid,
                            );
                            if p.exists() {
                                p
                            } else {
                                base.join("credentials")
                                    .join(format!("codex-{}.json", a.id))
                            }
                        }
                        None => base
                            .join("credentials")
                            .join(format!("codex-{}.json", a.id)),
                    };
                match credentials::load(&codex_path) {
                    Ok(creds) => match creds
                        .codex()
                        .and_then(|c| csq_core::http::codex::jwt_exp_secs(&c.tokens.access_token))
                    {
                        Some(exp_secs) => {
                            let secs = exp_secs as i64 - (now_ms as i64 / 1000);
                            let status = if secs <= 0 {
                                "expired"
                            } else if secs <= TOKEN_WARN_SECS as i64 {
                                "expiring"
                            } else {
                                "healthy"
                            };
                            (status.to_string(), Some(secs), reason)
                        }
                        // Credentials present but JWT exp unreadable — the slot is
                        // usable (daemon validated on mint); show healthy without a
                        // countdown rather than a false "missing".
                        None => {
                            let status = if a.has_credentials {
                                "healthy"
                            } else {
                                "missing"
                            };
                            (status.to_string(), None, reason)
                        }
                    },
                    Err(_) => ("missing".to_string(), None, reason),
                }
            } else {
                match AccountNum::try_from(a.id) {
                    Ok(num) => {
                        // M4-4: route through identity-keyed credentials
                        // when `profiles.json::by_slot` has a UUID for
                        // this slot. Slot-id channel: IPC handler
                        // parameterized by discovery output (channel (c)
                        // — slot-lifecycle parameter). Legacy fallback
                        // for pure-legacy installs.
                        let canonical = match csq_core::accounts::profiles::resolve_slot_to_uuid(
                            &base,
                            num.get(),
                        ) {
                            Some(uuid) => csq_core::accounts::identity_store::credentials_path_for(
                                &base, uuid,
                            ),
                            None => cred_file::canonical_path(&base, num),
                        };
                        let reason =
                            csq_core::refresh::sentinel::read_broker_failed_reason(&base, num)
                                .filter(|s| !s.is_empty());
                        match credentials::load(&canonical) {
                            Ok(creds) => {
                                let exp_ms = creds.expect_anthropic().claude_ai_oauth.expires_at;
                                let secs = (exp_ms as i64 - now_ms as i64) / 1000;
                                let status = if secs <= 0 {
                                    "expired"
                                } else if creds
                                    .expect_anthropic()
                                    .claude_ai_oauth
                                    .is_expired_within(TOKEN_WARN_SECS)
                                {
                                    "expiring"
                                } else {
                                    "healthy"
                                };
                                (status.to_string(), Some(secs), reason)
                            }
                            Err(_) => ("missing".to_string(), None, reason),
                        }
                    }
                    Err(_) => ("missing".to_string(), None, None),
                }
            };

            // Resolve the stable provider id ("mm", "zai", "deepseek",
            // "ollama") for 3P slots so the frontend can branch on a value
            // the Rust catalog owns, rather than on the localisable
            // display name.
            let provider_id = if matches!(a.source, AccountSource::ThirdParty { .. }) {
                providers::PROVIDERS
                    .iter()
                    .find(|p| p.name == a.label)
                    .map(|p| p.id.to_string())
            } else {
                None
            };

            // A usage window BEATS a balance whenever the observed row
            // carries BOTH. Billing shape is per-PLAN, not per-provider:
            // a Grok slot on a weekly-credit subscription writes a real
            // `seven_day` window AND a `$0.00` on-demand balance, so any
            // display shape derived from provider IDENTITY renders
            // "Balance $0.00" over a live 7%-used window.
            //
            // The daemon already resolves this per-ROW —
            // `usage_poller::grok` sets `kind` on exactly this rule
            // (window ? "utilization" : balance ? "balance" : ...) — and
            // the CLI resolves it per-ROW too, in
            // `csq-core/src/quota/status.rs::quota_suffix` (080430f0,
            // "a usage window beats a balance — grok-17 hid its 7%
            // behind $0.00"). The desktop was the only surface still
            // keying off the catalog, so it kept rendering the defect
            // the other two had fixed. Read the row here as well.
            // Deliberately reads the RAW `q`, not the surface-matched
            // `utilization_quota` computed below. That is parity with the CLI,
            // which does not surface-gate this decision either
            // (`status.rs`'s `let q = quota.get(a.id);`). The visible
            // consequence is that `quota_kind == "utilization"` with
            // `has_quota == false` is producible — a slot whose catalog kind is
            // "balance" carrying a stale cross-surface row with a window. Both
            // render honest PENDING states ("Checking usage…" rather than
            // "Balance checking…"), so neither makes a false claim; surface-
            // gating here would BREAK the CLI parity to change one pending
            // string into another. Intentional — recorded so the next reader
            // does not "fix" it.
            let row_shows_window = q.map(|q| q.shows_window()).unwrap_or(false);

            // Phase B' (an internal journal entry D5): expose the catalog's quota_kind
            // so the frontend can branch — `Unknown` slots get the new
            // tokens-and-cost-over-time ledger view instead of stuck-at-
            // zero 5h/7d bars. Subscription slots (Utilization / Counter)
            // keep the existing bar UI unchanged.
            let quota_kind = match a.source {
                AccountSource::ThirdParty { .. } => providers::PROVIDERS
                    .iter()
                    .find(|p| p.name == a.label)
                    .map(|p| match p.quota_kind {
                        providers::catalog::QuotaKind::Utilization => "utilization",
                        providers::catalog::QuotaKind::Counter => "counter",
                        // Kimi's 3P Bearer provider is deliberately
                        // catalogued `Unknown` so `tick_3p`'s generic probe
                        // loop skips it — the dedicated
                        // `usage_poller::kimi` owns the call instead
                        // (catalog.rs's Kimi provider entry comment). That
                        // `Unknown` is a POLLING-DISPATCH flag, not a
                        // rendering flag: treating it as "no quota signal"
                        // here routed the 3P Kimi slot into the
                        // pay-per-token ledger even though the dedicated
                        // poller writes real 5h/7d utilization rows for it
                        // (HIGH-1, an internal ticket redteam).
                        providers::catalog::QuotaKind::Unknown if p.id == "kimi" => "utilization",
                        providers::catalog::QuotaKind::Unknown => "unknown",
                        providers::catalog::QuotaKind::Balance => "balance",
                    })
                    .unwrap_or("utilization")
                    .to_string(),
                AccountSource::Anthropic | AccountSource::Manual => "utilization".to_string(),
                AccountSource::Codex => match a.surface {
                    csq_core::providers::catalog::Surface::Gemini => "counter".to_string(),
                    _ => "utilization".to_string(),
                },
                // Round-7 — Gemini bindings: API-key/Vertex SA paths
                // poll a counter; Code Assist OAuth path polls a
                // utilization-shape (per spec 05 §5.8). The desktop
                // UsageBar already branches on `surface === "gemini"`,
                // so any of these labels works for a Gemini slot.
                // "counter" matches the existing API-key default.
                AccountSource::Gemini => "counter".to_string(),
                // Native Kimi session (Wave 3, journals 0133/0135) IS
                // polled by the dedicated `usage_poller::kimi` (this PR)
                // — it writes real 5h/7d utilization rows keyed by this
                // slot, so it takes the ordinary bar-rendering path like
                // any other utilization surface. Routing it through
                // "native" hid those rows behind a static
                // "Subscription · vendor-managed" string (HIGH-1, PR
                // an internal ticket redteam).
                AccountSource::Native {
                    surface: csq_core::providers::catalog::Surface::Kimi,
                } => "utilization".to_string(),
                // Every OTHER native-CLI session surface (currently just
                // Grok) is SUBSCRIPTION (vendor-managed) with no
                // csq-polled quota endpoint AND no pay-per-token cost —
                // the vendor CLI owns auth + billing. Routing it to
                // "unknown" (the pay-per-token ledger) would mislabel it
                // as "$0 (0 tokens)" with an "unrecognized model" warning
                // (0135 issue 3). The dedicated "native" kind renders a
                // clean vendor-managed subscription state instead — no
                // ledger, no stuck-at-zero bar.
                // Grok native is ALSO csq-polled now. `usage_poller::grok`
                // writes a real `kind: "balance"` row (credit balance +
                // the weekly `currentPeriod` window) keyed by this slot,
                // so it takes the balance-rendering path like any other
                // balance surface.
                //
                // This is the IDENTICAL fix the Kimi arm above documents
                // (HIGH-1, an internal ticket): routing a polled surface through
                // "native" hides its rows behind the static
                // "Subscription · vendor-managed" string. Grok was left
                // on "native" because its poller genuinely produced
                // nothing — `parse_grok_billing` read the billing fields
                // at the JSON root while the endpoint nests them under
                // `config` with `{"val": N}` wrappers, so EVERY tick died
                // as `Parse("no recognised credit field")`. With that
                // fixed in this same PR the premise of the comment below
                // no longer holds, and leaving this arm as-is would ship
                // a parser fix the operator cannot see.
                AccountSource::Native {
                    surface: csq_core::providers::catalog::Surface::Grok,
                } => "balance".to_string(),
                // Any FUTURE native-CLI surface with no csq-polled quota
                // endpoint and no pay-per-token cost. Routing such a
                // surface to "unknown" (the pay-per-token ledger) would
                // mislabel it as "$0 (0 tokens)" with an "unrecognized
                // model" warning (0135 issue 3); "native" renders a clean
                // vendor-managed state instead. Kimi and Grok have both
                // since grown real pollers and left this arm.
                AccountSource::Native { .. } => "native".to_string(),
            };

            // Row beats catalog: a surface catalogued "balance" whose
            // ACTUAL row carries a usage window renders bars, not a
            // balance. The reverse promotion is deliberately NOT done —
            // a row with neither a window nor a balance means "no data
            // yet", which is not the same claim as "pay-per-token", and
            // conflating the two is what `is_balance_only`'s doc comment
            // in status.rs warns against. This only ever DEMOTES, so a
            // freshly-bound Grok slot with no row at all keeps
            // "balance" and renders the honest "checking…" state.
            let quota_kind = if quota_kind == "balance" && row_shows_window {
                "utilization".to_string()
            } else {
                quota_kind
            };

            // Gemini surface fields — pulled directly from quota.json
            // counter/rate_limit/model fields the daemon writes (PR-G3
            // NDJSON drain). All None on non-Gemini slots so the
            // frontend's `surface === "gemini"` branch is the sole
            // gate for Gemini rendering.
            let is_gemini = matches!(a.surface, csq_core::providers::catalog::Surface::Gemini);
            let gemini_counter_today = if is_gemini {
                q.and_then(|q| q.counter.as_ref().map(|c| c.requests_today))
            } else {
                None
            };
            let gemini_rate_limit_reset_at =
                if is_gemini {
                    q.and_then(|q| {
                        q.rate_limit.as_ref().and_then(|r| {
                            if r.active {
                                r.reset_at.clone()
                            } else {
                                None
                            }
                        })
                    })
                } else {
                    None
                };
            let gemini_selected_model = if is_gemini {
                q.and_then(|q| q.selected_model.clone())
            } else {
                None
            };
            let gemini_effective_model = if is_gemini {
                q.and_then(|q| q.effective_model.clone())
            } else {
                None
            };

            // Balance display — populated for pay-per-token (DeepSeek) slots whose
            // catalog quota_kind is Balance. The formatted string is rendered in the
            // usage area instead of the 5h/7d bars (which are None for those slots).
            // None on every other slot type: subscription, counter, unknown, Gemini.
            // Uses the shared `fmt_balance` (csq-core) so currency formatting +
            // control-char sanitization have a single source of truth with the
            // statusline (an internal ticket redteam L1/M1).
            //
            // Gated on `!row_shows_window` for the same reason
            // `quota_kind` is demoted above, and it is load-bearing
            // independently: `AccountList.svelte`'s balance arm fires on
            // `quota_kind === 'balance' || account.balance_display`, so a
            // populated `balance_display` alone is enough to route a
            // window-carrying slot into the balance renderer even after
            // the `quota_kind` demotion. Both gates are required.
            //
            // NOTE the asymmetry with the demotion above, which is
            // deliberate: that one is conditioned on `quota_kind ==
            // "balance"`, this one on NOTHING but the row. This gate is
            // provider-agnostic by design — a Z.AI or MiniMax slot whose row
            // carried both a window and a balance previously reached the
            // balance renderer through `AccountList.svelte`'s
            // `|| account.balance_display` disjunct and hid its window; it
            // now renders bars. That is the correct per-PLAN outcome and
            // matches the CLI, whose `quota_suffix` is likewise unconditional
            // on provider. The class is not Grok-specific; Grok is merely the
            // first plan shape that exercised it.
            let balance_display = q
                .filter(|_| !row_shows_window)
                .and_then(|q| q.balance.as_ref())
                .map(csq_core::quota::format::fmt_balance);

            // Utilization-quota fields (5h / 7d) are gated on
            // surface-match: the quota record's `surface` field MUST
            // equal the account's surface. This is the an internal journal entry H2
            // defense, restated structurally: slot ID namespace is shared
            // across surfaces, so a Codex binding at slot 13 collides with
            // a leftover `quota.json[13]` from a prior Anthropic occupant.
            // Surface-match prevents the IPC payload from shipping the
            // wrong numbers; the AccountList.svelte surface check is
            // defense-in-depth, not the primary gate.
            //
            // Anthropic (claude-code) AND Codex both poll 5h/7d utilization
            // windows — `q.surface` distinguishes them. Gemini surface has
            // its own quota render path (counter / rate-limit / "n/a" in
            // the AccountList gemini-quota block); even when its quota
            // entry is utilization-shape, it falls through this gate
            // because the AccountList surface check renders gemini's
            // dedicated block before reaching the usage-bars.
            //
            // Origin: redteam round 1 H2 (an internal journal entry) and an internal ticket
            // (codex 5h/7d desktop UI gap).
            //
            // Kimi is a structural exception to the bare surface-match
            // above (HIGH-1, an internal ticket redteam): its native-CLI slot's OWN
            // dispatch `Surface` (`Surface::Kimi`, `.as_str() == "kimi"`)
            // never equals the row it actually writes (`"kimi-cli"` —
            // `usage_poller::kimi::write_kimi_usages` doc comment), and
            // its 3P Bearer slot's dispatch `Surface` is `ClaudeCode`
            // (`"claude-code"`, it runs through the `claude` CLI) which
            // never equals the row it writes (`"kimi"`). Neither Kimi
            // shape's account `Surface` ever equals its own quota row's
            // `surface` string, so the bare compare is correct for every
            // OTHER surface but structurally wrong for both Kimi shapes.
            let utilization_quota = q.filter(|q| match &a.source {
                AccountSource::Native {
                    surface: csq_core::providers::catalog::Surface::Kimi,
                } => q.surface == "kimi" || q.surface == "kimi-cli",
                AccountSource::ThirdParty { .. } if provider_id.as_deref() == Some("kimi") => {
                    q.surface == "kimi"
                }
                _ => q.surface.as_str() == a.surface.as_str(),
            });
            AccountView {
                id: a.id,
                label: a.label,
                source: match a.source {
                    AccountSource::Anthropic => "anthropic".into(),
                    AccountSource::Codex => "codex".into(),
                    AccountSource::Gemini => "gemini".into(),
                    AccountSource::ThirdParty { .. } => "third_party".into(),
                    AccountSource::Manual => "manual".into(),
                    // Native-CLI session surfaces (Kimi/Grok — Wave 3,
                    // an internal journal entry). The `surface` field below already
                    // carries the specific tag ("kimi"/"grok") the
                    // frontend renders on; `source` distinguishes the
                    // dispatch/credential model at the Rust layer.
                    AccountSource::Native { .. } => "native".into(),
                },
                surface: a.surface.to_string(),
                has_credentials: a.has_credentials,
                has_quota: utilization_quota.is_some(),
                five_hour_pct: utilization_quota.map(|q| q.five_hour_pct()).unwrap_or(0.0),
                five_hour_resets_in: utilization_quota.and_then(|q| {
                    q.five_hour.as_ref().map(|w| {
                        let now = now_ms / 1000;
                        w.resets_at as i64 - now as i64
                    })
                }),
                seven_day_pct: utilization_quota.map(|q| q.seven_day_pct()).unwrap_or(0.0),
                seven_day_resets_in: utilization_quota.and_then(|q| {
                    q.seven_day.as_ref().map(|w| {
                        let now = now_ms / 1000;
                        w.resets_at as i64 - now as i64
                    })
                }),
                updated_at: q.map(|q| q.updated_at).unwrap_or(0.0),
                token_status,
                expires_in_secs,
                last_refresh_error,
                provider_id,
                billing_mode: a.billing_mode.to_string(),
                quota_kind,
                balance_display,
                gemini_counter_today,
                gemini_rate_limit_reset_at,
                gemini_selected_model,
                gemini_effective_model,
            }
        })
        .collect();

    Ok(views)
}

/// Renames an account's display label in profiles.json.
///
/// # Validation (RN1-D3)
///
/// - Empty or whitespace-only labels are rejected.
/// - Labels longer than 256 characters are rejected (prevents excessively
///   long display strings in the UI).
/// - Labels containing ASCII control characters (U+0000–U+001F, U+007F)
///   are rejected (prevents terminal injection and JSON display artifacts).
#[tauri::command]
pub fn rename_account(base_dir: String, account: u16, name: String) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("name must not be empty".into());
    }
    if trimmed.len() > 256 {
        return Err(format!(
            "name exceeds 256 characters (got {})",
            trimmed.len()
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("name must not contain control characters".into());
    }
    csq_core::accounts::profiles::update_email(&base, account_num, trimmed)
        .map_err(|e| format!("rename failed: {}", e.redacted_message()))
}

/// Whether a provider CLI binary is installed (resolvable on `PATH` or a
/// standard install location).
///
/// The desktop add-account flow calls this BEFORE launching a codex/gemini
/// login so a missing CLI surfaces a friendly "install codex-cli" prompt
/// instead of a raw error mid-device-auth. Native Kimi/Grok reuse the same
/// pre-flight (`kimi` / `grok` binaries) before offering
/// [`start_native_login`] — an internal journal entry C8. `binary` MUST be one of the
/// known surface binaries; any other value returns `false` without probing
/// (a caller cannot use this to test for arbitrary binaries).
///
/// # C6 (an internal journal entry issue 1) — known-install-dir fallback
///
/// `csq_core::accounts::login::find_cli_binary` (the CC-family resolver)
/// checks `$PATH` → system-wide well-known dirs (`/opt/homebrew/bin`,
/// `/usr/local/bin`, …) → per-user `$HOME`-relative subdirs (`.local/bin`,
/// `.cargo/bin`, …) — but has NO awareness of Kimi/Grok's own self-managed
/// install dirs (`~/.kimi-code/bin`, `~/.grok/bin`). Chained with
/// [`csq_core::cli_deps::install_path::find_in_path`] (which DOES carry
/// that `known_install_dirs` fallback — spec/13 §5) so a self-managed
/// kimi/grok install that never got symlinked onto PATH is still found,
/// while codex/gemini/claude keep their existing broader dir coverage.
#[tauri::command]
pub fn provider_cli_installed(binary: String) -> bool {
    if !matches!(
        binary.as_str(),
        "codex" | "gemini" | "claude" | "kimi" | "grok"
    ) {
        return false;
    }
    csq_core::accounts::login::find_cli_binary(&binary)
        .or_else(|| csq_core::cli_deps::install_path::find_in_path(&binary))
        .is_some()
}

/// Removes an account: deletes credentials, config dir, profile entry,
/// and — for Gemini ApiKey slots — the platform-native vault entry.
///
/// Refuses if a live `claude` process is currently bound to the
/// account (returns the conflicting PIDs in the error message). Best-
/// effort daemon cache invalidation runs after a successful removal.
///
/// ## Gemini vault cleanup (D7)
///
/// A Gemini ApiKey slot stores the key only in the OS keychain — the
/// binding marker `credentials/gemini-<N>.json` carries no secret. If
/// the slot is Gemini-bound before `logout_account` runs, the vault
/// entry is deleted first so the marker is still readable for auth-mode
/// detection. After the vault delete, `unbind` removes the marker, then
/// `logout_account` handles any residual CC-style state (`config-N/`,
/// `credentials/N.json`, `profiles.json` entry).
///
/// For Gemini-only slots (no `credentials/N.json`, no `config-N/`),
/// `logout_account` returns `NotConfigured` which is treated as success
/// — the Gemini-specific state was already cleaned by the vault delete
/// and `unbind` call above. See an internal journal entry §FD #1 and an internal journal entry D7.
///
/// ## M13b FIX-6 — Gemini-specific audit ordering
///
/// For Gemini-bound slots, `delete_api_key_from_vault` + `gemini_unbind`
/// run BEFORE `logout_account`. These are destructive operations that
/// previously had no prior committed INTENT. FIX-6 emits an `AccountLogout`
/// INTENT in this handler BEFORE the vault delete. The OUTCOME is emitted
/// after the full cleanup (either from `logout_account` or from the
/// Gemini-only `NotConfigured` path). `logout_account` also emits its own
/// INTENT+OUTCOME for the CC-state cleanup it performs — these are separate
/// audit events covering separate destructive steps (vault vs credential files).
/// Both are detectable by `scan_orphan_intents` on crash-between.
#[tauri::command]
pub fn remove_account(base_dir: String, account: u16) -> Result<RemoveAccountSummary, String> {
    use csq_core::accounts::logout::{logout_account, LogoutError};
    use csq_core::audit::op_emit;
    use csq_core::audit::types::{
        AccountLogoutPayload, EventKind, EventPayload, OpOutcome, RedactedString,
    };
    use csq_core::providers::gemini::provisioning::{
        delete_api_key_from_vault, is_gemini_bound_slot, unbind as gemini_unbind,
    };

    let base = PathBuf::from(&base_dir);
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    // D7: Gemini-specific cleanup — runs BEFORE `logout_account` so the
    // binding marker is still readable when we determine the auth mode.
    // Only fires for Gemini-bound slots; ClaudeCode and Codex have no
    // vault entries.
    let gemini_bound = is_gemini_bound_slot(&base, account_num);
    let gemini_marker_removed = if gemini_bound {
        // M13b FIX-6: emit INTENT before ANY vault/marker deletion.
        // If intent-persist fails, fail closed (no vault delete runs).
        let chain_id = op_emit::load_chain_id(&base);
        let correlation_id =
            op_emit::gen_correlation_id().map_err(|e| format!("audit correlation_id: {e}"))?;
        let gemini_intent_payload = EventPayload::AccountLogout(AccountLogoutPayload {
            slot: account_num,
            orphaned_uuid: None, // unknown pre-side-effect
        });

        // FIX-1 (R4): capture the bool so downstream outcome arms are gated on
        // whether an intent was actually committed. Ok(false) = chain-broken skip
        // (degrade — no audit trail, but vault delete proceeds). Ok(true) = emitted.
        // Err = fail-closed (no vault delete runs).
        let gemini_intent_emitted = op_emit::emit_intent(
            &base,
            &chain_id,
            EventKind::AccountLogout,
            gemini_intent_payload.clone(),
            correlation_id.clone(),
        )
        .map_err(|e| {
            format!(
                "REMOVE_FAILED: audit intent could not be persisted — \
                 Gemini vault delete aborted (fail-closed): {e}"
            )
        })?;

        let vault = csq_core::platform::secret::open_default_vault().map_err(|e| {
            // Best-effort OUTCOME:Failed — vault open failed.
            // FIX-1 (R5): gate on gemini_intent_emitted. When the chain was broken
            // and the intent was skipped (Ok(false)), emitting an outcome here would
            // produce an orphan outcome with no matching intent on the chain.
            if gemini_intent_emitted {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    gemini_intent_payload.clone(),
                    correlation_id.clone(),
                    OpOutcome::Failed {
                        reason: RedactedString::from_untrusted("vault unavailable"),
                    },
                );
            }
            // R2-FIX-1: use error_kind_tag() — never embed {e} (SecretError::Io
            // Display contains host paths, leaking them into the Tauri IPC payload).
            format!("REMOVE_FAILED: vault unavailable ({})", e.error_kind_tag())
        })?;

        // Delete the vault entry (idempotent for non-ApiKey and absent slots).
        if let Err(e) = delete_api_key_from_vault(&base, account_num, vault.as_ref()) {
            // FIX-1 (R5): same gate — only emit if intent was committed.
            if gemini_intent_emitted {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    gemini_intent_payload,
                    correlation_id,
                    OpOutcome::Failed {
                        reason: RedactedString::from_untrusted("vault delete failed"),
                    },
                );
            }
            // R2-FIX-1: same — use error_kind_tag(), not {e}.
            return Err(format!(
                "REMOVE_FAILED: vault unavailable ({})",
                e.error_kind_tag()
            ));
        }
        // Remove the binding marker. `logout_account` removes `config-N/`
        // recursively but does NOT know about `credentials/gemini-N.json`.
        let _ = gemini_unbind(&base, account_num); // best-effort; not an error

        // Store for the Gemini-only OUTCOME emit below ONLY when the intent was
        // actually committed. When chain is broken (gemini_intent_emitted == false),
        // store None so all downstream outcome arms are structurally unreachable —
        // no outcome can be emitted without a matching intent on the chain.
        // For non-Gemini-only slots, `logout_account` emits its own OUTCOME.
        if gemini_intent_emitted {
            Some((chain_id, correlation_id, gemini_intent_payload))
        } else {
            None
        }
    } else {
        None
    };

    match logout_account(&base, account_num) {
        Ok(s) => {
            // Best-effort daemon cache invalidation. Mirrors `csq logout`.
            #[cfg(unix)]
            {
                let sock = csq_core::daemon::socket_path(&base);
                if sock.exists() {
                    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
                }
            }
            // logout_account emitted its own INTENT+OUTCOME. Gemini vault
            // cleanup's OUTCOME is handled by the gemini_marker_removed path
            // if the slot was also a Gemini-only slot. For mixed slots
            // (Gemini + CC state), we just emit the Gemini vault OUTCOME here.
            if let Some((chain_id, corr_id, payload)) = gemini_marker_removed {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    payload,
                    corr_id,
                    OpOutcome::Ok,
                );
            }
            Ok(RemoveAccountSummary {
                account: s.account.get(),
                canonical_removed: s.canonical_removed,
                config_dir_removed: s.config_dir_removed,
                profiles_entry_removed: s.profiles_entry_removed,
                keychain_cleared: s.keychain_cleared,
            })
        }
        // Gemini-only slots have no `credentials/N.json` or `config-N/`,
        // so `logout_account` returns `NotConfigured`. If the Gemini
        // marker was present (and has just been removed), treat this as
        // success — the Gemini-specific state was already cleaned by the
        // vault delete and `unbind` call above.
        Err(LogoutError::NotConfigured { .. }) if gemini_marker_removed.is_some() => {
            #[cfg(unix)]
            {
                let sock = csq_core::daemon::socket_path(&base);
                if sock.exists() {
                    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
                }
            }
            // M13b FIX-6: emit OUTCOME for the Gemini-only cleanup path.
            if let Some((chain_id, corr_id, payload)) = gemini_marker_removed {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    payload,
                    corr_id,
                    OpOutcome::Ok,
                );
            }
            Ok(RemoveAccountSummary {
                account,
                canonical_removed: false,
                config_dir_removed: false,
                profiles_entry_removed: false,
                // `logout_account` returned `NotConfigured` here — its keychain
                // step never ran (no handle-dir/config-N state to process for a
                // Gemini-only slot), so nothing was cleared by THIS call.
                keychain_cleared: false,
            })
        }
        // R2-FIX-2: emit OUTCOME:Failed for the committed Gemini INTENT when
        // logout_account returns InUse (pre-side-effect rejection from the CC
        // layer — the Gemini vault was already deleted, so the INTENT is live).
        // R2-FIX-3: no {e} in the returned String — InUse carries no path.
        Err(LogoutError::InUse { account: a, pids }) => {
            if let Some((chain_id, corr_id, payload)) = gemini_marker_removed {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    payload,
                    corr_id,
                    OpOutcome::Failed {
                        reason: RedactedString::from_untrusted("logout aborted: account in use"),
                    },
                );
            }
            Err(format!(
                "ACCOUNT_IN_USE: account {} is bound to live process(es) {:?} \
                 — exit those terminals first",
                a, pids
            ))
        }
        // R2-FIX-3: NotConfigured carries only the slot number — safe to format.
        Err(LogoutError::NotConfigured { account: a }) => Err(format!(
            "NOT_CONFIGURED: account {a} has no state to remove"
        )),
        // R2-FIX-2 + R2-FIX-3: emit OUTCOME:Failed for the committed Gemini
        // INTENT; use fixed-vocab error tags rather than {e} so no filesystem
        // paths from LogoutError::Io::path.display() reach the Tauri payload.
        Err(LogoutError::Io { .. }) => {
            if let Some((chain_id, corr_id, payload)) = gemini_marker_removed {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    payload,
                    corr_id,
                    OpOutcome::Failed {
                        reason: RedactedString::from_untrusted(
                            "logout_account failed after vault delete",
                        ),
                    },
                );
            }
            Err("REMOVE_FAILED: filesystem error during logout".into())
        }
        Err(LogoutError::Profiles(_)) => {
            if let Some((chain_id, corr_id, payload)) = gemini_marker_removed {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    payload,
                    corr_id,
                    OpOutcome::Failed {
                        reason: RedactedString::from_untrusted(
                            "logout_account failed after vault delete",
                        ),
                    },
                );
            }
            Err("REMOVE_FAILED: profiles.json error during logout".into())
        }
        // logout_account's OWN Gemini vault step (see its doc comment) is a
        // no-op here in practice — this handler already cleared the vault
        // and unbound the marker above, so `is_gemini_bound_slot` reads
        // `false` inside `logout_account`. This arm exists for exhaustivity
        // and to fail loudly (rather than silently) on the residual case
        // where it somehow still fires. Fixed-vocab tag only — no {e}.
        Err(LogoutError::VaultUnavailable { error_kind, .. }) => {
            if let Some((chain_id, corr_id, payload)) = gemini_marker_removed {
                let _ = op_emit::emit_outcome(
                    &base,
                    &chain_id,
                    EventKind::AccountLogout,
                    payload,
                    corr_id,
                    OpOutcome::Failed {
                        reason: RedactedString::from_untrusted(
                            "logout_account failed after vault delete",
                        ),
                    },
                );
            }
            Err(format!(
                "REMOVE_FAILED: gemini vault unavailable ({error_kind})"
            ))
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RemoveAccountSummary {
    pub account: u16,
    pub canonical_removed: bool,
    pub config_dir_removed: bool,
    pub profiles_entry_removed: bool,
    /// Mirrors `LogoutSummary::keychain_cleared` (security review 1386 M2) —
    /// no secret content, just whether a macOS keychain OAuth item clear was
    /// confirmed for at least one handle dir bound to this slot. Safe on IPC
    /// per `tauri-commands.md` MUST-3.
    pub keychain_cleared: bool,
}

/// Renames slot `from` to slot `to`. Wraps `csq_core::accounts::move_slot::move_account`.
///
/// Phase 3 (M3-6) removed the live-process refusal: handle-dir symlinks
/// retarget through `identities/<UUID>/` for `.credentials.json`, and
/// Step 5.5 of `move_account` rewrites the remaining `config-N/`-keyed
/// symlinks (markers + Codex slot-state) so live processes survive the
/// slot renumber. The pre-rename live-PID scan result is surfaced on
/// [`MoveAccountSummary::live_pids_bound`] as informational telemetry —
/// renderers SHOULD display a notice but MUST NOT treat a non-empty
/// vector as a failure mode. The `SLOT_IN_USE` error tag is retired.
///
/// Remaining refusal classes (typed-error tags returned as `Err`):
/// - `SAME_SLOT` — `from == to`
/// - `NOT_CONFIGURED` — `from` has no state to move
/// - `TARGET_EXISTS` — `to` is already configured (never silently clobber)
/// - `IO_ERROR` — filesystem operation failed mid-move
/// - `PROFILES_ERROR` — profiles.json load/save failed
/// - `MOVE_BUSY` — another `csq move` invocation holds `.move.lock`
///
/// Validates: `from` and `to` are 1-MAX_ACCOUNTS, `from != to`,
/// `from` is currently configured.
#[tauri::command]
pub fn move_account(base_dir: String, from: u16, to: u16) -> Result<MoveAccountSummary, String> {
    use csq_core::accounts::move_slot::{move_account as core_move, MoveError};

    let base = PathBuf::from(&base_dir);
    let from_num =
        AccountNum::try_from(from).map_err(|e| format!("INVALID_INPUT: from={from}: {e}"))?;
    let to_num = AccountNum::try_from(to).map_err(|e| format!("INVALID_INPUT: to={to}: {e}"))?;

    match core_move(&base, from_num, to_num) {
        Ok(s) => {
            // Best-effort daemon cache invalidation — two notifications:
            // 1. /api/invalidate-cache  — broad discovery cache clear
            // 2. /api/slot-swap         — targeted per-slot TtlCache invalidation (SEC-2.11)
            // Both route through the shared csq_core helpers so CLI and desktop
            // use the same production chokepoint.
            #[cfg(unix)]
            {
                let sock = csq_core::daemon::socket_path(&base);
                if sock.exists() {
                    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
                }
                // Shared chokepoint: `notify_slot_swap` handles absent-socket no-op
                // and CRLF validation. Do NOT inline the JSON body here.
                let _ = csq_core::daemon::notify_slot_swap(&sock, s.from.get(), s.to.get());
            }
            Ok(MoveAccountSummary {
                from: s.from.get(),
                to: s.to.get(),
                config_dir_moved: s.config_dir_moved,
                canonical_creds_moved: s
                    .canonical_creds_moved
                    .iter()
                    .map(|surface| format!("{surface:?}").to_lowercase())
                    .collect(),
                profiles_entry_moved: s.profiles_entry_moved,
                by_slot_swapped: s.by_slot_swapped,
                by_slot_identity_swapped: s.by_slot_identity_swapped,
                quota_entry_moved: s.quota_entry_moved,
                live_pids_bound: s.live_pids_bound,
            })
        }
        Err(MoveError::SameSlot) => Err("SAME_SLOT: from and to must differ".to_string()),
        Err(MoveError::NotConfigured { from }) => Err(format!(
            "NOT_CONFIGURED: slot {from} has no state to move"
        )),
        Err(MoveError::TargetExists { to }) => Err(format!(
            "TARGET_EXISTS: slot {to} is already configured — pick an unused slot or remove slot {to} first"
        )),
        // R3-SEC: `MoveError::Io` Display embeds `path.display()` and `source`
        // (which can itself carry a path on some kernels). Both are dropped here
        // — a host path in the renderer-visible Tauri error String discloses the
        // filesystem layout (operator-surface-verification.md Rule 2, same class
        // as the R2-FIX-3 redaction in `remove_account`).
        Err(MoveError::Io { .. }) => {
            Err("IO_ERROR: filesystem op failed during move".to_string())
        }
        // R3-SEC: `ConfigError::InvalidJson { path, .. }` Display embeds the
        // profiles.json path; drop it (same redaction class as the Io arm above
        // and the `remove_account` Profiles arm).
        Err(MoveError::Profiles(_)) => {
            Err("PROFILES_ERROR: profiles.json error during move".to_string())
        }
        Err(MoveError::Busy { pid }) => Err(match pid {
            Some(p) => format!(
                "MOVE_BUSY: another `csq move` is already in progress (held by pid {p}) — try again shortly"
            ),
            None => "MOVE_BUSY: another `csq move` is already in progress (or the accounts directory is read-only)".to_string(),
        }),
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MoveAccountSummary {
    pub from: u16,
    pub to: u16,
    pub config_dir_moved: bool,
    pub canonical_creds_moved: Vec<String>,
    pub profiles_entry_moved: bool,
    /// True when `profiles.json::by_slot` was swapped for both slots
    /// (Phase 2 M2-4 addition).
    pub by_slot_swapped: bool,
    /// True when `profiles.json::by_slot_identity` contained an entry for
    /// either slot at move time (F-C-1 follow-on telemetry, WBS M4 line 135).
    pub by_slot_identity_swapped: bool,
    pub quota_entry_moved: bool,
    /// PIDs of live `claude` processes that were bound to slot `from`
    /// when the move ran. Phase 3 (M3-6) removed the live-process
    /// refusal; this field is informational telemetry for the renderer.
    pub live_pids_bound: Vec<u32>,
}

// ── Phase B' billing ledger cache (an internal ticket) ────────────────────────────
//
// PERF: `aggregator::aggregate` scans CC's transcripts under
// `~/.claude/projects`. On a heavy host that is tens of GB across thousands of
// files — a ~20s read that MUST NOT run on the UI's synchronous call path.
// `BillingLedger.svelte` is mounted once per account card and `AccountList`
// re-fetches every 5s, so a naive live scan would be ~14 full scans per render
// and freeze the app.
//
// The cache below makes `get_account_usage` return in microseconds: it serves
// the last computed all-slots aggregate (stale-tolerant) and, when the entry
// is older than the TTL, kicks ONE guarded background thread to recompute. The
// existing 5s `AccountList` poll picks up the refreshed numbers with no
// frontend change.
//
// The fully-durable design this cache once stood in for — a daemon-written
// persistent `usage-{slot}.ndjson` that the command just reads — is BUILT
// (an internal ticket, CLOSED; shipped as [`csq_core::daemon::usage_ledger_writer`]).
// `get_account_usage` below now reads that ledger FIRST ("Ledger-first",
// an internal ticket) and only falls through to this cache as a cold-start path for
// the first seconds after daemon launch, before the writer's first tick
// completes. This cache is therefore the FALLBACK, not the primary path;
// the comment above describes only the fallback.

type UsagePairs = Vec<(AccountNum, csq_core::usage::ledger::UsageEvent)>;

struct UsageCacheEntry {
    base_dir: String,
    computed_at: std::time::Instant,
    pairs: std::sync::Arc<UsagePairs>,
}

// SINGLE-BASE ASSUMPTION: csq desktop runs with exactly one `~/.claude/accounts`
// base per process, so a single global cache slot + single in-flight flag are
// sufficient. If two DIFFERENT `base_dir`s ever alternated through this cache,
// they would thrash the one slot and the single flag could starve the "losing"
// base's refresh — acceptable because that configuration does not occur in
// production. The `base_dir` guard below is also load-bearing for TEST
// isolation: tests with distinct tempdir bases route a foreign-base cache hit
// to the "absent" arm, so they never observe each other's cached aggregate.
static USAGE_CACHE: std::sync::OnceLock<std::sync::Mutex<Option<UsageCacheEntry>>> =
    std::sync::OnceLock::new();
static USAGE_REFRESH_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// How long a cached aggregate is served before a background refresh is kicked.
/// A billing ledger does not need second-fresh numbers; this bounds the ~20s
/// background scan to at most once per interval while the dashboard is open.
const USAGE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

fn usage_cache() -> &'static std::sync::Mutex<Option<UsageCacheEntry>> {
    USAGE_CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

/// Runs the aggregator for `base` and returns the all-slots (slot, event)
/// pairs. Synchronous; used by the background refresh thread and by tests.
///
/// The real per-turn model is sourced from the transcript (an internal ticket); the
/// callback below is only a FALLBACK for sessions whose transcript had no
/// model line (prior to an internal ticket this hardcoded model was applied to EVERY slot,
/// costing a DeepSeek slot at Sonnet rates).
fn aggregate_usage_pairs(base: &std::path::Path, now: chrono::DateTime<chrono::Utc>) -> UsagePairs {
    // Resolve $HOME/.claude — `get_base_dir` resolves ~/.claude/accounts, so
    // claude_home is its parent. Malformed base → empty (no panic).
    let Some(claude_home) = base.parent().map(|p| p.to_path_buf()) else {
        return Vec::new();
    };
    // Model FALLBACK for the rare model-less transcript line: resolve the
    // slot's configured model (matching the daemon usage-ledger writer's
    // fallback) so the cold-start live-scan and the published ledger cost such
    // lines identically. (an internal ticket redteam R1 MEDIUM-2.)
    csq_core::usage::aggregator::aggregate(&claude_home, base, now, |slot| {
        csq_core::providers::settings::model_id_for_slot(base, slot.get())
            .unwrap_or_else(|| "claude-sonnet-5".to_string())
    })
}

/// Filters the cached pairs to one slot and summarizes into the IPC view.
fn summarize_slot(
    pairs: &UsagePairs,
    account_num: AccountNum,
    now: chrono::DateTime<chrono::Utc>,
) -> UsageSummaryView {
    let events: Vec<csq_core::usage::ledger::UsageEvent> = pairs
        .iter()
        .filter(|(s, _)| *s == account_num)
        .map(|(_, ev)| ev.clone())
        .collect();
    let summary = csq_core::usage::ledger::summarize(&events, now);
    summary_to_view(summary)
}

/// Maps a core [`csq_core::usage::ledger::UsageSummary`] to the IPC view.
/// Shared by the live-scan path ([`summarize_slot`]) and the ledger-first path
/// ([`get_account_usage`], an internal ticket) so both surfaces produce an identical
/// shape.
fn summary_to_view(summary: csq_core::usage::ledger::UsageSummary) -> UsageSummaryView {
    UsageSummaryView {
        total_input_tokens: summary.total_input_tokens,
        total_output_tokens: summary.total_output_tokens,
        total_cost_usd: summary.total_cost_usd,
        last_30d_input_tokens: summary.last_30d_input_tokens,
        last_30d_output_tokens: summary.last_30d_output_tokens,
        last_30d_cost_usd: summary.last_30d_cost_usd,
        last_7d_input_tokens: summary.last_7d_input_tokens,
        last_7d_output_tokens: summary.last_7d_output_tokens,
        last_7d_cost_usd: summary.last_7d_cost_usd,
        last_5d_input_tokens: summary.last_5d_input_tokens,
        last_5d_output_tokens: summary.last_5d_output_tokens,
        last_5d_cost_usd: summary.last_5d_cost_usd,
        today_input_tokens: summary.today_input_tokens,
        today_output_tokens: summary.today_output_tokens,
        today_cost_usd: summary.today_cost_usd,
        event_count: summary.event_count,
        unestimated_cost_count: summary.unestimated_cost_count,
    }
}

/// Returns the cached all-slots pairs (cloning the `Arc`), kicking ONE guarded
/// background refresh when the entry is stale/absent/for a different base. The
/// caller gets an immediate answer; refreshed numbers appear on the next poll.
fn cached_or_refresh_pairs(base_dir: &str) -> std::sync::Arc<UsagePairs> {
    use std::sync::atomic::Ordering;

    let (pairs, needs_refresh) = {
        let guard = usage_cache().lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(c) if c.base_dir == base_dir && c.computed_at.elapsed() < USAGE_CACHE_TTL => {
                (c.pairs.clone(), false)
            }
            Some(c) if c.base_dir == base_dir => (c.pairs.clone(), true), // stale → serve + refresh
            _ => (std::sync::Arc::new(Vec::new()), true),                 // absent / different base
        }
    };

    if needs_refresh && !USAGE_REFRESH_IN_FLIGHT.swap(true, Ordering::AcqRel) {
        let base_owned = base_dir.to_string();
        // `Builder::spawn` returns a `Result` instead of panicking on OS thread
        // exhaustion, so we can release the flag we just took if the thread
        // never starts. Without this, a spawn failure after `swap(true)` would
        // leave the flag stuck `true` and freeze the ledger for the process
        // lifetime — the same failure class as the panic-in-scan case the RAII
        // guard below covers (redteam an internal ticket HIGH-1 + R2 MEDIUM).
        let spawned = std::thread::Builder::new()
            .name("csq-usage-refresh".into())
            .spawn(move || {
                // RAII reset: clears the in-flight flag on EVERY exit of the
                // running thread, including an unwind out of the scan.
                struct ResetInFlight;
                impl Drop for ResetInFlight {
                    fn drop(&mut self) {
                        USAGE_REFRESH_IN_FLIGHT.store(false, std::sync::atomic::Ordering::Release);
                    }
                }
                let _reset = ResetInFlight;

                let now = chrono::Utc::now();
                let fresh = aggregate_usage_pairs(&PathBuf::from(&base_owned), now);
                let mut guard = usage_cache().lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some(UsageCacheEntry {
                    base_dir: base_owned,
                    computed_at: std::time::Instant::now(),
                    pairs: std::sync::Arc::new(fresh),
                });
                // `_reset` drops here (or on unwind), releasing the flag.
            });
        if spawned.is_err() {
            // Thread never started → release the flag so a later call retries.
            USAGE_REFRESH_IN_FLIGHT.store(false, Ordering::Release);
        }
    }

    pairs
}

/// Phase B' (an internal journal entry) — returns the per-account usage summary for the
/// pay-per-token ledger view.
///
/// Non-blocking: serves a cached all-slots aggregate and kicks a background
/// refresh when stale (see the cache module above) — the ~20s transcript scan
/// never runs on this synchronous call path (an internal ticket).
///
/// PRIVACY (D6): the aggregator's deserialization shape (see
/// `csq_core::usage::aggregator::TranscriptLine`) reads ONLY metadata fields
/// (model, token counts, timestamps, cwd) from CC's transcripts at
/// `~/.claude/projects/<cwd>/<session-id>.jsonl`, line-streamed so no
/// transcript is held whole. Conversation content is never retained or
/// persisted (an internal ticket).
#[tauri::command]
pub fn get_account_usage(base_dir: String, account: u16) -> Result<UsageSummaryView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("INVALID_INPUT: {e}"))?;
    let now = chrono::Utc::now();

    // Ledger-first (an internal ticket): when the daemon has published this slot's
    // ledger, read it directly — a sub-ms read that renders instantly. The
    // daemon usage-ledger writer is the SOLE producer; this terminal only reads
    // (account-terminal-separation.md Rule 1, extended for billing telemetry).
    // The desktop app runs the in-process daemon, so the writer's immediate
    // first tick populates the ledger within seconds of launch and refreshes it
    // every 10 min — the read path never pays the ~20s scan.
    let base = std::path::PathBuf::from(&base_dir);
    if csq_core::usage::ledger::ledger_path(&base, account_num).exists() {
        if let Ok(result) = csq_core::usage::ledger::read_all(&base, account_num) {
            // Treat the ledger as a cache: a NON-EMPTY read is a hit → serve it
            // fast. An EMPTY read is a miss (rolled-off / never-populated slot)
            // → fall through to the authoritative live-scan below, which yields
            // the same zero but defends against a transient empty tick blanking
            // a populated slot. (an internal ticket redteam R1 MEDIUM-1.)
            if !result.events.is_empty() {
                let summary = csq_core::usage::ledger::summarize(&result.events, now);
                return Ok(summary_to_view(summary));
            }
        }
        // A read error (I/O, not "absent") also falls through to the live scan.
    }

    // Cold-start fallback: no daemon-written ledger yet (fresh install, or the
    // first seconds after launch before the writer's first tick completes).
    // Serve the cached live-scan aggregate and kick a background refresh
    // (an internal ticket) — non-blocking, never runs the scan on this call.
    let pairs = cached_or_refresh_pairs(&base_dir);
    Ok(summarize_slot(&pairs, account_num, now))
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct UsageSummaryView {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub last_30d_input_tokens: u64,
    pub last_30d_output_tokens: u64,
    pub last_30d_cost_usd: f64,
    pub last_7d_input_tokens: u64,
    pub last_7d_output_tokens: u64,
    pub last_7d_cost_usd: f64,
    pub last_5d_input_tokens: u64,
    pub last_5d_output_tokens: u64,
    pub last_5d_cost_usd: f64,
    pub today_input_tokens: u64,
    pub today_output_tokens: u64,
    pub today_cost_usd: f64,
    pub event_count: u64,
    pub unestimated_cost_count: u64,
}

/// Returns the current auto-rotation configuration.
///
/// Returns defaults if `rotation.json` does not exist.
#[tauri::command]
pub fn get_rotation_config(base_dir: String) -> Result<RotationConfig, String> {
    let base = PathBuf::from(&base_dir);
    rotation_config::load(&base).map_err(|e| e.redacted_message())
}

/// Enables or disables auto-rotation, writing the change to `rotation.json`.
#[tauri::command]
pub fn set_rotation_enabled(base_dir: String, enabled: bool) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    let mut config = rotation_config::load(&base).map_err(|e| e.redacted_message())?;
    config.enabled = enabled;
    rotation_config::save(&base, &config).map_err(|e| e.redacted_message())
}

/// IPC view of [`CapabilityLayerToggles`] for the desktop tray
/// (M6 PR-CA12 — FR-CL-05). Mirrors the on-disk shape one-to-one;
/// no secrets, all booleans. Provided as a separate type rather
/// than re-exporting `CapabilityLayerToggles` directly so a future
/// csq-core change to the persisted shape (e.g. adding a non-public
/// audit-trail field) does not silently change the IPC contract
/// the frontend depends on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CapabilityLayerTogglesView {
    pub disable_capability_layer: bool,
    pub disable_scaffold: bool,
    pub disable_mcp_gate: bool,
    pub disable_post_validate: bool,
    pub disable_struct_out: bool,
}

impl From<CapabilityLayerToggles> for CapabilityLayerTogglesView {
    fn from(t: CapabilityLayerToggles) -> Self {
        Self {
            disable_capability_layer: t.disable_capability_layer,
            disable_scaffold: t.disable_scaffold,
            disable_mcp_gate: t.disable_mcp_gate,
            disable_post_validate: t.disable_post_validate,
            disable_struct_out: t.disable_struct_out,
        }
    }
}

impl From<CapabilityLayerTogglesView> for CapabilityLayerToggles {
    fn from(v: CapabilityLayerTogglesView) -> Self {
        Self {
            disable_capability_layer: v.disable_capability_layer,
            disable_scaffold: v.disable_scaffold,
            disable_mcp_gate: v.disable_mcp_gate,
            disable_post_validate: v.disable_post_validate,
            disable_struct_out: v.disable_struct_out,
        }
    }
}

/// Returns the persisted capability-layer toggles. Missing or
/// unreadable files yield defaults (every technique enabled). The
/// frontend renders these as the initial state of the tray submenu
/// checkmarks.
///
/// Idempotent: calling repeatedly with no writer in between returns
/// the same view. Writes happen via [`set_capability_layer_toggles`].
///
/// # Defense-in-depth: handler `is_dir()` + core `create_dir_all`
///
/// R-MEDIUM-5 (M6 redteam round 1) flagged the two-layer pattern as
/// potentially contradictory: this handler rejects with a typed error
/// when `base_dir` does not exist, while the underlying core fns
/// (`save_capability_layer_toggles`, `save_grace_state`) call
/// `create_dir_all(parent)` and would silently create the directory
/// chain. The two layers are intentional and complementary:
///
/// - **Handler `is_dir()`**: surfaces a clear typed error to the
///   frontend per `tauri-commands.md` §"Argument Validation" ("the
///   command handler is the last line of defense before data reaches
///   core logic"). A frontend caller passing a typo'd or unmounted
///   path gets `"base directory does not exist: <path>"` not a stale
///   write to a freshly-created sibling directory.
///
/// - **Core `create_dir_all(parent)`**: handles the legitimate case
///   where `<base>/coc-version-grace.json`'s parent (the base dir
///   itself, in practice) exists but a non-base ancestor of the
///   eventual file path does not — e.g. a future schema lands the
///   file at `<base>/coc/version-grace.json` and needs `<base>/coc/`
///   created on first write.
///
/// The two layers are NOT redundant: removing the handler check
/// downgrades the error message; removing the core check breaks
/// nested-path schema evolution.
#[tauri::command]
pub fn get_capability_layer_toggles(
    base_dir: String,
) -> Result<CapabilityLayerTogglesView, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    Ok(load_capability_layer_toggles(&base).into())
}

/// Persists the capability-layer toggles. The next `csq run` call
/// reads the file and honors the new toggles — there is no
/// in-process cache to invalidate. Returns the saved view (server-
/// side echo) so the frontend can confirm the round-trip without a
/// follow-up `get_*` call.
///
/// See [`get_capability_layer_toggles`] for the rationale on the
/// handler-boundary `is_dir()` check vs the core
/// `create_dir_all(parent)` pattern (R-MEDIUM-5).
#[tauri::command]
pub fn set_capability_layer_toggles(
    base_dir: String,
    toggles: CapabilityLayerTogglesView,
) -> Result<CapabilityLayerTogglesView, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    let to_save: CapabilityLayerToggles = toggles.into();
    save_capability_layer_toggles(&base, &to_save).map_err(|e| e.redacted_message())?;
    Ok(toggles)
}

/// Public view of one live CC session, safe to send over IPC.
///
/// Includes the current account for the bound config dir plus its
/// 5-hour usage percentage so the dashboard can render a "terminal
/// #5 → account #3 at 87%" row without the frontend making a
/// second IPC call.
///
/// Also exposes terminal identity fields (tty, iTerm window/tab/pane,
/// profile, resolved tab title) so the user can match the dashboard
/// row to the terminal window they're looking at.
#[derive(Serialize)]
pub struct SessionView {
    /// OS process ID.
    pub pid: u32,
    /// Working directory at process creation.
    pub cwd: String,
    /// Path to the `config-N` dir this session is bound to.
    pub config_dir: String,
    /// Account number extracted from the config dir name, or null.
    pub account_id: Option<u16>,
    /// Account label for `account_id` at the moment of the query,
    /// or null if the account is unknown.
    pub account_label: Option<String>,
    /// Current 5-hour quota percentage for the bound account.
    ///
    /// `0.0` when `has_quota` is false — a wire-format default, NOT a
    /// measurement. Gate any rendering on `has_quota` first.
    pub five_hour_pct: f64,
    /// Current 7-day quota percentage for the bound account.
    ///
    /// Same caveat as [`Self::five_hour_pct`].
    pub seven_day_pct: f64,
    /// Whether the two percentages above are MEASUREMENTS.
    ///
    /// False when the bound account has no quota row, or has one carrying
    /// no usage window at all (a balance-metered slot such as DeepSeek, or
    /// a weekly-only slot before its first poll). Without this the badge
    /// rendered `7d:0%` styled healthy for slots whose quota is simply not
    /// observable — the same wire-format-default hazard `AccountView`
    /// already carries `has_quota` to prevent. `SessionView` was missing
    /// the companion field, so the session list could not tell the two
    /// apart even though the account list could.
    pub has_quota: bool,
    /// Unix seconds since the process started, or null if the
    /// platform could not report it.
    pub started_at: Option<u64>,
    /// Controlling TTY basename (e.g. `"ttys003"`). Users can run
    /// `tty` in their terminal to match a row.
    pub tty: Option<String>,
    /// iTerm2 window/tab/pane indices parsed from `TERM_SESSION_ID`.
    pub term_window: Option<u8>,
    pub term_tab: Option<u8>,
    pub term_pane: Option<u8>,
    /// iTerm2 profile name from `ITERM_PROFILE`.
    pub iterm_profile: Option<String>,
    /// Human-readable iTerm2 tab title resolved via osascript.
    /// Most specific identifier when available.
    pub terminal_title: Option<String>,
}

/// Resolves the slot a session's config dir is CURRENTLY bound to.
///
/// `dir_name_account` is the id parsed from the `config-<N>` directory
/// NAME (`SessionInfo::account_id`). It is a last resort, never an
/// override: `account-terminal-separation.md` MUST NOT Rule 3 makes the
/// `.csq-account` marker the SOLE authority, with no exception for a
/// marker that is present but unresolvable.
///
/// The two `None` cases of
/// [`csq_core::accounts::markers::resolve_marker_to_slot`] mean opposite
/// things and MUST be separated here:
///
/// - **no marker at all** — a genuine pre-`by_slot` legacy dir. The
///   dir-name fallback is exactly what it was written for.
/// - **marker present, but it will not resolve** — a UUID marker whose
///   `by_slot` entry is missing or stale (`profiles.json` mid-update,
///   or a `move_slot` rename in flight). Falling back to the dir name
///   HERE re-opens the confident-wrong-answer this function exists to
///   close, and does so in precisely the slot-rename scenario the
///   caller's comment cites as its worked example. Render unknown.
fn resolve_live_account(
    base: &Path,
    config_dir: &Path,
    dir_name_account: Option<u16>,
) -> Option<u16> {
    match csq_core::accounts::markers::read_identity_marker(config_dir) {
        // A marker EXISTS — it is the sole authority. Unresolvable means
        // unknown, NOT "guess from the directory name".
        Some(_) => {
            csq_core::accounts::markers::resolve_marker_to_slot(base, config_dir).map(|n| n.get())
        }
        // No marker — legacy dir, the dir name is all there is.
        None => dir_name_account,
    }
}

#[cfg(test)]
mod resolve_live_account_tests {
    use super::resolve_live_account;
    use csq_core::testing::identity_fixtures::{fixture_uuid_for_slot, write_uuid_account_marker};
    use tempfile::TempDir;

    /// (a) UUID marker WITH a `by_slot` entry — the modern, healthy slot.
    #[test]
    fn uuid_marker_with_by_slot_resolves_to_the_mapped_slot() {
        let base = TempDir::new().unwrap();
        let config = base.path().join("config-5");
        std::fs::create_dir_all(&config).unwrap();
        write_uuid_account_marker(base.path(), &config, 5);

        // The dir-name id is deliberately WRONG (8, not 5). DO NOT "tidy"
        // it to 5 — it is load-bearing twice over. It proves the marker
        // beats the dir name, AND it is the only thing that discriminates
        // a `base`/`config_dir` argument transposition: those two are both
        // `&Path` and adjacent, so swapping them compiles cleanly. Under a
        // swap, `read_identity_marker(base)` finds no marker at the
        // TempDir root, takes the `None` arm, and returns Some(8) — which
        // fails only because the expected value is 5.
        assert_eq!(
            resolve_live_account(base.path(), &config, Some(8)),
            Some(5),
            "the marker is the sole authority; the dir-name id must not win"
        );
    }

    /// (b) UUID marker present but NOT resolvable. This fixture builds the
    /// `by_slot`-**missing** variant (no `profiles.json` at all); the
    /// **stale** variant (`profiles.json` present, no entry for this UUID)
    /// routes through the same `resolve_uuid_to_slot` → `None` and is
    /// covered by `resolve_uuid_to_slot_present_and_absent` in `markers.rs`.
    ///
    /// This is the arm the `.or(dir_name)` form got wrong: it rendered
    /// another account's label and quota row in exactly the slot-rename
    /// case the caller's comment cites.
    ///
    /// Why this cannot pass for the wrong reason: `dir_name_account` here
    /// is `Some(6)`. Had the marker read returned `None` and taken the
    /// wrong arm, the function would return `Some(6)`, not `None` — so
    /// asserting `== None` structurally proves the `Some(_)` arm ran.
    /// (The mutation probe recorded in this commit's history proves the
    /// DEFECT is reproduced; it does NOT pin the fixture state, because
    /// the old `.or()` code returns `Some(6)` for both a present-UUID
    /// marker and an absent one. Two claims, two separate proofs.)
    #[test]
    fn uuid_marker_without_by_slot_entry_is_unknown_not_the_dir_name() {
        let base = TempDir::new().unwrap();
        let config = base.path().join("config-6");
        std::fs::create_dir_all(&config).unwrap();
        // Marker written WITHOUT provisioning a by_slot entry for it.
        let orphan = fixture_uuid_for_slot(99);
        csq_core::accounts::markers::write_csq_account(&config, orphan).unwrap();

        assert_eq!(
            resolve_live_account(base.path(), &config, Some(6)),
            None,
            "a present-but-unresolvable marker must render unknown, never \
             fall back to the config-dir name (account-terminal-separation.md \
             MUST NOT Rule 3 has no exception for an unresolvable marker)"
        );
    }

    /// (c) No marker at all — a genuine pre-`by_slot` legacy dir. The
    /// dir-name fallback is exactly what it was written for and MUST
    /// survive; dropping it would regress legacy dirs to "unknown".
    #[test]
    fn absent_marker_falls_back_to_the_dir_name_id() {
        let base = TempDir::new().unwrap();
        let config = base.path().join("config-7");
        std::fs::create_dir_all(&config).unwrap();
        // No marker file written at all.

        assert_eq!(
            resolve_live_account(base.path(), &config, Some(7)),
            Some(7),
            "a markerless legacy dir must still resolve via the dir name"
        );
    }
}

/// Returns the list of live Claude Code sessions under the current
/// user. Each entry is one terminal's `claude` process with the
/// current account and 5-hour quota for its bound config dir.
///
/// Unknown on Windows (returns an empty vector). See
/// `csq_core::sessions::windows` for the rationale.
#[tauri::command]
pub fn list_sessions(base_dir: String) -> Result<Vec<SessionView>, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let sessions = sessions::list();
    if sessions.is_empty() {
        return Ok(Vec::new());
    }

    // One discovery + quota load reused across rows. Ties each
    // session row to the *current* active account for its config
    // dir, which may have rotated since the process launched.
    let accounts = discovery::discover_all(&base);
    // an internal ticket: salvage per-row — read-only IPC query, never writes back.
    let quota: QuotaFile = quota_state::load_state_salvage(&base);

    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        // Use the `.csq-account` marker for the live account, not
        // the config dir name. The marker reflects swaps and renames
        // (e.g. config-8 with marker=7 after a slot rename).
        //
        // M4-7 (an internal ticket Phase 4): the marker's CONTENT is a UUID
        // whenever a `by_slot` mapping exists, so the numeric-only
        // `read_csq_account` returned `None` on every modern slot and the
        // dir-name fallback then silently won — the confident wrong answer
        // this comment forbids. `resolve_live_account` reads the marker as
        // the sole authority and keeps the dir-name fallback for markerless
        // legacy dirs ONLY (`guard-reader-writer-parity.md`).
        let live_account = resolve_live_account(&base, &s.config_dir, s.account_id);
        let account_info = live_account.and_then(|id| accounts.iter().find(|a| a.id == id));
        let account_label = account_info.map(|a| a.label.clone());
        // A row exists AND carries at least one usage window. Both halves
        // matter: a balance-metered slot has a row but no window, and its
        // percentages below are wire-format defaults rather than readings.
        let session_row = live_account.and_then(|id| quota.get(id));
        let has_quota = session_row.map(|q| q.shows_window()).unwrap_or(false);
        let five_hour_pct = session_row
            .and_then(|q| q.five_hour_pct_opt())
            .unwrap_or(0.0);
        let seven_day_pct = session_row
            .and_then(|q| q.seven_day_pct_opt())
            .unwrap_or(0.0);

        out.push(SessionView {
            pid: s.pid,
            cwd: s.cwd.display().to_string(),
            config_dir: s.config_dir.display().to_string(),
            account_id: live_account,
            account_label,
            five_hour_pct,
            seven_day_pct,
            has_quota,
            started_at: s.started_at,
            tty: s.tty,
            term_window: s.term_window,
            term_tab: s.term_tab,
            term_pane: s.term_pane,
            iterm_profile: s.iterm_profile,
            terminal_title: s.terminal_title,
        });
    }

    // Deterministic ordering by PID so the dashboard list doesn't
    // shuffle between polls. Ascending PID roughly maps to "order
    // the terminals were opened" which matches how the user thinks
    // about their workspace.
    out.sort_by_key(|s| s.pid);
    Ok(out)
}
/// Returns whether the csq daemon is running.
#[tauri::command]
pub fn get_daemon_status(base_dir: String) -> Result<DaemonStatusView, String> {
    let base = PathBuf::from(&base_dir);
    let pid_path = csq_core::daemon::pid_file_path(&base);
    let status = csq_core::daemon::status_of(&pid_path);
    Ok(match status {
        csq_core::daemon::DaemonStatus::Running { pid } => DaemonStatusView {
            running: true,
            pid: Some(pid),
        },
        _ => DaemonStatusView {
            running: false,
            pid: None,
        },
    })
}

/// Public view of a provider entry, safe to send over IPC.
///
/// Intentionally does not include any secret material — the
/// `key_env_var` and `base_url_env_var` fields name the env vars
/// whose *values* are secrets, not the values themselves.
#[derive(Serialize)]
pub struct ProviderView {
    /// Short identifier used on subsequent commands (e.g. "claude", "mm", "zai", "deepseek").
    pub id: String,
    /// Display name (e.g. "Claude", "MiniMax", "Z.AI", "DeepSeek").
    pub name: String,
    /// `"oauth"` | `"bearer"` | `"none"`.
    pub auth_type: String,
    /// Default base URL or null.
    pub default_base_url: Option<String>,
    /// Default model the provider ships with.
    pub default_model: String,
}

/// Returns the full provider catalog (Claude, MiniMax, Z.AI, Ollama).
///
/// The frontend branches on `auth_type`:
/// - `"oauth"` → Claude sign-in flow
/// - `"bearer"` → API-key entry (MiniMax, Z.AI)
/// - `"none"` → keyless slot binding (Ollama) via [`bind_keyless_provider`]
#[tauri::command]
pub fn list_providers() -> Result<Vec<ProviderView>, String> {
    Ok(providers::PROVIDERS
        .iter()
        .map(|p| ProviderView {
            id: p.id.to_string(),
            name: p.name.to_string(),
            auth_type: match p.auth_type {
                providers::catalog::AuthType::OAuth => "oauth".into(),
                providers::catalog::AuthType::Bearer => "bearer".into(),
                providers::catalog::AuthType::None => "none".into(),
            },
            default_base_url: p.default_base_url.map(|s| s.to_string()),
            default_model: p.default_model.to_string(),
        })
        .collect())
}

/// Public view of a native-CLI session-surface entry (Kimi, Grok), safe
/// to send over IPC. Distinct from [`ProviderView`] — a native surface
/// is a **self-authenticating vendor binary** csq dispatches sessions
/// to but never stores credentials for (Design B, an internal journal entry), not a
/// Bearer/OAuth provider in [`providers::PROVIDERS`].
#[derive(Serialize)]
pub struct NativeCliView {
    /// Short identifier passed to [`start_native_login`] /
    /// [`complete_native_login`] (`"kimi-cli"`, `"grok"`). Distinct from
    /// the 3P-bearer Kimi provider's id (`"kimi"`) — the two are
    /// separate picker entries.
    pub id: String,
    /// Display name for the picker (e.g. "Kimi (native CLI)").
    pub display_name: String,
    /// Vendor-selected default model, display-only — csq does not pin
    /// it. Empty string means "vendor-selected"; the picker hides the
    /// model line in that case.
    pub default_model: String,
    /// Dispatch-axis surface tag (`"kimi"` / `"grok"`), matching
    /// `Surface::as_str`. Not currently consumed by the frontend but
    /// kept for parity with `ProviderView` and future diagnostics.
    pub surface: String,
    /// Vendor binary name (`"kimi"` / `"grok"`) the frontend passes to
    /// [`provider_cli_installed`] for the pre-flight CLI-missing hint.
    /// Deliberately a SEPARATE field from `surface` — the two happen to
    /// share the same string today but are independent concepts
    /// (dispatch-axis tag vs PATH-resolvable binary name); the frontend
    /// must not assume they stay in sync.
    pub binary: String,
}

/// Returns the native-CLI session-surface catalog (Kimi, Grok) — vendor
/// binaries csq dispatches `csq run N` sessions to but never stores
/// credentials for; the vendor CLI self-authenticates on its own
/// schedule.
///
/// The frontend renders these alongside [`list_providers`]'s entries in
/// the Add Account picker (so native Kimi appears next to the existing
/// 3P-bearer Kimi, and Grok appears as native-only); picking one starts
/// the [`start_native_login`] / [`complete_native_login`] device-code
/// flow instead of an OAuth/bearer/keyless one (an internal journal entry C8).
#[tauri::command]
pub fn list_native_clis() -> Result<Vec<NativeCliView>, String> {
    Ok(csq_core::providers::native::NATIVE_CLIS
        .iter()
        .map(|nc| NativeCliView {
            id: nc.id.to_string(),
            display_name: nc.display_name.to_string(),
            default_model: nc.default_model.to_string(),
            surface: nc.surface.as_str().to_string(),
            binary: nc.binary.to_string(),
        })
        .collect())
}

// ── Native Kimi/Grok desktop login commands (an internal journal entry C8) ─────
//
// Mirrors the Codex desktop twin's start/complete/cancel shape (PR-C8,
// `start_codex_login` / `complete_codex_login` / `cancel_codex_login`)
// but simpler: the 0135 design lock made native surfaces per-slot-authed
// via an isolated vendor home (the `CODEX_HOME` pattern, without codex's
// UUID/symlink/relocation machinery — native surfaces self-refresh, so
// csq never needs to centrally rotate their tokens). All the real work —
// spawn into the slot's vendor home, forward device codes, verify the
// vendor's credential file, write the marker on success ONLY — already
// lives in `csq_core::providers::native_login::login_native_with`. The
// desktop layer here supplies ONLY the two DI seams `login_native_with`
// needs: (a) a production `spawn` closure that starts the real vendor
// binary with piped stdout and registers the child for cancellation,
// and (b) an `on_device_code` callback that emits a `native-device-code`
// Tauri event. Device-code parsing happens EXCLUSIVELY inside
// `login_native_with` (the host-allowlisted `parse_native_device_code`)
// — this layer never re-parses raw stdout itself, so the phishing
// surface C1 closed for codex/native stays closed here too.

/// Result view for [`start_native_login`]. IPC-safe.
#[derive(Debug, Serialize)]
pub struct StartNativeLoginView {
    /// Echoes the resolved native id back (`"kimi-cli"` / `"grok"`).
    pub native_id: String,
    pub display_name: String,
    /// Whether `binary` resolves via [`provider_cli_installed`]'s same
    /// resolution chain (`find_cli_binary` OR
    /// `cli_deps::install_path::find_in_path`). `false` surfaces an
    /// install hint — it does NOT block [`complete_native_login`], which
    /// re-resolves the binary at spawn time and errors cleanly if it is
    /// still missing (mirrors the pre-0135 `native-cli-confirm` posture:
    /// the missing-CLI state is informational, not a hard gate).
    pub cli_installed: bool,
}

/// Device-code payload emitted to the desktop UI while a native vendor
/// login subprocess is running. Mirrors
/// `codex::desktop_login::DeviceCodeInfo` but carries `surface` so ONE
/// Svelte listener (`native-device-code`) serves both the Kimi and Grok
/// flows.
#[derive(Serialize)]
pub struct NativeDeviceCodeView {
    /// `"kimi"` / `"grok"` — matches `Surface::as_str`.
    pub surface: String,
    pub user_code: String,
    pub verification_url: String,
}

/// Resolves + validates a native-CLI login request. Shared by
/// [`start_native_login`] and [`complete_native_login`] so both commands
/// agree on unknown-id / invalid-slot / missing-base-dir / conflicting-
/// binding rejection — this is the same validation the retired
/// `provision_native_cli` (an internal journal entry W3-5) used to perform inline,
/// factored out now that TWO commands need it.
///
/// # Errors
///
/// - `"unknown native CLI id: ..."` — id not in
///   `providers::native::NATIVE_CLIS` (frontend sent a stale id)
/// - `"invalid slot: ..."` — slot out of range 1..=999
/// - `"base directory does not exist: ..."` — base dir missing
/// - `"slot N is bound to <surface> — run \`csq logout N\` to rebind"`
///   — conflicting surface already claims the slot (Codex, Claude/
///   Anthropic OAuth, Gemini, 3P-bearer, or the OTHER native surface —
///   see [`csq_core::providers::native::conflicting_bound_surface`])
fn resolve_native_login_request(
    base_dir: &str,
    native_id: &str,
    slot: u16,
) -> Result<
    (
        &'static csq_core::providers::native::NativeCli,
        PathBuf,
        AccountNum,
    ),
    String,
> {
    use csq_core::providers::native;

    let descriptor = native::descriptor_by_id(native_id)
        .ok_or_else(|| format!("unknown native CLI id: {native_id}"))?;
    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let base = PathBuf::from(base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    // Use the `BoundSurface`-returning guard directly so a 3P-bearer conflict is
    // labeled accurately ("a third-party provider") rather than mislabeled via
    // the `ThirdPartyBearer→ClaudeCode` wire collapse (redteam R1 MEDIUM-1).
    if let Some(existing) = csq_core::accounts::binding_guard::conflicting_bound_surface(
        &base,
        slot_num,
        descriptor.surface,
    ) {
        return Err(format!(
            "slot {slot} is bound to {} — run `csq logout {slot}` to rebind",
            existing.label()
        ));
    }
    Ok((descriptor, base, slot_num))
}

/// Pre-check step of a native Kimi/Grok Add Account flow (mirrors
/// [`start_codex_login`]): validates the request (id/slot/base-dir/
/// conflicting-binding) and surfaces whether the vendor CLI binary is
/// installed, so the modal can render an in-flow install hint BEFORE
/// spawning the login. No filesystem writes beyond the PATH probe.
#[tauri::command]
pub fn start_native_login(
    base_dir: String,
    native_id: String,
    slot: u16,
) -> Result<StartNativeLoginView, String> {
    let (descriptor, _base, _slot_num) = resolve_native_login_request(&base_dir, &native_id, slot)?;
    let cli_installed = csq_core::accounts::login::find_cli_binary(descriptor.binary)
        .or_else(|| csq_core::cli_deps::install_path::find_in_path(descriptor.binary))
        .is_some();
    Ok(StartNativeLoginView {
        native_id: descriptor.id.to_string(),
        display_name: descriptor.display_name.to_string(),
        cli_installed,
    })
}

/// Atomically checks-and-reserves `surface` in `children` under a SINGLE
/// lock acquisition, so two concurrent [`complete_native_login`] calls
/// for the SAME surface cannot both pass the presence check before
/// either registers.
///
/// # The TOCTOU this closes
///
/// The previous shape checked `contains_key(&surface)` under a lock,
/// RELEASED the lock, and only registered the real child much later —
/// inside [`spawn_native_device_auth_piped`], after `resolve_native_login_request`,
/// `tokio::task::spawn_blocking`, and `login_native_with`'s home-dir
/// creation had all run. Two `complete_native_login` calls for the same
/// surface could both observe an empty map, both pass the check, and
/// both go on to spawn a real vendor login — the second spawn's insert
/// would silently overwrite the first's map entry, orphaning the first
/// child (uncancellable via [`cancel_native_login`], and racing the same
/// `native-homes/<surface>-<N>/` directory). Holding the lock across the
/// check AND the reservation insert removes the window entirely: the
/// second caller observes the first caller's reservation and is
/// refused before ever reaching `spawn_blocking`.
///
/// The reservation is a `None` placeholder — see [`NativeLoginChildren`]
/// — later overwritten with `Some(child)` by
/// [`spawn_native_device_auth_piped`] once the vendor binary is
/// actually spawned. [`complete_native_login`] clears the reservation
/// (whether it ever became a real child or not) on every exit path, so
/// a failed spawn can never wedge the surface permanently.
///
/// Extracted as a pure function (mirrors [`cancel_native_login_from`])
/// so the refusal path is unit-testable without a live Tauri runtime.
///
/// # Errors
///
/// `"<display_name> login already in progress — cancel the running
/// flow before starting a new one"` if `surface` already has an entry
/// (reserved OR spawned).
fn reserve_native_login_slot(
    children: &NativeLoginChildren,
    surface: csq_core::providers::catalog::Surface,
    display_name: &str,
) -> Result<(), String> {
    let mut guard = children
        .lock()
        .map_err(|_| "native login slot poisoned".to_string())?;
    if guard.contains_key(&surface) {
        return Err(format!(
            "{display_name} login already in progress — cancel the running flow before starting a new one"
        ));
    }
    guard.insert(surface, None);
    Ok(())
}

/// Belt-and-suspenders reservation cleanup for [`complete_native_login`]
/// (redteam R2 LOW-1 + LOW-2).
///
/// The spawn closure's `wait` closure (inside
/// [`spawn_native_device_auth_piped`]) already clears the surface's map
/// entry on the happy path, once the vendor subprocess is reaped. But an
/// early pre-spawn error (binary not found, or `login_native_with`
/// erroring before it ever calls the spawn closure) would leave the
/// `None` reservation from [`reserve_native_login_slot`] in place forever
/// without a second cleanup path.
///
/// The naive fix — an unconditional `remove` after `login_native_with`
/// returns — is a TOCTOU itself: once spawn succeeds, the `wait` closure
/// ALWAYS clears the entry before `login_native_with` returns (see its
/// doc), so an unconditional remove afterward runs AFTER that clear —
/// and can delete a DIFFERENT, concurrent same-surface login's fresh
/// reservation if one raced in during the gap (LOW-1). `spawned` — set
/// `true` the instant [`spawn_native_device_auth_piped`] registers a real
/// child — lets this guard tell "my reservation is still sitting
/// untouched" (spawn never happened, safe to remove — nobody else could
/// have reserved while our entry was present, since
/// [`reserve_native_login_slot`] refuses a second reservation for the
/// same surface) from "the wait closure already handled it" (spawn
/// happened, never touch the entry again).
///
/// Implemented as a `Drop` guard rather than an unconditional post-call
/// statement so cleanup ALSO fires if `login_native_with` panics
/// (LOW-2) — Rust runs `Drop` impls during stack unwinding, so this
/// guard clears a still-`None` reservation even when the panic unwinds
/// past the point an ordinary "cleanup after the call" statement would
/// have run. A panic AFTER a successful spawn (`spawned == true`)
/// intentionally leaves the entry in place — a real subprocess may still
/// be running and [`cancel_native_login`] needs the entry to reach it.
struct NativeLoginReservationCleanup {
    children: NativeLoginChildren,
    surface: csq_core::providers::catalog::Surface,
    spawned: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for NativeLoginReservationCleanup {
    fn drop(&mut self) {
        if !self.spawned.load(std::sync::atomic::Ordering::Acquire) {
            if let Ok(mut guard) = self.children.lock() {
                guard.remove(&self.surface);
            }
        }
    }
}

/// Completes a native Kimi/Grok Add Account flow: spawns the vendor's
/// device-code login (`kimi login` / `grok login --device-auth`) into
/// the slot's isolated vendor home (0135 design lock), forwards
/// `native-device-code` events as the vendor's device code appears
/// (via `login_native_with`'s host-allowlisted parser — see the module
/// doc above), blocks until the subprocess exits, and writes the
/// credential-less binding marker on success ONLY — no marker on
/// failure, and no marker if the vendor exits 0 without ever writing
/// its own credential file (`native_login::finish_native_login`).
///
/// # Concurrency (mirrors an internal journal entry finding 8, scoped per-surface)
///
/// Refused per SURFACE, not per slot or globally: a Kimi login already
/// in flight blocks a second Kimi login (any slot), but a Grok login may
/// run concurrently — independent vendor binary, independent vendor
/// home. Observed via `AppState.native_login_children` keyed by
/// [`csq_core::providers::catalog::Surface`].
///
/// The refusal check and the surface reservation happen under a SINGLE
/// lock acquisition ([`reserve_native_login_slot`]) — two concurrent
/// calls for the SAME surface cannot both pass the check before either
/// registers, which a check-then-release-then-register-much-later
/// sequence would allow (see that function's doc for the TOCTOU this
/// closes).
///
/// # Cancellation
///
/// The spawned child is registered in `AppState.native_login_children`
/// so [`cancel_native_login`] can kill it from the modal's
/// close/unmount handler.
#[tauri::command]
pub async fn complete_native_login(
    app: AppHandle,
    state: State<'_, AppState>,
    base_dir: String,
    native_id: String,
    slot: u16,
) -> Result<(), String> {
    let (descriptor, base, slot_num) = resolve_native_login_request(&base_dir, &native_id, slot)?;
    let surface = descriptor.surface;

    reserve_native_login_slot(
        &state.native_login_children,
        surface,
        descriptor.display_name,
    )?;

    let children = state.native_login_children.clone();
    let children_for_cleanup = children.clone();
    let app_for_task = app.clone();

    let login_result: Result<(), String> = tokio::task::spawn_blocking(move || {
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _cleanup = NativeLoginReservationCleanup {
            children: children_for_cleanup,
            surface,
            spawned: spawned.clone(),
        };

        csq_core::providers::native_login::login_native_with(
            &base,
            slot_num,
            surface,
            |home, binary, args, home_env| {
                spawn_native_device_auth_piped(
                    home, binary, args, home_env, surface, &children, &spawned,
                )
            },
            |code| {
                let _ = app_for_task.emit_to(
                    "main",
                    "native-device-code",
                    &NativeDeviceCodeView {
                        surface: surface.as_str().to_string(),
                        user_code: code.user_code,
                        verification_url: code.verification_url,
                    },
                );
            },
        )
        .map_err(|e| {
            csq_core::error::redact_tokens(&csq_core::cli_deps::sanitize::redact_home_anywhere(
                &format!("{e:#}"),
            ))
        })
    })
    .await
    .map_err(|e| format!("complete_native_login task failed: {e}"))?;

    login_result?;

    // Best-effort daemon cache invalidation, mirroring
    // complete_codex_login / the retired provision_native_cli. Fast
    // local Unix-socket call — no spawn_blocking wrapper needed.
    #[cfg(unix)]
    {
        let base = PathBuf::from(&base_dir);
        let sock = csq_core::daemon::socket_path(&base);
        if sock.exists() {
            let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
        }
    }

    Ok(())
}

/// Cancels an in-flight native (Kimi/Grok) login by killing the child
/// process registered for `native_id`'s surface. No-op when no login is
/// running for that surface. Mirrors [`cancel_codex_login`].
#[tauri::command]
pub fn cancel_native_login(state: State<'_, AppState>, native_id: String) -> Result<(), String> {
    cancel_native_login_from(&state.native_login_children, &native_id)
}

/// Pure inner of [`cancel_native_login`] — takes the per-surface child
/// map directly so the id-resolution + kill contract can be
/// unit-tested without constructing a Tauri runtime (mirrors
/// `consume_prefs_recovery_from`, which extracts for the same reason:
/// `#[tauri::command]`'s `State<'_, AppState>` requires the full app
/// handle to instantiate).
fn cancel_native_login_from(children: &NativeLoginChildren, native_id: &str) -> Result<(), String> {
    let descriptor = csq_core::providers::native::descriptor_by_id(native_id)
        .ok_or_else(|| format!("unknown native CLI id: {native_id}"))?;
    let handle_opt = {
        let guard = children.lock().map_err(|_| "native login slot poisoned")?;
        guard.get(&descriptor.surface).cloned()
    };
    // `None` (no map entry) = nothing running. `Some(None)` = a
    // `reserve_native_login_slot` reservation that hasn't been
    // overwritten with a real child yet (still resolving / pre-spawn) —
    // also nothing to kill. Only `Some(Some(handle))` has a live child.
    let Some(Some(handle)) = handle_opt else {
        return Ok(());
    };
    let mut child = handle.lock().map_err(|_| "native login child poisoned")?;
    let _ = child.kill();
    Ok(())
}

/// Production spawn closure for [`complete_native_login`]. Starts the
/// real vendor binary (`kimi` / `grok`) with `<home_env>=<home>` and
/// piped stdout, registers the child in `AppState.native_login_children`
/// (keyed by [`csq_core::providers::catalog::Surface`]) so
/// [`cancel_native_login`] can kill it, and returns a
/// [`csq_core::providers::native_login::SpawnedNativeLogin`] handle.
///
/// Device-code parsing happens ENTIRELY inside `login_native_with` —
/// this function never inspects the piped stdout's content, only wires
/// the raw reader through (0135 C8 primary methodological directive).
///
/// Resolves the binary via
/// [`csq_core::cli_deps::install_path::find_in_path`] (kimi/grok
/// known-install-dir aware) rather than the OS's own PATH search inside
/// `Command::new`, mirroring [`spawn_codex_device_auth_piped`].
///
/// `spawned` is set `true` the instant a real child is registered in
/// `children` (redteam R2 LOW-1 + LOW-2) — [`complete_native_login`]'s
/// `ReservationCleanup` guard reads it to decide whether the belt-and-
/// suspenders reservation cleanup is safe to run (it is NOT once a real
/// spawn has happened, since the `wait` closure below already owns
/// clearing the entry from that point on).
#[allow(clippy::too_many_arguments)]
fn spawn_native_device_auth_piped(
    home: &std::path::Path,
    binary: &str,
    login_args: &[&str],
    home_env: &str,
    surface: csq_core::providers::catalog::Surface,
    children: &NativeLoginChildren,
    spawned: &Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<csq_core::providers::native_login::SpawnedNativeLogin> {
    use std::process::{Command, Stdio};

    let bin_path = csq_core::cli_deps::install_path::find_in_path(binary).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "could not locate the `{binary}` binary in $PATH or any standard install \
                 location — install it and try again"
            ),
        )
    })?;

    let mut child = Command::new(&bin_path)
        .args(login_args)
        // Strip BOTH known native home vars before setting this
        // surface's own — same strip-before-set discipline
        // `set_native_home_env` uses for `csq run` (0135 design lock):
        // a parent shell exporting the OTHER surface's home var must
        // never leak into this spawn. Not a security defect on its own
        // (the login subprocess only ever reads its own `home_env`),
        // but keeps the discipline uniform across every native spawn
        // site rather than leaving login as the one exception.
        .env_remove(csq_core::providers::native::KIMI.home_env)
        .env_remove(csq_core::providers::native::GROK.home_env)
        .env(home_env, home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other(format!("spawned `{binary}` has no piped stdout")))?;

    let child_arc = Arc::new(std::sync::Mutex::new(child));

    // Register for cancel. Overwrite any stale entry defensively —
    // `complete_native_login`'s pre-check rejects concurrent callers for
    // the SAME surface, but a panicked prior run could leave a ghost
    // entry (mirrors `spawn_codex_device_auth_piped`). Overwrites
    // `reserve_native_login_slot`'s `None` placeholder with the real
    // child handle.
    {
        let mut guard = children
            .lock()
            .map_err(|_| std::io::Error::other("native login child slot poisoned"))?;
        guard.insert(surface, Some(child_arc.clone()));
    }
    // From this point on, the `wait` closure below owns clearing the map
    // entry — mark `spawned` so `ReservationCleanup` (redteam R2 LOW-1)
    // never touches it, even on a later panic (LOW-2) or an early return
    // from this function's caller.
    spawned.store(true, std::sync::atomic::Ordering::Release);

    let children = children.clone();
    Ok(csq_core::providers::native_login::SpawnedNativeLogin::new(
        std::io::BufReader::new(stdout),
        move || {
            let status = {
                let mut guard = child_arc
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.wait()
            };
            // Clear the slot now that the subprocess is fully reaped —
            // mirrors `spawn_codex_device_auth_piped`'s post-wait clear.
            if let Ok(mut guard) = children.lock() {
                guard.remove(&surface);
            }
            status
        },
    ))
}

/// Result of [`begin_claude_login`]. Safe to send over IPC — contains
/// the authorize URL, the CSRF state token, and the target account,
/// but no tokens, verifier, or authorization code.
///
/// Phase 2 of an internal ticket — no longer reachable from the renderer; struct
/// stays compiled until Phase 3's full deletion of the legacy login
/// surface.
#[allow(dead_code)]
#[derive(Serialize)]
pub struct ClaudeLoginView {
    /// Full Anthropic authorize URL the frontend should open in the
    /// system browser via `tauri-plugin-opener`'s `openUrl`.
    pub auth_url: String,
    /// CSRF state token. The frontend carries this through the
    /// paste-code step so it can route the submission back to the
    /// correct pending PKCE state when multiple logins are in flight.
    pub state: String,
    /// Account slot being authorized, echoed back for correlation.
    pub account: u16,
    /// Seconds remaining on the pending state entry. The frontend
    /// uses this to cancel the spinner with a clear message if the
    /// user walks away.
    pub expires_in_secs: u64,
}

impl From<LoginRequest> for ClaudeLoginView {
    fn from(r: LoginRequest) -> Self {
        Self {
            auth_url: r.auth_url,
            state: r.state,
            account: r.account,
            expires_in_secs: r.expires_in_secs,
        }
    }
}

/// Begins an in-process PKCE OAuth login for the given account slot.
///
/// This is step 1 of the paste-code OAuth flow:
/// 1. Generates a fresh PKCE verifier + challenge
/// 2. Records them in the shared `OAuthStateStore` keyed by a
///    random state token (CSRF protection + single-use)
/// 3. Builds the Anthropic authorize URL and returns it to the
///    frontend as a [`ClaudeLoginView`]
///
/// After calling this command the frontend should:
/// - Open `auth_url` in the system browser (via `openUrl`)
/// - Show a code-paste input field to the user
/// - Call [`submit_oauth_code`] with the `state_token` returned here
///   and the code the user copies from Anthropic's callback page
///
/// To cancel an in-flight login (e.g. user closes the modal),
/// call [`cancel_login`] with the same `state_token`.
///
/// # Errors
///
/// - `"invalid account: ..."` — account out of range 1..=999
/// - `"login store full"` — MAX_PENDING simultaneous logins active
///   (unlikely in practice but possible under rapid re-opens)
#[tauri::command]
#[allow(dead_code)]
pub fn begin_claude_login(
    state: State<'_, AppState>,
    account: u16,
) -> Result<ClaudeLoginView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    csq_core::oauth::login::start_login(&state.oauth_store, account_num)
        .map(ClaudeLoginView::from)
        .map_err(|e| e.to_string())
}

/// Runs `claude auth login` subprocess for the given account slot,
/// using an absolute path to the `claude` binary so the call works
/// in the Finder-launched desktop bundle (which doesn't inherit the
/// user's shell `PATH`).
///
/// Returns `CLAUDE_NOT_FOUND` if no `claude` install can be located
/// in `$PATH` or any of the well-known directories searched by
/// [`csq_core::accounts::login::find_claude_binary`]. The frontend
/// uses that tag to fall back to the in-process paste-code flow.
///
/// This is a BLOCKING command — runs on a Tokio blocking worker so
/// it doesn't freeze the Tauri event loop. The OAuth handshake is
/// owned entirely by the spawned `claude` process: it opens a
/// browser, captures the callback, writes `.credentials.json` into
/// the supplied `CLAUDE_CONFIG_DIR`. csq just reads the file after
/// the subprocess exits and mirrors it to `credentials/N.json`.
///
/// On 3P import, the daemon's account-discovery cache is invalidated
/// so the dashboard sees the new account on its next 5s poll.
///
/// # Legacy shell-out path
///
/// As of v2.4 the default Claude OAuth path is the in-process
/// parallel-race flow (see [`race::start_claude_login_race`]). This
/// shell-out command is preserved as an emergency-rollback knob,
/// invocable via `force_legacy_shell: true` from a future Settings
/// toggle if the in-process race regresses on a particular host /
/// browser combination. The frontend does not reach this path
/// during normal operation.
#[tauri::command]
#[allow(dead_code)]
pub async fn start_claude_login(base_dir: String, account: u16) -> Result<u16, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = std::path::PathBuf::from(&base_dir);

    // GH an internal ticket: the reverse conflict guard that used to run here
    // (redteam R3) is retired — a stale Gemini/native marker is now detected
    // pre-mint and cleared on the SUCCESS path by `finalize_login`
    // (`binding_guard::detect_stale_marker_binding` +
    // `clear_detected_marker_binding`) rather than refused up-front. See
    // those functions' doc comments.

    tokio::task::spawn_blocking(move || {
        // Resolve `claude` via the shared finder before we start
        // creating state — there's no point provisioning a new
        // config dir if the binary is missing.
        let claude_bin = csq_core::accounts::login::find_claude_binary().ok_or_else(|| {
            "CLAUDE_NOT_FOUND: could not locate the `claude` binary in $PATH or any standard install location".to_string()
        })?;

        let config_dir = base.join(format!("config-{}", account_num));
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| format!("failed to create config dir: {e}"))?;

        // NOTE: the `.csq-account` marker is written LATER — only after the
        // credential read + save succeed (see below). Writing it here, before
        // the subprocess and `read_fresh_after_login` (which can now return
        // Err(OnlyStale/NoCredentials)), would leave an orphan marker the
        // daemon's discovery treats as a credential-less account — the M8 /
        // REV-R1-02 bug the live CLI path (handle_direct_post_subprocess) fixed
        // by ordering marker-after-save.

        // Run claude auth login with isolated config dir, calling
        // by absolute path so the Finder-default $PATH gap can't
        // bite us.
        let status = std::process::Command::new(&claude_bin)
            .args(["auth", "login"])
            .env("CLAUDE_CONFIG_DIR", &config_dir)
            .status()
            .map_err(|e| format!("failed to run `claude auth login`: {e}"))?;

        if !status.success() {
            return Err("claude auth login failed or was cancelled".to_string());
        }

        // CC's modern `claude auth login` commits the freshly minted token to
        // the macOS Keychain, and that write can land a beat AFTER the
        // subprocess exits. `read_fresh_after_login` reads both keychain and
        // file, keeps whichever has the later `expiresAt`, retries to let CC
        // commit, and errors rather than persisting a stale token — the same
        // hardening as the live CLI + desktop-twin login paths
        // (`csq_core::credentials::post_login`). This `start_claude_login`
        // entry point is a dormant `#[allow(dead_code)]` rollback knob, but it
        // is hardened identically so re-enabling it can never re-introduce the
        // keychain-commit-race bug. Already inside `spawn_blocking`, so the
        // synchronous retry helper is fine here.
        let creds = csq_core::credentials::read_fresh_after_login(&config_dir)
            .map_err(|e| e.to_string())?;

        // an internal ticket: mint the slot's identity UUID BEFORE save_canonical_for
        // (which is fail-closed on an absent UUID, M4-12). Mirrors the two live
        // login twins (CLI handle_direct_post_subprocess + desktop
        // start_claude_login_subprocess) so re-enabling this rollback knob can't
        // hit the fresh-install / keychain-only "no credentials configured"
        // failure. Idempotent + no-op when already minted or no email source.
        csq_core::accounts::login::ensure_login_identity_minted(&base, account_num)
            .map_err(|e| format!("mint identity: {e}"))?;

        // Save canonical (UUID-keyed path; M4-12: fail-closed if UUID absent)
        credentials::save_canonical_for(&base, account_num, &creds)
            .map_err(|e| format!("credential write failed: {e}"))?;

        // Mark this dir with the account number — AFTER the credential read +
        // save succeed (M8 / REV-R1-02 ordering, mirroring the live CLI path).
        // M4-7: identity UUID if `by_slot` maps; otherwise legacy decimal.
        match csq_core::accounts::profiles::resolve_slot_to_uuid(&base, account_num.get()) {
            Some(uuid) => csq_core::accounts::markers::write_csq_account(&config_dir, uuid)
                .map_err(|e| format!("failed to write marker: {e}"))?,
            None => csq_core::accounts::markers::write_csq_account_legacy(&config_dir, account_num)
                .map_err(|e| format!("failed to write marker: {e}"))?,
        }

        // profiles.json email update + broker-failed clear — shared with
        // `csq login` so the dashboard sees the real email instead of "unknown".
        csq_core::accounts::login::finalize_login(&base, account_num)
            .map_err(|e| format!("post-login bookkeeping failed: {e}"))?;

        // Tell the daemon its account-discovery cache is stale so
        // get_accounts picks up the new slot on the dashboard's
        // next 5s poll.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base);
            if sock.exists() {
                let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
            }
        }

        Ok(account_num.get())
    })
    .await
    .map_err(|e| format!("login task failed: {e}"))?
}

/// Submits a paste-code from Anthropic's OAuth callback page and
/// exchanges it for a credential file.
///
/// The frontend calls this after the user completes the browser
/// authorization and pastes the displayed code. This command:
///
/// 1. Consumes the pending PKCE state entry keyed by `state_token`
///    (rejects missing, expired, or already-consumed entries)
/// 2. Calls [`csq_core::oauth::exchange_code`] with the code, the
///    recovered verifier, and the paste-code redirect URI (must be
///    byte-identical to what the authorize URL advertised)
/// 3. Writes the resulting credential file to
///    `credentials/N.json` with 0o600 permissions
/// 4. Returns the account number so the frontend can refresh the
///    account list and show a success toast
///
/// # Errors
///
/// - `"invalid code: ..."` — empty or whitespace-only paste input
/// - `"no matching login: ..."` — state token not recognized
///   (wrong paste window, already submitted, or TTL expired)
/// - `"exchange failed: ..."` — Anthropic rejected the code or
///   returned a malformed token response
/// - `"credential write failed: ..."` — disk error during save
///
/// All error messages are pre-redacted — the underlying
/// `OAuthError` types already run response bodies through
/// `redact_tokens`, so it is safe to surface the message to the
/// frontend and the log.
#[tauri::command]
#[allow(dead_code)]
pub async fn submit_oauth_code(
    state: State<'_, AppState>,
    base_dir: String,
    state_token: String,
    code: String,
) -> Result<u16, String> {
    // Clean the pasted code: strip whitespace and CR (Windows paste).
    // Anthropic authorization codes can contain `#` characters, so
    // we must NOT strip at `#` — doing so truncates the code and
    // causes the exchange to fail.
    let code = code.trim().trim_end_matches('\r').to_string();
    if code.is_empty() {
        return Err("invalid code: paste was empty".into());
    }

    // Consume the pending PKCE state. `consume` is the authentication
    // boundary: only a caller holding the exact state token that was
    // issued at `start_claude_login` time can retrieve the verifier.
    let pending = state
        .oauth_store
        .consume(&state_token)
        .map_err(|e| format!("no matching login: {e}"))?;

    // GH an internal ticket: the reverse conflict guard that used to run here
    // (redteam R3) is retired — a stale Gemini/native marker is now detected
    // pre-mint and cleared on the SUCCESS path by `finalize_login`
    // (`binding_guard::detect_stale_marker_binding` +
    // `clear_detected_marker_binding`) rather than refused up-front. See
    // those functions' doc comments.

    // Run the blocking token exchange on a worker thread so we
    // don't freeze the Tauri event loop during the HTTP call.
    let base_dir_clone = base_dir.clone();
    tokio::task::spawn_blocking(move || {
        let credential = exchange_code(
            &code,
            &pending.code_verifier,
            PASTE_CODE_REDIRECT_URI,
            csq_core::http::post_json_node,
        )
        .map_err(|e| format!("exchange failed: {e}"))?;

        // Persist to `credentials/N.json` via the canonical helper
        // which handles atomic replace + 0o600 permissions.
        let base = PathBuf::from(&base_dir_clone);
        if !base.is_dir() {
            return Err(format!("base directory does not exist: {base_dir_clone}"));
        }

        credentials::save_canonical_for(&base, pending.account, &credential)
            .map_err(|e| format!("credential write failed: {e}"))?;

        // Mirror the start_claude_login bookkeeping so the paste-code
        // path also populates profiles.json. In this branch CC did
        // NOT run, so `.claude.json` is unlikely to exist with an
        // emailAddress field — finalize_login falls back to "unknown"
        // gracefully and still writes the marker + clears the
        // broker-failed flag.
        // RN1-C: finalize_login now propagates the UUID credential seed error
        // fail-closed. Discard the Ok(email) string but propagate Err.
        csq_core::accounts::login::finalize_login(&base, pending.account)
            .map_err(|e| format!("post-login bookkeeping failed: {e}"))?;

        // Tell the daemon its account-discovery cache is stale.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base);
            if sock.exists() {
                let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
            }
        }

        Ok(pending.account.get())
    })
    .await
    .map_err(|e| format!("exchange task failed: {e}"))?
}

/// Cancels a pending login by consuming its state token from the
/// store. Used when the user closes the Add Account modal before
/// submitting a code.
///
/// Returns `Ok(())` even if the token was not found — a concurrent
/// callback may have already consumed it, which is not an error
/// from the user's perspective.
#[tauri::command]
#[allow(dead_code)]
pub fn cancel_login(state: State<'_, AppState>, state_token: String) -> Result<(), String> {
    // `consume` returns the pending entry on success, or a
    // StateMismatch / StateExpired error if the token was already
    // consumed or evicted. All three outcomes are "the token no
    // longer does anything" from the caller's perspective — exactly
    // what cancel means — so we classify explicitly rather than use
    // a blanket discard.
    match state.oauth_store.consume(&state_token) {
        Ok(_pending) => {
            // Token was still pending; now cancelled.
            Ok(())
        }
        Err(csq_core::error::OAuthError::StateMismatch) => {
            // Already consumed by a racing callback, or never valid.
            // Idempotent from the user's perspective.
            Ok(())
        }
        Err(csq_core::error::OAuthError::StateExpired { .. }) => {
            // TTL elapsed. Same effective outcome — the token is
            // gone from the store.
            Ok(())
        }
        // Fixed-vocabulary fallback to avoid leaking `OAuthError::Http { body }`
        // or `OAuthError::Exchange(String)` content through the IPC
        // response if a future refactor widens `consume`'s error
        // surface. an internal journal entry M1.
        Err(csq_core::error::OAuthError::Http { .. }) => Err("cancel failed: http_error".into()),
        Err(csq_core::error::OAuthError::PkceVerification) => {
            Err("cancel failed: pkce_verification".into())
        }
        Err(csq_core::error::OAuthError::Exchange(_)) => {
            Err("cancel failed: exchange_failed".into())
        }
        // The race-only error variants cannot be returned from
        // `consume` (they're set by the orchestrator/exchange paths),
        // but listing them keeps the match exhaustive so a future
        // widening of `consume` surfaces a typed error here rather
        // than at runtime.
        Err(csq_core::error::OAuthError::Cancelled) => Err("cancel failed: cancelled".into()),
        Err(csq_core::error::OAuthError::StoreAtCapacity { .. }) => {
            Err("cancel failed: store_at_capacity".into())
        }
        Err(csq_core::error::OAuthError::ExchangeTimeout { .. }) => {
            Err("cancel failed: exchange_timeout".into())
        }
        // SEC-R2-01: this variant is set by the desktop race path,
        // not by `consume`. Listed for exhaustiveness so a future
        // widening of `consume`'s error surface to include it
        // surfaces a typed error here.
        Err(csq_core::error::OAuthError::LoginInProgressElsewhere { .. }) => {
            Err("cancel failed: login_in_progress".into())
        }
    }
}

/// Sets the API key for a bearer-auth provider (MiniMax, Z.AI).
///
/// Wraps [`providers::settings::save_settings`] with validation
/// matching the CLI `csq setkey` command. The key is never echoed
/// back to the caller — only a masked fingerprint of the stored
/// key.
///
/// # Errors
///
/// - `"unknown provider: X"` — provider id not in catalog
/// - `"provider X uses OAuth, not API keys"` — wrong flow for Claude
/// - `"provider X does not use API keys"` — keyless provider
/// - `"key must not be empty"` — empty input
/// - `"key too short ..."` — fewer than 8 bytes after trimming
/// - `"key contains control characters ..."` — control byte in key
/// - `"key too long"` — input >4096 bytes
#[tauri::command]
pub fn set_provider_key(
    base_dir: String,
    provider_id: String,
    key: String,
) -> Result<String, String> {
    // 4096 matches MAX_KEY_LEN in csq-cli setkey.
    const MAX_KEY_LEN: usize = 4096;
    // Mirrors csq_core::accounts::third_party::MIN_KEY_LEN (an internal journal entry).
    // Defense in depth against ESC / garbage tokens slipping through the
    // Bearer form's input box.
    const MIN_KEY_LEN: usize = 8;

    let provider = providers::get_provider(&provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;

    match provider.auth_type {
        providers::catalog::AuthType::OAuth => {
            return Err(format!(
                "provider {provider_id} uses OAuth, not API keys — use start_claude_login instead"
            ));
        }
        providers::catalog::AuthType::None => {
            return Err(format!("provider {provider_id} does not use API keys"));
        }
        providers::catalog::AuthType::Bearer => {}
    }

    let key = key.trim().trim_end_matches('\r').to_string();
    if key.is_empty() {
        return Err("key must not be empty".into());
    }
    if key.len() > MAX_KEY_LEN {
        return Err(format!("key too long (limit {MAX_KEY_LEN} bytes)"));
    }
    if key.len() < MIN_KEY_LEN {
        return Err(format!("key too short (need at least {MIN_KEY_LEN} bytes)"));
    }
    if key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("key contains control characters — check your clipboard and try again".into());
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let mut settings = providers::settings::load_settings(&base, &provider_id)
        .map_err(|e| format!("load settings: {}", e.redacted_message()))?;
    settings
        .set_api_key(&key)
        .map_err(|e| format!("set key: {}", e.redacted_message()))?;
    providers::settings::save_settings(&base, &settings)
        .map_err(|e| format!("save settings: {}", e.redacted_message()))?;

    Ok(settings.key_fingerprint())
}

/// Binds a keyed (Bearer) provider to a slot, writing the per-slot
/// `config-<slot>/settings.json` with `env.ANTHROPIC_BASE_URL` /
/// `env.ANTHROPIC_AUTH_TOKEN` / `env.ANTHROPIC_*_MODEL`. Companion to
/// [`set_provider_key`] (which writes the global `settings-{provider}.json`):
/// the Add Account modal MUST call both for a Bearer provider — the
/// global file feeds `csq listkeys` and the per-slot file is what
/// `discover_per_slot_third_party` walks for the slot list.
///
/// Originating bug (this session, 2026-05-08): `submitBearerKey`
/// called only `set_provider_key`, so a freshly-added DeepSeek slot
/// did not surface in the dashboard — the global key file was
/// written but the slot's `config-N/settings.json` was never created.
///
/// Thin wrapper around
/// [`csq_core::accounts::third_party::bind_provider_to_slot`] with
/// `key = Some(...)`. Input validation mirrors [`set_provider_key`].
#[tauri::command]
pub fn bind_keyed_provider(
    base_dir: String,
    provider_id: String,
    slot: u16,
    key: String,
    model: Option<String>,
) -> Result<(), String> {
    const MAX_KEY_LEN: usize = 4096;
    const MIN_KEY_LEN: usize = 8;

    let provider = providers::get_provider(&provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;
    if provider.auth_type != providers::catalog::AuthType::Bearer {
        return Err(format!(
            "provider {provider_id} is not a Bearer provider — use \
             bind_keyless_provider for keyless or start_claude_login for OAuth"
        ));
    }

    let slot =
        csq_core::types::AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;

    let key = key.trim().trim_end_matches('\r').to_string();
    if key.is_empty() {
        return Err("key must not be empty".into());
    }
    if key.len() > MAX_KEY_LEN {
        return Err(format!("key too long (limit {MAX_KEY_LEN} bytes)"));
    }
    if key.len() < MIN_KEY_LEN {
        return Err(format!("key too short (need at least {MIN_KEY_LEN} bytes)"));
    }
    if key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("key contains control characters — check your clipboard and try again".into());
    }

    let model = match model {
        Some(m) => {
            let trimmed = m.trim();
            if trimmed.is_empty() {
                return Err("model must not be empty".into());
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    csq_core::accounts::third_party::bind_provider_to_slot(
        &base,
        &provider_id,
        slot,
        Some(&key),
        model.as_deref(),
    )
    .map_err(|e| format!("bind provider to slot: {}", e.redacted_message()))
}

/// Binds a keyless provider (Ollama) to an account slot, optionally
/// with a user-selected model.
///
/// The UI flow calls this when the user picks Ollama from the Add
/// Account modal — there is no key to enter, but the user MAY have
/// multiple models installed locally (`ollama list`). Passing `model`
/// overrides the catalog default (currently `gemma4`) and is written
/// verbatim to every `ANTHROPIC_*_MODEL` env key. Omit to accept the
/// default.
///
/// Thin wrapper around [`csq_core::accounts::third_party::bind_provider_to_slot`]
/// with `key = None`, plus input validation (bounds on slot, existence
/// of base dir, provider must be keyless, model non-empty when given).
///
/// # Errors
///
/// - `"unknown provider: X"` — provider id not in catalog
/// - `"provider X is not keyless"` — called on a keyed provider
/// - `"invalid slot: ..."` — slot out of range 1..=999
/// - `"model must not be empty"` — model override supplied but blank
/// - `"base directory does not exist: ..."` — base dir missing
/// - filesystem errors surfaced from the core bind path
#[tauri::command]
pub fn bind_keyless_provider(
    base_dir: String,
    provider_id: String,
    slot: u16,
    model: Option<String>,
) -> Result<(), String> {
    let provider = providers::get_provider(&provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;

    if provider.auth_type != providers::catalog::AuthType::None {
        return Err(format!("provider {provider_id} is not keyless"));
    }

    let slot =
        csq_core::types::AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;

    let model = match model {
        Some(m) => {
            let trimmed = m.trim();
            if trimmed.is_empty() {
                return Err("model must not be empty".into());
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    csq_core::accounts::third_party::bind_provider_to_slot(
        &base,
        &provider_id,
        slot,
        None,
        model.as_deref(),
    )
    .map_err(|e| format!("bind provider: {}", e.redacted_message()))
}

/// Returns the list of locally-installed Ollama models by running
/// `ollama list`. Returns an empty list if Ollama is not installed
/// or has no models pulled — the frontend treats empty as a prompt
/// to `ollama pull <model>` before retrying.
///
/// Wraps [`csq_core::providers::ollama::get_ollama_models`]; errors
/// from the subprocess (not-found, non-zero exit) collapse into an
/// empty list so a missing Ollama install surfaces as "no models
/// found" rather than a hang.
#[tauri::command]
pub fn list_ollama_models() -> Result<Vec<String>, String> {
    Ok(providers::ollama::get_ollama_models())
}

/// Retargets a slot's `config-<slot>/settings.json` to a new model
/// by rewriting every `ANTHROPIC_*_MODEL` env key.
///
/// The slot must already be bound (via `bind_keyless_provider` or
/// `setkey` on the CLI). This is the runtime model-change path
/// for Ollama slots whose installed model list expands post-bind.
/// Same semantics as the CLI's `csq models switch <provider> <model>
/// --slot N --no-pull`: we assume any required pull has already
/// happened via [`pull_ollama_model`].
///
/// # Errors
///
/// - `"invalid slot: ..."` — slot out of range 1..=999
/// - `"model must not be empty"` — blank input
/// - `"base directory does not exist: ..."` — base dir missing
/// - `"slot N is not bound — ..."` — slot has no settings.json
/// - filesystem errors surfaced from the atomic-write path
///
/// M2-7: delegates to the shared UUID-routing chokepoint in csq-core.
///
/// Previously this function hardcoded `config-{slot}/settings.json` and
/// bypassed UUID-canonical routing entirely. Replaced by a thin wrapper
/// over `csq_core::session::write_slot_model_with_uuid_routing` so CLI and
/// desktop use exactly the same Phase 2 logic.
///
/// See `csq-core/src/session/settings.rs` for implementation and
/// `internal-design-docs § M2-7`
/// for the M2-7 READER routing contract.
pub fn set_slot_model_write(base_dir: String, slot: u16, model: String) -> Result<(), String> {
    let slot_num =
        csq_core::types::AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("model must not be empty".into());
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    csq_core::session::write_slot_model_with_uuid_routing(&base, slot_num, &model)
}

#[tauri::command]
pub fn set_slot_model(
    app: AppHandle,
    base_dir: String,
    slot: u16,
    model: String,
) -> Result<(), String> {
    set_slot_model_write(base_dir, slot, model.clone())?;
    // Notify any other listening window / tray menu that the slot
    // changed, so they can refresh their view. Best-effort: a
    // failed emit doesn't undo the successful file write.
    let _ = app.emit(
        "slot-model-changed",
        serde_json::json!({ "slot": slot, "model": model }),
    );
    Ok(())
}

/// Fetches an Ollama model via `ollama pull <model>`, streaming
/// progress segments back to the frontend on the
/// `ollama-pull-progress` Tauri event so the UI can render a
/// progress indicator. Returns once the pull subprocess exits.
///
/// **Streaming**: ollama renders progress as a single line
/// updated with carriage returns, not newlines. A naive
/// `BufRead::lines()` reader would buffer the entire pull into
/// one string and never emit anything until completion. This
/// function instead reads bytes and flushes a payload on either
/// `\r` or `\n`, so the UI sees live progress bars.
///
/// **Cancellation**: the running child is registered in
/// `AppState.ollama_pull_child` so a later `cancel_ollama_pull`
/// command can send SIGTERM and release the UI from a stuck
/// (or unwanted) download. Normal completion clears the handle.
///
/// **Pre-check**: if the `ollama` binary is not on PATH we fail
/// fast with an installable-ness hint rather than letting the
/// user wait on a silent exec failure.
///
/// Failure modes:
///   - `ollama` binary not found → `"ollama not found: ..."`
///   - non-zero exit from the pull → `"ollama pull exited with N"`
///     (if the exit was SIGTERM from cancel_ollama_pull the
///     payload matches `"ollama pull exited with -1"` or a
///     signal code; the frontend treats any non-zero exit the
///     same — back to the picker screen).
#[tauri::command]
pub async fn pull_ollama_model(
    app: AppHandle,
    state: State<'_, AppState>,
    model: String,
) -> Result<(), String> {
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("model must not be empty".into());
    }

    // Pre-check: resolve the ollama binary. A Finder-launched macOS
    // GUI inherits `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, so bare
    // `Command::new("ollama")` fails to locate the binary at the
    // usual Homebrew prefixes. `find_ollama_bin` walks the known
    // install paths and honours the `OLLAMA_BIN` override.
    let ollama_bin = match providers::ollama::find_ollama_bin() {
        Some(p) if p.is_file() => p,
        _ => {
            return Err(
                "ollama not found — install via https://ollama.com or set OLLAMA_BIN".into(),
            );
        }
    };
    if std::process::Command::new(&ollama_bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return Err("ollama not found — install via https://ollama.com or set OLLAMA_BIN".into());
    }

    // Capture the child-slot Arc BEFORE `spawn_blocking` so the
    // worker thread doesn't need to borrow `State<AppState>`.
    let child_slot = state.ollama_pull_child.clone();

    tauri::async_runtime::spawn_blocking(move || {
        pull_ollama_model_blocking(app, child_slot, ollama_bin, model)
    })
    .await
    .map_err(|e| format!("pull task join error: {e}"))?
}

/// Pure-Rust body of `pull_ollama_model` (no Tauri traits) so it
/// can be invoked from `spawn_blocking` without the caller
/// holding a `State<AppState>` borrow.
fn pull_ollama_model_blocking(
    app: AppHandle,
    child_slot: Arc<std::sync::Mutex<Option<Arc<std::sync::Mutex<std::process::Child>>>>>,
    ollama_bin: std::path::PathBuf,
    model: String,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(&ollama_bin)
        .arg("pull")
        .arg(&model)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn ollama pull: {e}"))?;

    let stderr = child.stderr.take();
    let stdout = child.stdout.take();
    let child_arc = Arc::new(std::sync::Mutex::new(child));

    // Register for cancel. Overwrite any stale entry — the
    // frontend guards against concurrent pulls, but defence
    // in depth doesn't hurt here.
    {
        let mut slot = child_slot.lock().map_err(|_| "child slot poisoned")?;
        *slot = Some(child_arc.clone());
    }

    let stderr_t = spawn_progress_reader(stderr, "stderr", app.clone());
    let stdout_t = spawn_progress_reader(stdout, "stdout", app.clone());

    // Wait for the child to exit (or be killed via cancel).
    let status = {
        let mut guard = child_arc.lock().map_err(|_| "child lock poisoned")?;
        guard
            .wait()
            .map_err(|e| format!("wait on ollama pull: {e}"))?
    };

    if let Some(t) = stderr_t {
        let _ = t.join();
    }
    if let Some(t) = stdout_t {
        let _ = t.join();
    }

    {
        let mut slot = child_slot.lock().map_err(|_| "child slot poisoned")?;
        *slot = None;
    }

    if !status.success() {
        return Err(format!(
            "ollama pull exited with {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Byte-level progress reader. `ollama pull` updates a single
/// progress line with carriage returns, not newlines, so a
/// standard `BufRead::lines()` reader would buffer the entire
/// multi-gigabyte download into one string. This function reads
/// bytes and flushes on either `\r` or `\n` so the UI sees live
/// progress. The 1 MiB buffer cap is a defence against a stream
/// that never emits a delimiter.
fn spawn_progress_reader(
    stream: Option<impl std::io::Read + Send + 'static>,
    tag: &'static str,
    app: AppHandle,
) -> Option<std::thread::JoinHandle<()>> {
    let mut stream = stream?;
    Some(std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(2048);
        let mut byte = [0u8; 1];
        let flush = |buf: &mut Vec<u8>, app: &AppHandle| {
            if buf.is_empty() {
                return;
            }
            let line = String::from_utf8_lossy(buf).to_string();
            let _ = app.emit(
                "ollama-pull-progress",
                serde_json::json!({ "stream": tag, "line": line }),
            );
            buf.clear();
        };
        loop {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    let b = byte[0];
                    if b == b'\r' || b == b'\n' {
                        flush(&mut buf, &app);
                    } else {
                        buf.push(b);
                        if buf.len() >= 1 << 20 {
                            flush(&mut buf, &app);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        flush(&mut buf, &app);
    }))
}

/// Cancels an in-flight `ollama pull` by killing the child
/// process. No-op when no pull is running — the modal's Cancel
/// button calls this unconditionally, and the frontend treats a
/// successful cancel as "return to picker".
///
/// Uses `Child::kill` (SIGKILL on Unix, TerminateProcess on
/// Windows). The companion `pull_ollama_model` reader threads
/// see EOF on their piped stdout/stderr and exit cleanly; the
/// `wait()` call in the blocking task returns a non-success
/// status which the frontend maps to the error banner.
#[tauri::command]
pub fn cancel_ollama_pull(state: State<'_, AppState>) -> Result<(), String> {
    let handle_opt = {
        let slot = state
            .ollama_pull_child
            .lock()
            .map_err(|_| "child slot poisoned")?;
        slot.clone()
    };
    let Some(handle) = handle_opt else {
        return Ok(());
    };
    let mut child = handle.lock().map_err(|_| "child lock poisoned")?;
    let _ = child.kill();
    Ok(())
}

// ── Launch-on-login (tauri-plugin-autostart) ──────────────────

/// Returns whether the csq desktop app is registered to auto-start
/// at OS login.
///
/// Reads the platform-native registration state:
/// - **macOS**: `~/Library/LaunchAgents/<bundle-id>.plist`
/// - **Windows**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<bundle-id>`
/// - **Linux**: `~/.config/autostart/<bundle-id>.desktop`
///
/// All three paths are abstracted by `tauri-plugin-autostart`.
/// Returns `false` on any read error so the UI defaults to "off"
/// rather than displaying stale information.
#[tauri::command]
pub fn get_autostart_enabled(app: AppHandle) -> Result<bool, String> {
    app.autolaunch()
        .is_enabled()
        .map_err(|e| format!("failed to read autostart state: {e}"))
}

/// Enables or disables launch-on-login for the csq desktop app.
///
/// Writes the platform-native registration as described in
/// `get_autostart_enabled`. Takes effect on the next login (no
/// need to log out and back in now — the change persists).
///
/// Idempotent: enabling when already enabled, or disabling when
/// already disabled, is a no-op on all three platforms.
#[tauri::command]
pub fn set_autostart_enabled(app: AppHandle, enabled: bool) -> Result<(), String> {
    let autolaunch = app.autolaunch();
    if enabled {
        autolaunch
            .enable()
            .map_err(|e| format!("failed to enable autostart: {e}"))
    } else {
        autolaunch
            .disable()
            .map_err(|e| format!("failed to disable autostart: {e}"))
    }
}

// ── Dock-icon hide (macOS Accessory policy) ──────────────────────
//
// User-toggleable: hide csq's Dock icon, Cmd-Tab entry, and the
// menubar application menu by switching the app's
// NSApplicationActivationPolicy from `Regular` to `Accessory`. The
// menubar tray icon remains the only UI surface (Ollama-style).
//
// Persistence: `<base>/desktop-prefs.json` via
// `crate::desktop::preferences::{load,save}_desktop_prefs`.
// Runtime: `AppHandle::set_activation_policy(...)` on macOS only;
// Windows / Linux no-op the runtime call but still persist the pref
// for shape-consistency across platforms (a future user switching
// hosts should not lose their preference).
//
// See `internal-design-docs` for
// the API-choice rationale (Accessory vs `set_dock_visibility(false)`).

/// Returns whether the running platform supports the dock-hide
/// feature. This is a compile-time constant matching the target
/// triple — `true` only for the macOS binary; `false` for every
/// other target. The frontend uses this to gate visibility of the
/// "Hide Dock icon" toggle so Windows and Linux users do not see
/// a control that would persist a preference but have no runtime
/// effect.
///
/// Doc clarification per R1 redteam Finding T-8: the docstring
/// formerly implied a runtime guard, but `cfg!(target_os = "macos")`
/// resolves at build time, not at runtime. The macOS x86_64 and
/// arm64 binaries both return `true`; the Linux and Windows binaries
/// both return `false`. Cross-compilation does not affect runtime
/// dispatch — the binary already knows its target.
#[tauri::command]
pub fn is_dock_hide_supported() -> Result<bool, String> {
    Ok(cfg!(target_os = "macos"))
}

/// Returns whether the user has chosen to hide the Dock icon. Reads
/// the persisted preference from `<base>/desktop-prefs.json`. Returns
/// `false` (default) when the file does not exist or is corrupt —
/// the historical foreground-app behaviour.
///
/// The returned value reflects the *persisted intent*. Runtime
/// divergence is possible at two narrow windows:
///
/// 1. **Startup apply failure**: if `apply_dock_hidden_policy` at
///    startup fails (rare — typically a macOS-version bug in the
///    AppKit call), the disk holds the user's intent but the
///    runtime stays at Tauri's default `Regular`. Logged and the
///    user can re-toggle.
/// 2. **Save failure after successful runtime apply**: R2 LOW-1
///    rolls back the runtime in this case so disk and runtime
///    stay in sync. Both end up at the pre-flip state and the
///    Err disclosure tells the user the save failed.
#[tauri::command]
pub fn get_dock_hidden(base_dir: String) -> Result<bool, String> {
    let base = resolve_csq_base_dir(&base_dir)?;
    Ok(crate::desktop::preferences::load_desktop_prefs(&base)
        .0
        .hide_dock_icon)
}

/// Resolves and validates a user-supplied `base_dir` against the
/// canonical csq accounts directory. Per R1 redteam Finding S-H1,
/// the renderer must NOT be able to persist `desktop-prefs.json`
/// outside the csq state root. Returns the validated path on match
/// or an Err with no path leakage.
///
/// The frontend always passes `~/.claude/accounts` (or honors
/// `CSQ_BASE_DIR` during integration testing). Anything that
/// resolves to a different absolute path is rejected.
///
/// R2 redteam Finding R2-HIGH-1: the original shape pre-required
/// `supplied.is_dir()` to be true, which blocked the fresh-install
/// case where `~/.claude/accounts` does not yet exist. R1 Finding
/// S-M3 designed the Header frontend to allow the toggle on fresh
/// installs and rely on `save_desktop_prefs`'s
/// `create_dir_all(parent)` to bootstrap on first write. That
/// bootstrap was structurally unreachable until this resolver
/// tolerated the not-yet-existent case for paths lexically equal
/// to `base_dir()`.
fn resolve_csq_base_dir(base_dir: &str) -> Result<PathBuf, String> {
    let supplied = PathBuf::from(base_dir);
    let expected =
        crate::desktop::base_dir().ok_or_else(|| "csq base directory unavailable".to_string())?;

    // Fast path — lexical equality. Tolerates the fresh-install
    // case where `expected` does not yet exist on disk. The S-H1
    // path-traversal defense is preserved: an attacker supplying
    // `/etc` or `~/.ssh` does NOT lexically match the resolved
    // `~/.claude/accounts`, and falls through to the canonicalize
    // path below which will reject the mismatch.
    if supplied == expected {
        return Ok(supplied);
    }

    // Slow path — canonicalize and compare. Resolves symlinks so
    // a user with `~` on an external drive is not falsely rejected.
    // Either side may fail to canonicalize (path does not exist);
    // in that case we treat the failed canonicalization as identity
    // (the lexical fast path above already covered the equal-but-
    // nonexistent case, so this branch sees a real mismatch).
    let supplied_canon = std::fs::canonicalize(&supplied).unwrap_or_else(|_| supplied.clone());
    let expected_canon = std::fs::canonicalize(&expected).unwrap_or_else(|_| expected.clone());
    if supplied_canon != expected_canon {
        return Err("base_dir does not match the resolved csq accounts directory".to_string());
    }
    Ok(supplied_canon)
}

/// Applies the runtime activation policy AND persists the dock-hide
/// preference. Per R1 redteam Finding S-H3, the runtime call happens
/// FIRST, then the disk write. This means:
///
/// - Policy-apply failure → no disk change. User sees an Err and
///   their visible state is unchanged. The next restart preserves
///   the prior state.
/// - Disk-save failure → runtime has the new policy applied for the
///   current session, but the next restart will revert. The user
///   sees an Err with that disclosure in the message.
///
/// Tray click and IPC paths both go through this function via
/// `crate::desktop::apply_and_persist_dock_hidden` so the
/// `desktop_prefs_lock` mutex serializes concurrent writers
/// (Finding S-H2 / T-5).
///
/// Returns the saved value (server-side echo) so the frontend can
/// confirm the round-trip without a follow-up `get_*` call.
#[tauri::command]
pub fn set_dock_hidden(
    app: AppHandle,
    state: tauri::State<'_, crate::desktop::AppState>,
    base_dir: String,
    hidden: bool,
) -> Result<bool, String> {
    let base = resolve_csq_base_dir(&base_dir)?;
    crate::desktop::apply_and_persist_dock_hidden(&app, &state, &base, hidden)?;
    // R1 redteam Finding T-9: rebuild the tray menu after a
    // successful IPC toggle so the "Hide Dock icon" CheckMenuItem
    // reflects the new state immediately. Without this the tray
    // checkmark would lag the frontend toggle for up to 30s
    // (until the next refresh_tray_menu tick).
    if let Some(tray) = app.tray_by_id("main") {
        crate::desktop::refresh_tray_menu(&app, &tray);
    }
    Ok(hidden)
}

/// Returns the persisted `dashboard_at_launch` preference. Default `true`
/// (show the dashboard at app start) when the file is missing or corrupt,
/// preserving the classic desktop-app behavior.
#[tauri::command]
pub fn get_dashboard_at_launch(base_dir: String) -> Result<bool, String> {
    let base = resolve_csq_base_dir(&base_dir)?;
    Ok(crate::desktop::preferences::load_desktop_prefs(&base)
        .0
        .dashboard_at_launch)
}

/// Persists the `dashboard_at_launch` preference. The new value takes effect
/// at NEXT app launch — toggling at runtime does NOT immediately hide/show
/// the dashboard (that would be jarring UX from a settings popover). The
/// returned value is the server-side echo of the saved bool so the frontend
/// can confirm the round-trip without a follow-up `get_*` call.
///
/// Shares the `desktop_prefs_lock` mutex with the dock-hide writer so
/// concurrent toggles to either pref serialize cleanly.
#[tauri::command]
pub fn set_dashboard_at_launch(
    state: tauri::State<'_, crate::desktop::AppState>,
    base_dir: String,
    enabled: bool,
) -> Result<bool, String> {
    let base = resolve_csq_base_dir(&base_dir)?;
    crate::desktop::apply_and_persist_dashboard_at_launch(&state, &base, enabled)?;
    Ok(enabled)
}

/// Applies the activation policy to a live `AppHandle` AND issues
/// the show / hide window orchestration that the policy switch
/// requires for a clean UX.
///
/// - **Hide direction (`Regular → Accessory`)**: hide the main
///   window BEFORE the policy switch. On macOS Sonoma+ the Dock
///   icon otherwise lingers for 1-3s after `setActivationPolicy`
///   because the policy is honored on the next display-server
///   cycle (R1 redteam Finding T-3).
/// - **Show direction (`Accessory → Regular`)**: after restoring
///   `Regular` policy, call `show()` + `set_focus()` on the main
///   window. Tao's runtime `set_activation_policy` does NOT call
///   `NSApp.activate(ignoringOtherApps:)`, so the app's Dock icon
///   reappears but the app is not visible in Cmd-Tab until the
///   user triggers an activation event (R1 redteam Finding T-1).
///   Calling `show()` on a window triggers AppKit's activation
///   path which re-registers the app in Cmd-Tab immediately.
///
/// macOS-only effect; other platforms return `Ok(())` unconditionally.
pub(crate) fn apply_dock_hidden_policy(app: &AppHandle, hidden: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let policy = if hidden {
            tauri::ActivationPolicy::Accessory
        } else {
            tauri::ActivationPolicy::Regular
        };
        let label = if hidden { "Accessory" } else { "Regular" };
        if let Err(e) = app.set_activation_policy(policy) {
            log::warn!(
                target: "csq::desktop::commands",
                "set_activation_policy: error_kind=activation_policy_failed policy={label} error={e}"
            );
            return Err(format!("activation policy apply failed ({label}): {e}"));
        }
        // NOTE — window visibility is intentionally NOT touched here.
        //
        // Pre-refactor this function hid the window when entering Accessory
        // and re-showed it when returning to Regular. That conflated two
        // semantically distinct user preferences: "hide the Dock icon" and
        // "open the dashboard at launch". The user observed that checking
        // "Hide Dock icon" silently also hid the dashboard on every relaunch.
        //
        // Window visibility is now owned by `apply_dashboard_visibility`
        // (driven by `DesktopPrefs::dashboard_at_launch`) and by user-driven
        // events (tray click, window-close-to-tray). Dock-icon policy and
        // window visibility are orthogonal here; any combination is valid.
        //
        // The macOS quirk this previously worked around — entering Accessory
        // with a visible window can briefly linger the Dock icon for 1-3s —
        // is accepted as the cost of clean semantics for a settings toggle
        // the user changes rarely. The Dock icon does still disappear; it is
        // not stuck. R2-MED-1's `is_visible() == false` startup focus-steal
        // defense is no longer relevant here because this function never
        // calls `show()`/`set_focus()`.
    }
    // Suppress unused warnings on non-macOS targets.
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (app, hidden);
    }
    Ok(())
}

/// Applies the persisted `dashboard_at_launch` preference to the main
/// webview window. Idempotent — safe to call from startup or in response to
/// a runtime toggle (though the pref is consumed only at startup today; the
/// helper exists at runtime as a future hook).
///
/// `visible == true`: show the main window. Mirrors Tauri's default startup
/// behavior for `visible: true` windows, but called explicitly so the
/// startup sequence is deterministic regardless of `tauri.conf.json` window
/// defaults and regardless of which activation policy is in effect.
///
/// `visible == false`: hide the main window. Used when the user has opted
/// into the launch-into-tray mode — the app starts, the tray icon appears,
/// the dashboard stays hidden until the user clicks the tray icon.
///
/// All platforms: a no-op return-Ok if the window handle is unavailable
/// (the startup sequence shouldn't fault on missing-window — it's typically
/// the lifecycle being torn down, not a real error).
pub(crate) fn apply_dashboard_visibility(app: &AppHandle, visible: bool) -> Result<(), String> {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("main") {
        if visible {
            let _ = w.show();
        } else {
            let _ = w.hide();
        }
    }
    Ok(())
}

#[cfg(test)]
mod resolve_csq_base_dir_tests {
    //! Direct unit tests for the S-H1 path-traversal defense.
    //! These tests do not need an `AppHandle`; they exercise the
    //! pure `&str → Result<PathBuf, _>` resolver against the
    //! `CSQ_BASE_DIR` env-var injection used by integration tests.
    //!
    //! R3 redteam Finding LOW-1: the resolver previously had no
    //! direct test coverage. The four cases below correspond to
    //! the R3 review's case list (a/b/c/d).
    //!
    //! Run serially via a process-global mutex because they
    //! mutate `CSQ_BASE_DIR` and would race otherwise.
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_csq_base_dir<F: FnOnce() -> R, R>(value: &Path, f: F) -> R {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("CSQ_BASE_DIR");
        // SAFETY: Tests are serialized via ENV_LOCK; set_var is
        // sound in this single-threaded scope.
        unsafe {
            std::env::set_var("CSQ_BASE_DIR", value);
        }
        let out = f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("CSQ_BASE_DIR", v),
                None => std::env::remove_var("CSQ_BASE_DIR"),
            }
        }
        out
    }

    #[test]
    fn case_a_lexical_equal_and_exists_accepts() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        with_csq_base_dir(&path, || {
            let r = resolve_csq_base_dir(path.to_str().unwrap());
            assert!(r.is_ok(), "expected accept, got {r:?}");
            assert_eq!(r.unwrap(), path);
        });
    }

    #[test]
    fn case_b_lexical_equal_does_not_exist_accepts_fresh_install() {
        // R2-HIGH-1 — the fresh-install case must succeed.
        let dir = tempfile::TempDir::new().unwrap();
        let nonexistent = dir.path().join("fresh-install").join("accounts");
        assert!(!nonexistent.exists(), "precondition");
        with_csq_base_dir(&nonexistent, || {
            let r = resolve_csq_base_dir(nonexistent.to_str().unwrap());
            assert!(
                r.is_ok(),
                "expected accept for fresh-install path, got {r:?}"
            );
            assert_eq!(r.unwrap(), nonexistent);
        });
    }

    #[test]
    fn case_c_symlinked_path_canonicalizes_and_accepts() {
        // A user with `~/.claude/accounts` via a symlink to an
        // external drive: supplied is the symlinked path, expected
        // is the same symlinked path — they're lexically equal in
        // this scenario, so the fast path takes it. Force the
        // canonicalize fallback by supplying an alternate spelling
        // (here: a relative-then-resolved path).
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempfile::TempDir::new().unwrap();
            let target = dir.path().join("real");
            std::fs::create_dir(&target).unwrap();
            let link = dir.path().join("link");
            symlink(&target, &link).unwrap();
            // expected = link (the symlinked path), supplied = the
            // target's canonical form. canonicalize(link) ==
            // canonicalize(target) so this should accept.
            with_csq_base_dir(&link, || {
                let r = resolve_csq_base_dir(target.to_str().unwrap());
                assert!(
                    r.is_ok(),
                    "expected accept via canonicalize equivalence, got {r:?}"
                );
            });
        }
    }

    #[test]
    fn case_d_lexically_and_canonically_different_rejects() {
        // S-H1 path-traversal defense: an attacker supplying a
        // different absolute path MUST be rejected. Use `/tmp` as
        // the attacker-supplied path; expected is a tmpdir.
        let dir = tempfile::TempDir::new().unwrap();
        let expected_dir = dir.path().join("expected");
        std::fs::create_dir(&expected_dir).unwrap();
        with_csq_base_dir(&expected_dir, || {
            // `/tmp` exists on every Unix host the tests run on
            // and canonicalizes to itself — definitely NOT equal
            // to a fresh TempDir-resolved path.
            let r = resolve_csq_base_dir("/tmp");
            assert!(r.is_err(), "expected reject of /tmp, got {r:?}");
            // Error message must not leak the supplied path.
            let msg = r.unwrap_err();
            assert!(
                !msg.contains("/tmp"),
                "error message should not echo supplied path: {msg}"
            );
        });
    }

    #[test]
    fn case_e_relative_path_lexical_mismatch_rejects() {
        // Defense-in-depth: relative paths are NOT lexically
        // equal to absolute `~/.claude/accounts`, so they fall
        // through to canonicalize. The relative-resolved canonical
        // form may or may not equal expected — depends on CWD.
        // In any case, the resolver MUST not accept arbitrary
        // relative paths that happen to be a directory.
        let dir = tempfile::TempDir::new().unwrap();
        let expected_dir = dir.path().join("expected");
        std::fs::create_dir(&expected_dir).unwrap();
        with_csq_base_dir(&expected_dir, || {
            let r = resolve_csq_base_dir(".");
            // `.` canonicalizes to CWD; CWD != expected_dir (tmp),
            // so reject.
            assert!(r.is_err(), "expected reject of '.', got {r:?}");
        });
    }
}

// ── Update check ─────────────────────────────────────────────────
//
// These commands expose the CLI's update-check mechanism
// (`csq_core::update::check_for_update`) to the desktop frontend.
// They do NOT install updates — the signing key is a placeholder
// and `download_and_apply` rejects placeholder-signed releases.
// Instead, the frontend should notify the user and open the GitHub
// release page for manual install.

/// Current running csq version — read at compile time from the
/// workspace `Cargo.toml`. Shown in the "v{current} → v{latest}"
/// update banner so users can confirm the delta.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Triggers a synchronous GitHub Releases check.
///
/// Returns `Some(CachedUpdateInfo)` if a newer version is available,
/// `None` otherwise. Caches the result in `AppState` so the frontend
/// can re-read without re-polling. Network errors are surfaced as
/// `Err(String)` — the frontend decides whether to retry or hide the
/// banner.
#[tauri::command]
pub fn check_for_update(state: State<'_, AppState>) -> Result<Option<CachedUpdateInfo>, String> {
    // Edition independence (rules/independence.md): the update channel is the
    // COMMUNITY repo. Enterprise never queries it — the background loop that
    // drives the banner is already gated off, but this command is registered
    // for both editions, so short-circuit here too (defense in depth).
    if crate::BUILD_EDITION == "enterprise" {
        return Ok(None);
    }
    let info = match csq_core::update::check_for_update() {
        Ok(v) => v,
        Err(e) => return Err(format!("update check failed: {e}")),
    };

    let cached = info.map(|u| CachedUpdateInfo {
        version: u.version,
        current_version: CURRENT_VERSION.to_string(),
        release_url: u.html_url,
    });

    // Store in cache so get_update_status can return it without a
    // fresh network call. Lock held briefly; no await in scope.
    if let Ok(mut guard) = state.update_cache.lock() {
        *guard = cached.clone();
    }

    Ok(cached)
}

/// Returns the cached result of the most recent update check without
/// re-polling GitHub. Intended for frontend callers that want to
/// render the banner without paying network latency on every mount.
///
/// Returns `None` if no check has run yet OR the app is up to date.
/// Callers distinguish the two by calling `check_for_update` once at
/// startup (the desktop app does this automatically 10s after launch).
#[tauri::command]
pub fn get_update_status(state: State<'_, AppState>) -> Result<Option<CachedUpdateInfo>, String> {
    match state.update_cache.lock() {
        Ok(guard) => Ok(guard.clone()),
        Err(_) => Err("update cache lock poisoned".into()),
    }
}

/// Opens the GitHub release page for the cached update in the user's
/// default browser. The frontend calls this from the update banner's
/// "download" button. Manual install is the only option until the
/// Foundation's Ed25519 signing key is provisioned.
///
/// Returns `Err` if no update is cached (the button should be hidden
/// in that case — this guard is defense-in-depth, not a UX path).
#[tauri::command]
pub fn open_release_page(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    let url = {
        let guard = state
            .update_cache
            .lock()
            .map_err(|_| "update cache lock poisoned")?;
        match guard.as_ref() {
            Some(u) => u.release_url.clone(),
            None => return Err("no cached update — call check_for_update first".into()),
        }
    };

    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(&url, None::<&str>)
        .map_err(|e| format!("failed to open release page: {e}"))
}

// ── Codex desktop commands (PR-C8) ───────────────────────────────
//
// Four commands driving the Codex surface Add Account + Change Model
// flows. Every command validates at the IPC boundary and delegates
// the real work to csq-core's `providers::codex` module. No token
// material ever enters a return type (IPC audit is in `tests` below
// — extends the PR-C6 `account_view_serializes_surface_without_secrets`
// forbidden-key harness to every new `Serialize` struct).

/// Fires the pre-check step of a Codex Add Account flow: surfaces
/// whether the user must first acknowledge the Codex terms-of-service
/// disclosure and whether a stale `com.openai.codex` keychain entry
/// would conflict with the file-backed auth store csq requires.
///
/// No filesystem writes beyond the keychain probe. The caller
/// resolves both preconditions and then invokes
/// [`complete_codex_login`].
#[tauri::command]
pub async fn start_codex_login(
    base_dir: String,
    account: u16,
) -> Result<csq_core::providers::codex::desktop_login::StartLoginView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(&base_dir);
    tokio::task::spawn_blocking(move || {
        csq_core::providers::codex::desktop_login::start_login(
            &base,
            account_num,
            csq_core::providers::codex::keychain::probe_residue,
        )
        .map_err(|e| {
            csq_core::error::redact_tokens(&csq_core::cli_deps::sanitize::redact_home_anywhere(
                &format!("{e:#}"),
            ))
        })
    })
    .await
    .map_err(|e| format!("start_codex_login task failed: {e}"))?
}

/// Fixed-vocabulary tag for the filesystem error [`AccountLoginLock::acquire`]
/// returns when it cannot even attempt the lock (distinct from finding it
/// already HELD, which carries no `io::Error` at all — see
/// [`AcquireOutcome::Held`]). `std::io::Error`'s `Display` is unspecified and,
/// for a hand-opened lock file, commonly embeds the absolute path — exactly
/// the shape `tauri-commands.md` § Anti-Patterns bans ("BAD — leaks internal
/// paths"). `ErrorKind`'s `Debug` never does, so it is the only part of the
/// error this handler may interpolate into a renderer-facing string.
fn login_lock_io_error_tag(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::AlreadyExists => "already_exists",
        _ => "io_other",
    }
}

/// Acquires the per-account [`AccountLoginLock`] for a desktop Codex
/// login, or returns a user-facing `Err`.
///
/// Extracted from [`complete_codex_login`] so the acquire/refuse
/// branch is unit-testable without a Tauri `AppHandle` / `State` —
/// mirrors the CLI's `acquire_login_lock` helper in
/// `csq/src/cli/commands/login.rs`. `account` is the raw slot number
/// (not `AccountNum`) purely for rendering in the error string, since
/// callers already have both forms in scope.
fn acquire_codex_desktop_login_lock(
    base: &std::path::Path,
    account_num: AccountNum,
) -> Result<AccountLoginLock, String> {
    let account = account_num.get();
    match AccountLoginLock::acquire(base, account_num) {
        Ok(AcquireOutcome::Acquired(guard)) => Ok(guard),
        Ok(AcquireOutcome::Held { pid: Some(pid), .. }) => Err(format!(
            "codex login already in progress for slot {account} (PID {pid}) — \
             wait for it to finish or cancel it before starting a new one"
        )),
        Ok(AcquireOutcome::Held { pid: None, .. }) => Err(format!(
            "codex login already in progress for slot {account} — \
             wait for it to finish before starting a new one"
        )),
        // No path, no `{e}` — see `login_lock_io_error_tag`'s doc comment.
        Err(e) => Err(format!(
            "could not acquire login lock for slot {account} ({}) — check \
             that the accounts directory is writable and try again",
            login_lock_io_error_tag(&e)
        )),
    }
}

/// Validates `account` + `base_dir` and acquires the per-account
/// [`AccountLoginLock`] — the full precondition chain
/// [`complete_codex_login`] runs before any I/O. Extracted (like
/// [`acquire_codex_desktop_login_lock`] above it) so the chain is
/// unit-testable without a Tauri `AppHandle` / `State`.
///
/// The base-dir check MUST run before the lock acquire:
/// `AccountLoginLock::acquire` convenience-calls
/// `create_dir_all(base_dir)`, so without this ordering a
/// renderer-supplied bad path would be silently CREATED instead of
/// rejected — inverting the convention every other command in this
/// file follows (49 call sites, incl. sibling `acknowledge_codex_tos`
/// / `list_codex_models`, each testing this exact rejection).
/// `desktop_login::complete_login` (called later, inside
/// `spawn_blocking`) has its own base-dir check, but by the time it
/// runs the lock acquire would already have created the directory,
/// making that inner check permanently vacuous for this entry point.
fn codex_login_preconditions(
    base_dir: &str,
    account: u16,
) -> Result<(AccountNum, PathBuf, AccountLoginLock), String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    // Cross-process guard: a concurrent `csq login N --provider codex`
    // (or another desktop instance — not expected, but the lock is
    // cheap insurance) for this same slot is refused here rather than
    // racing the codex-cli subprocess. Non-blocking try-lock —
    // reports contention immediately instead of hanging the modal.
    let lock = acquire_codex_desktop_login_lock(&base, account_num)?;
    Ok((account_num, base, lock))
}

/// Completes a Codex Add Account flow after the UI has resolved the
/// ToS and keychain prompts. Emits `codex-device-code` events with
/// `{ verification_url, user_code }` payloads so the Svelte modal can
/// render the code the user types on ChatGPT's verification page.
///
/// Blocks until `codex login --device-auth` exits (normally minutes,
/// capped by codex-cli's own internal timeout). On success, relocates
/// the freshly-written `auth.json` to `credentials/codex-<N>.json`
/// with 0o400 and fires an `invalidate-cache` to the daemon so the
/// dashboard sees the new slot on its next poll tick.
///
/// # Idempotency + concurrency (an internal journal entry finding 8)
///
/// This command is NOT idempotent mid-flight: a second concurrent call
/// for the same `account` returns `Err("codex login already in progress
/// for slot N")` rather than racing the first call. The rejection is
/// observed via `AppState.codex_login_child` — if the slot is already
/// populated we refuse. Once the first call completes (success or
/// failure), the slot is cleared and a retry is allowed.
///
/// # Cross-process exclusion
///
/// `AppState.codex_login_child` only protects against a second
/// invocation *within this desktop process*. It says nothing about a
/// concurrent `csq login N --provider codex` running in a terminal
/// for the SAME slot — both spawn `codex login --device-auth` with
/// the same `CODEX_HOME=config-<N>/`, racing the subprocess's own
/// `auth.json` write before either side reaches
/// `providers::codex::login::perform_with` /
/// `desktop_login::complete_login`'s `ProfilesFileLock`, which only
/// serialises the identity-mint + canonical-save step. The
/// per-account [`AccountLoginLock`] (UX-R1-H3, shared with the CLI's
/// Claude paths and [`claude_login_subprocess`]) closes that
/// gap; acquired by [`codex_login_preconditions`] before the in-process
/// slot check below, and held for the lifetime of this command.
///
/// # Cancellation (an internal journal entry finding 6)
///
/// The running child process is registered in
/// `AppState.codex_login_child` so a later [`cancel_codex_login`] can
/// SIGKILL it from the modal's close/unmount handler. Without this the
/// subprocess orphans for the minutes-long device-auth window after
/// the user closes the modal.
///
/// # Cross-surface marker cleanup (GH an internal ticket)
///
/// The reverse conflict guard that used to refuse here up-front (redteam R2
/// MED-3) is retired. A stale Gemini or native (Kimi/Grok) marker on
/// `account` is now detected pre-mint and cleared on the success path, deep
/// inside [`csq_core::providers::codex::desktop_login::complete_login`]
/// (mirroring the CLI codex path's `providers::codex::login::perform_with`),
/// rather than refused here — silent replace, not refuse, matching the
/// shipped 3P-unbind precedent. The desktop NATIVE provision path
/// (`resolve_native_login_request` above, via
/// `native::conflicting_bound_surface`) is UNCHANGED and still refuses
/// native↔native and native↔other (an additive marker bind, not an
/// OAuth-login replace).
#[tauri::command]
pub async fn complete_codex_login(
    app: AppHandle,
    state: State<'_, AppState>,
    base_dir: String,
    account: u16,
    purge_keychain: bool,
) -> Result<csq_core::providers::codex::desktop_login::CompleteLoginView, String> {
    let (account_num, base, _cross_process_lock) = codex_login_preconditions(&base_dir, account)?;

    let app_for_task = app.clone();

    // an internal journal entry finding 8: refuse concurrent invocations for any
    // account. codex-cli writes to a single `CODEX_HOME/auth.json`
    // and multiple spawns would race both the subprocess itself and
    // the post-login `save_canonical_for` + `remove_file` sequence.
    {
        let slot_guard = state
            .codex_login_child
            .lock()
            .map_err(|_| "codex login slot poisoned")?;
        if slot_guard.is_some() {
            return Err(format!(
                "codex login already in progress (slot {account}) — \
                 cancel the running flow before starting a new one"
            ));
        }
    }

    let child_slot = state.codex_login_child.clone();
    let child_slot_for_cleanup = child_slot.clone();

    tokio::task::spawn_blocking(move || {
        let result = csq_core::providers::codex::desktop_login::complete_login(
            &base,
            account_num,
            purge_keychain,
            csq_core::providers::codex::keychain::purge_residue,
            |config_dir, on_code| {
                spawn_codex_device_auth_piped(config_dir, on_code, &app_for_task, &child_slot)
            },
            |info| {
                // an internal journal entry finding 4: emit_to("main") so a
                // secondary window (tray/settings) cannot subscribe
                // to the one-time user_code.
                let _ = app_for_task.emit_to("main", "codex-device-code", &info);
            },
        )
        // an internal journal entry finding M3: pass the full anyhow chain
        // through `redact_tokens` before it reaches the renderer.
        // Defense-in-depth — inner call sites already redact, but
        // a future `.context(...)` that omits redaction would leak
        // without this outer wrapper. `redact_home_anywhere` is the
        // path-leak half of that same defense-in-depth (an internal ticket
        // — the anyhow chain can wrap a path-bearing error, e.g.
        // `CredentialError`/`ConfigError`, that a future `.context(...)`
        // forgets to redact at its own construction site).
        .map_err(|e| {
            csq_core::error::redact_tokens(&csq_core::cli_deps::sanitize::redact_home_anywhere(
                &format!("{e:#}"),
            ))
        });

        // Always clear the child slot once we exit, regardless of
        // result. The slot is cleared inside
        // `spawn_codex_device_auth_piped`'s exit path already, but
        // do it here too so an early error (pre-spawn) cannot leave
        // a stale slot entry.
        {
            if let Ok(mut slot) = child_slot_for_cleanup.lock() {
                *slot = None;
            }
        }

        let result = result?;

        // Best-effort: kick daemon cache invalidation so the dashboard
        // sees the new slot immediately rather than waiting for the
        // 5s discovery tick. an internal journal entry finding M6: the HTTP POST
        // over the Unix socket has NO client-side timeout — a hung
        // daemon would block the spawn_blocking thread. We wrap in
        // a coarse 500ms deadline enforced by a worker thread. If
        // the daemon doesn't answer in 500ms the dashboard catches
        // up on its next 5s discovery tick.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base);
            if sock.exists() {
                // Fire-and-forget style: spawn a short-lived worker
                // that does the blocking call; a timer on the main
                // thread bounds the wait. Whichever finishes first
                // wins; the other side is dropped on return.
                let (tx, rx) = std::sync::mpsc::channel();
                let sock_copy = sock.clone();
                std::thread::spawn(move || {
                    let r = csq_core::daemon::http_post_unix(&sock_copy, "/api/invalidate-cache");
                    let _ = tx.send(r);
                });
                let _ = rx.recv_timeout(std::time::Duration::from_millis(500));
            }
        }

        Ok::<_, String>(result)
    })
    .await
    .map_err(|e| format!("complete_codex_login task failed: {e}"))?
}

/// Cancels an in-flight `codex login --device-auth` by killing the
/// child process. No-op when no login is running — the modal's close
/// handler calls this unconditionally, and the frontend treats a
/// successful cancel as "return to picker".
///
/// Mirrors [`cancel_ollama_pull`] — SIGKILL via `Child::kill`; the
/// reader threads see EOF on piped stdout/stderr and exit; the
/// waiting `spawn_blocking` task returns a non-success status and
/// the frontend sees a generic failure banner.
#[tauri::command]
pub fn cancel_codex_login(state: State<'_, AppState>) -> Result<(), String> {
    let handle_opt = {
        let slot = state
            .codex_login_child
            .lock()
            .map_err(|_| "codex login slot poisoned")?;
        slot.clone()
    };
    let Some(handle) = handle_opt else {
        return Ok(());
    };
    let mut child = handle.lock().map_err(|_| "codex login child poisoned")?;
    let _ = child.kill();
    Ok(())
}

/// True when the URL-without-code diagnostic should fire from
/// [`spawn_codex_device_auth_piped`] after the child process exits.
/// Extracted as a free function so the truth table is unit-testable
/// without standing up a real codex-cli subprocess.
///
/// Fires only when the child exited successfully AND saw a URL AND
/// did NOT see a code-shape. A non-zero exit (user Ctrl-C, codex-cli
/// crash, network failure) routes upstream to the existing "user may
/// have cancelled in the browser" path; without the success gate the
/// diagnostic falsely reports "codex-cli output format may have
/// changed" for legitimate user-cancel cases.
///
/// Origin: redteam follow-up to PRs an internal ticket-an internal ticket (LOW finding —
/// user-cancel diagnostic mis-frame).
fn should_emit_url_without_code_diagnostic(
    child_exited_successfully: bool,
    saw_url: bool,
    seen_code: bool,
) -> bool {
    child_exited_successfully && saw_url && !seen_code
}

/// Production `codex login --device-auth` spawn. Captures stdout +
/// stderr line-by-line; feeds each line through
/// [`csq_core::providers::codex::desktop_login::parse_device_code_line`]
/// to detect the device-code payload; when found, invokes `on_code`
/// so [`complete_codex_login`] can forward it to the UI.
///
/// Also emits `codex-login-progress` events with raw stdout/stderr
/// lines (scrubbed of anything token-shaped via the core redactor)
/// so the modal can show a log tail for debugging auth failures —
/// same ergonomic pattern as `ollama-pull-progress` in
/// [`pull_ollama_model`].
///
/// # PR-C9a hardening (an internal journal entry)
///
/// - Device-code parse runs on the **scrubbed** line (finding 2) so a
///   malicious codex-cli that prints a synthetic code alongside a
///   token cannot trick the parser into forwarding a fake code.
/// - The BufReader is bounded at 64 KiB per line (finding 3) so
///   codex-cli cannot OOM the process by emitting an unbounded line.
///   Lines that exceed the cap are emitted as `[line truncated]`.
/// - The device-code channel is `sync_channel(4)` + early-exit after
///   the first code (finding M7) so a banner repetition cannot fill
///   memory.
/// - The child process is registered in the shared `child_slot`
///   (finding 6) so `cancel_codex_login` can kill it.
/// - `child.wait()` runs BEFORE joining the reader threads (finding
///   7) so a stuck reader cannot deadlock the forwarder.
fn spawn_codex_device_auth_piped(
    config_dir: &std::path::Path,
    on_code: &mut dyn FnMut(csq_core::providers::codex::desktop_login::DeviceCodeInfo),
    app: &AppHandle,
    child_slot: &Arc<std::sync::Mutex<Option<Arc<std::sync::Mutex<std::process::Child>>>>>,
) -> anyhow::Result<std::process::ExitStatus> {
    use csq_core::error::redact_tokens;
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};

    // Resolve `codex` via the same finder Claude uses so the Finder-
    // launched desktop bundle (which inherits a minimal PATH —
    // `/usr/bin:/bin:/usr/sbin:/sbin`) can locate Homebrew or
    // per-user installs. Without this, every desktop Codex login
    // fails with "No such file or directory" on macOS bundles. Same
    // pattern as `start_claude_login` and Ollama spawn.
    let codex_bin =
        csq_core::accounts::login::find_cli_binary(csq_core::providers::codex::surface::CLI_BINARY)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not locate the `{}` binary in $PATH or any standard install location \
             (/opt/homebrew/bin, /usr/local/bin, ~/.local/bin, ~/.npm-global/bin) — install \
             codex-cli (npm i -g @openai/codex) and try again",
                    csq_core::providers::codex::surface::CLI_BINARY
                )
            })?;
    let child = Command::new(&codex_bin)
        .args(["login", "--device-auth"])
        .env(
            csq_core::providers::codex::surface::HOME_ENV_VAR,
            config_dir,
        )
        .env_remove("CLAUDE_CONFIG_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "spawn `{} login --device-auth`: {e} — is codex-cli installed and on PATH?",
                csq_core::providers::codex::surface::CLI_BINARY
            )
        })?;

    let mut child = child;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child_arc = Arc::new(std::sync::Mutex::new(child));

    // Register for cancel. Overwrite any stale entry defensively —
    // `complete_codex_login`'s pre-check rejects concurrent callers,
    // but a panicked prior run could leave a ghost entry.
    {
        let mut slot = child_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("child slot poisoned"))?;
        *slot = Some(child_arc.clone());
    }

    // Bounded channel — pathological codex-cli banner repetition
    // cannot fill memory. `sync_channel(4)` lets four codes queue
    // (unlikely in practice; the forwarder exits after the first).
    let (tx, rx) = std::sync::mpsc::sync_channel::<
        csq_core::providers::codex::desktop_login::DeviceCodeInfo,
    >(4);

    // codex-cli 0.128.0+ prints the verification URL and the device
    // code on SEPARATE lines — `parse_device_code_line` alone returns
    // None per line and the modal hangs. The accumulator tracks
    // cross-line state and emits when both halves have been seen.
    // Wrapped in Arc<Mutex<…>> so both reader threads can share state
    // (in practice only stdout enables `parse`, but the channel-style
    // contract makes accidental cross-stream pairing impossible:
    // stderr's reader is constructed with `parse=false`, so stderr
    // lines never feed the accumulator).
    let accumulator = Arc::new(std::sync::Mutex::new(
        csq_core::providers::codex::desktop_login::DeviceCodeAccumulator::new(),
    ));

    // #2a (browser auto-open): open the verification URL the instant codex-cli
    // prints it, rather than waiting for the accumulator to pair URL+code.
    // codex-cli 0.128.0+ prints the URL on an EARLIER line than the code, so the
    // paired `codex-device-code` event (and the modal's openUrl) fire only after
    // the later code line — leaving the browser closed in between (user had to
    // open it manually). The URL is already allowlist/HTTPS/userinfo-validated by
    // `extract_device_auth_url`. Guarded so it fires at most once; best-effort
    // (an opener failure never blocks login — the modal still renders the link).
    let url_opened = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Reader factory. Only the stdout reader feeds the parser; stderr
    // emits progress only. This narrows the parse trust boundary:
    // stderr lines are never interpreted as device codes.
    let reader = |stream: Option<Box<dyn std::io::Read + Send>>,
                  tag: &'static str,
                  parse: bool,
                  app: AppHandle,
                  tx: std::sync::mpsc::SyncSender<
        csq_core::providers::codex::desktop_login::DeviceCodeInfo,
    >,
                  accumulator: Arc<
        std::sync::Mutex<csq_core::providers::codex::desktop_login::DeviceCodeAccumulator>,
    >,
                  url_opened: Arc<std::sync::atomic::AtomicBool>| {
        let stream = match stream {
            Some(s) => s,
            None => return None,
        };
        Some(std::thread::spawn(move || {
            // 64 KiB per-line cap. Manual read_until beats
            // BufReader::lines() which allocates unboundedly.
            const LINE_CAP: usize = 64 * 1024;
            let mut buf = BufReader::new(stream);
            let mut line_bytes: Vec<u8> = Vec::with_capacity(1024);
            loop {
                line_bytes.clear();
                // Take the reader limited to the cap to prevent
                // unbounded allocation per line.
                let n = {
                    let mut limited = (&mut buf).take((LINE_CAP + 1) as u64);
                    limited
                        .read_until(b'\n', &mut line_bytes)
                        .unwrap_or_default()
                };
                if n == 0 {
                    break;
                }
                // If the line exceeded LINE_CAP (still no newline),
                // drop the rest of that line from the underlying
                // reader and emit a truncation marker instead of
                // the raw bytes.
                let truncated = line_bytes.len() > LINE_CAP;
                if truncated {
                    // Drain the rest of the physical line so the
                    // next iteration sees a fresh start. Best-effort.
                    let mut sink = Vec::new();
                    let _ = (&mut buf)
                        .take((1 << 20) as u64)
                        .read_until(b'\n', &mut sink);
                }
                let raw_line = if truncated {
                    "[line truncated]".to_string()
                } else {
                    // Strip trailing newline for cleaner display.
                    let bytes = if line_bytes.last() == Some(&b'\n') {
                        &line_bytes[..line_bytes.len() - 1]
                    } else {
                        &line_bytes[..]
                    };
                    String::from_utf8_lossy(bytes).to_string()
                };
                let scrubbed = redact_tokens(&raw_line);
                let _ = app.emit(
                    "codex-login-progress",
                    serde_json::json!({ "stream": tag, "line": scrubbed }),
                );
                // Device-code parse runs on the SCRUBBED string and
                // ONLY for stdout (trust boundary narrowing — journal
                // 0021 finding 2). Goes through the cross-line
                // accumulator so codex-cli 0.128.0's split-line shape
                // is handled.
                if parse && !truncated {
                    // #2a: open the verification URL as soon as it appears,
                    // before the code line arrives. Once-guarded, best-effort —
                    // mirrors the CLI's URL-alone auto-launch.
                    if !url_opened.load(std::sync::atomic::Ordering::SeqCst) {
                        if let Some(url) =
                            csq_core::providers::codex::desktop_login::extract_device_auth_url(
                                &scrubbed,
                            )
                        {
                            if url_opened
                                .compare_exchange(
                                    false,
                                    true,
                                    std::sync::atomic::Ordering::SeqCst,
                                    std::sync::atomic::Ordering::SeqCst,
                                )
                                .is_ok()
                            {
                                use tauri_plugin_opener::OpenerExt;
                                let _ = app.opener().open_url(&url, None::<&str>);
                            }
                        }
                    }
                    let maybe_info = accumulator
                        .lock()
                        .ok()
                        .and_then(|mut acc| acc.observe(&scrubbed));
                    if let Some(info) = maybe_info {
                        // try_send so a full channel does not block
                        // the reader thread. Drop extra codes.
                        let _ = tx.try_send(info);
                    }
                }
            }
        }))
    };

    let stdout_t = reader(
        stdout.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        "stdout",
        true, // parse device-code on stdout only
        app.clone(),
        tx.clone(),
        Arc::clone(&accumulator),
        Arc::clone(&url_opened),
    );
    let stderr_t = reader(
        stderr.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        "stderr",
        false, // stderr is progress-only; never parse
        app.clone(),
        tx.clone(),
        Arc::clone(&accumulator),
        Arc::clone(&url_opened),
    );

    // Drop the forwarder's tx clone so rx.recv() returns Err once
    // both readers drop theirs (on pipe EOF / child exit).
    drop(tx);

    // Forwarder: fire on_code for the FIRST code, drain subsequent
    // sends into the void. We do not `break` — draining keeps reader
    // threads from blocking on a full bounded channel.
    let mut seen_code = false;
    while let Ok(info) = rx.recv() {
        if !seen_code {
            seen_code = true;
            on_code(info);
        }
    }

    // an internal journal entry finding 7: wait on the child BEFORE joining
    // reader threads. A stuck reader thread would deadlock .join()
    // forever otherwise. After child exit, the OS closes pipes and
    // the reader threads see EOF.
    let status = {
        let mut guard = child_arc
            .lock()
            .map_err(|_| anyhow::anyhow!("codex login child poisoned"))?;
        guard.wait()?
    };

    // Explicit drops so the pipe fds close if the kernel didn't
    // already do it (belt-and-suspenders).
    drop(child_arc);

    if let Some(t) = stdout_t {
        let _ = t.join();
    }
    if let Some(t) = stderr_t {
        let _ = t.join();
    }

    // Clear slot now that the subprocess is fully reaped.
    {
        let mut slot = child_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("child slot poisoned"))?;
        *slot = None;
    }

    // Diagnostic for the "URL emitted but no recognised code shape"
    // failure mode (e.g. OpenAI bumps codex-cli's device-code length
    // past the 4-{4..=5} window — `is_device_code_shape` silently
    // drops the token, no `codex-device-code` event ever fires, and
    // the modal sits in `codex-running` until the codex-cli timeout
    // fires minutes later. Without this the upstream `complete_login`
    // surfaces the generic "user may have cancelled in the browser"
    // message which is misleading for this failure shape.
    //
    // Gate on `status.success()` so a user who Ctrl-Cs codex-cli
    // mid-flow (after the URL is printed but before a code shape is
    // emitted) still routes to the upstream "user may have cancelled"
    // message rather than the false-positive "output format may have
    // changed" diagnostic. Origin: redteam follow-up to PRs an internal ticket-an internal ticket
    // (LOW finding — user-cancel diagnostic mis-frame).
    let saw_url = accumulator.lock().map(|acc| acc.saw_url()).unwrap_or(false);
    if should_emit_url_without_code_diagnostic(status.success(), saw_url, seen_code) {
        let warning = "csq saw a verification URL on codex-cli stdout but never \
            saw a recognised device-code shape (4-letter–4-or-5-letter, \
            e.g. ABCD-EFGH or ABCD-12345). codex-cli's output format may \
            have changed; please report this to https://github.com/terrene-foundation/csq/issues";
        // Surface as a progress event so any external listener / log
        // tail catches it, AND return Err so `complete_login` routes
        // a precise diagnostic to the modal's existing error path.
        let _ = app.emit_to(
            "main",
            "codex-login-progress",
            serde_json::json!({ "stream": "warning", "line": warning }),
        );
        return Err(anyhow::anyhow!(warning));
    }

    Ok(status)
}

/// Returns the Codex models list. Consults (in order) the on-disk
/// cache, a live fetch to `https://chatgpt.com/backend-api/codex/models`
/// with a 1.5s timeout via the Node transport, and finally the
/// bundled cold-start list. Never returns an empty list.
///
/// Requires a Codex account to be already authenticated — the live
/// fetch uses that account's access token as a Bearer. If no Codex
/// slot exists, only the cache and bundled fallback are consulted.
#[tauri::command]
pub async fn list_codex_models(
    base_dir: String,
) -> Result<csq_core::providers::codex::models::CodexModelList, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    tokio::task::spawn_blocking(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let base_for_cache = base.clone();
        let base_for_write = base.clone();
        let base_for_fetch = base.clone();
        let list = csq_core::providers::codex::models::list_models_with(
            move || csq_core::providers::codex::models::read_cache(&base_for_cache, now),
            move || fetch_codex_models_live(&base_for_fetch),
            probe_codex_cli_models,
            move |list| {
                let _ = csq_core::providers::codex::models::write_cache(&base_for_write, list);
            },
            now,
        );
        Ok::<_, String>(list)
    })
    .await
    .map_err(|e| format!("list_codex_models task failed: {e}"))?
}

/// Live fetcher used by [`list_codex_models`]. Picks the lowest-numbered
/// Codex account slot, reads its access token, and issues a Bearer
/// GET against `chatgpt.com/backend-api/codex/models`. Returns the
/// raw response body on HTTP 200; any other status is a fetch
/// failure, surfacing as a fall-through to the bundled list.
fn fetch_codex_models_live(base_dir: &std::path::Path) -> Result<Vec<u8>, String> {
    // Discover Codex slots. If none, nothing to fetch with.
    let accounts = csq_core::accounts::discovery::discover_all(base_dir);
    let codex_account = accounts
        .iter()
        .find(|a| a.surface == csq_core::providers::catalog::Surface::Codex)
        .ok_or_else(|| "no codex account provisioned".to_string())?;

    // Read that account's canonical credential file.
    let codex_num = AccountNum::try_from(codex_account.id)
        .map_err(|e| format!("bad codex account number {}: {e}", codex_account.id))?;
    let canonical = csq_core::credentials::file::canonical_path_for(
        base_dir,
        codex_num,
        csq_core::providers::catalog::Surface::Codex,
    );
    let creds = csq_core::credentials::load(&canonical)
        .map_err(|e| format!("load codex credentials: {}", e.redacted_message()))?;
    let token = creds
        .codex()
        .ok_or_else(|| "credentials at canonical path are not codex-shape".to_string())?
        .tokens
        .access_token
        .clone();

    let url = "https://chatgpt.com/backend-api/codex/models";
    let extra_headers: &[(&str, &str)] = &[("User-Agent", "csq-desktop/codex-models")];
    let (status, body) =
        csq_core::http::get_bearer_node(url, &token, extra_headers).map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(format!("codex/models returned HTTP {status}"));
    }
    Ok(body)
}

/// Hard cap on how long to wait for `codex debug models`. The probe
/// is in-process (no network), so a short ceiling is generous and
/// keeps the picker responsive when codex-cli is wedged.
const CODEX_CLI_PROBE_TIMEOUT_SECS: u64 = 3;

/// Hard cap on bytes read from `codex debug models` stdout. Real
/// output at codex-cli 0.128.0 is ~220 KB; 4 MiB is ~20× headroom
/// and defends against a wedged codex-cli flooding stdout.
const CODEX_CLI_PROBE_STDOUT_CAP_BYTES: usize = 4 * 1024 * 1024;

/// Probes `codex debug models` for the model catalog. Used as the
/// fallback after the HTTP fetch fails (or has no Codex account to
/// authenticate with). Bounded by [`CODEX_CLI_PROBE_TIMEOUT_SECS`]
/// — codex-cli's `debug models` is in-process (no network), so a
/// short timeout is generous.
///
/// Origin: /autonomize item 2 (2026-05-07) — operator request to
/// dynamically fetch the model list from codex-cli rather than
/// falling through to a hardcoded snapshot when HTTP fails.
fn probe_codex_cli_models() -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    let mut child = Command::new("codex")
        .args(["debug", "models"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn codex debug models: {e}"))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "codex debug models: no stdout pipe".to_string())?;

    // Reader thread drains stdout up to the cap; result lands on a
    // channel. Main thread waits with `recv_timeout` — on timeout,
    // it kills the child via Child::kill() (cross-platform std API),
    // which causes the reader's `read_to_end` to return EOF.
    let (tx, rx) = mpsc::sync_channel::<Result<Vec<u8>, String>>(1);
    std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(256 * 1024);
        let cap = CODEX_CLI_PROBE_STDOUT_CAP_BYTES;
        let read_result = (&mut stdout).take(cap as u64 + 1).read_to_end(&mut buf);
        let send = match read_result {
            Ok(_) if buf.len() > cap => Err(format!(
                "codex debug models stdout exceeded {cap} bytes; suspected runaway output"
            )),
            Ok(_) => Ok(buf),
            Err(e) => Err(format!("read codex debug models stdout: {e}")),
        };
        let _ = tx.send(send);
    });

    let result = rx.recv_timeout(std::time::Duration::from_secs(CODEX_CLI_PROBE_TIMEOUT_SECS));
    match result {
        Ok(Ok(buf)) => {
            // Reader finished within deadline; reap the child.
            let status = child
                .wait()
                .map_err(|e| format!("wait codex debug models: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "codex debug models exited with status {:?}",
                    status.code()
                ));
            }
            if buf.is_empty() {
                return Err("codex debug models produced no output".into());
            }
            Ok(buf)
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
        Err(_) => {
            // recv_timeout — kill child + reap to avoid zombie.
            let _ = child.kill();
            let _ = child.wait();
            Err(format!(
                "codex debug models exceeded {CODEX_CLI_PROBE_TIMEOUT_SECS}s timeout"
            ))
        }
    }
}

/// Writes `model = "<id>"` into the Codex slot's `config.toml`.
/// Mirrors the `csq models switch codex <id>` CLI path (PR-C7) —
/// uses `providers::codex::surface::write_config_toml` so the
/// `cli_auth_credentials_store = "file"` directive (INV-P03) is
/// preserved. `--force` semantics are handled at the UI — the
/// desktop picker only surfaces ids from `list_codex_models`, and
/// custom ids are an explicit override.
///
/// # Surface verification (an internal journal entry finding 9)
///
/// Refuses when the target slot is not a Codex slot. Without this
/// check, a renderer passing a ClaudeCode slot number would cause
/// `write_config_toml` to seed a `config-<N>/config.toml` into an
/// Anthropic slot's directory — poisoning surface classification
/// because `config.toml` is a Codex-unique marker in the handle-dir
/// model (spec 07 §7.2.2). We verify via `discover_all` which
/// includes both ClaudeCode and Codex slots.
#[tauri::command]
pub fn set_codex_slot_model(
    app: AppHandle,
    base_dir: String,
    slot: u16,
    model: String,
) -> Result<(), String> {
    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("model must not be empty".into());
    }
    // Bound the renderer-supplied model id at the IPC boundary (tauri-commands.md
    // MUST Rule 2 — validate all string args; assume the renderer is adversarial).
    // Codex model ids are short; a value this long is malformed. The value is
    // TOML-escaped downstream (no injection), but the cap rejects a bloated id
    // early. Mirrors the CLI's catalog gate on the desktop path (R3 finding).
    if model.len() > 256 {
        return Err(format!(
            "model id too long: {} chars (max 256)",
            model.len()
        ));
    }
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    // an internal journal entry finding 9: verify surface before writing.
    // `write_config_toml` does not verify the destination slot's
    // surface; it would silently poison an Anthropic slot with
    // Codex config.toml if called on the wrong slot.
    let accounts = csq_core::accounts::discovery::discover_all(&base);
    let slot_info = accounts.iter().find(|a| a.id == slot);
    match slot_info {
        Some(info) if info.surface == csq_core::providers::catalog::Surface::Codex => {
            // ok
        }
        Some(info) => {
            return Err(format!(
                "slot {slot} is not a Codex slot (surface = {:?}) — \
                 use set_slot_model for ClaudeCode slots",
                info.surface
            ));
        }
        None => {
            return Err(format!(
                "slot {slot} does not exist or has no credentials — \
                 run `csq login {slot} --provider codex` first"
            ));
        }
    }

    // Explicit user choice → `Some`: the desktop model picker sets the per-slot
    // `model` key (mirrors the `csq models set codex` CLI path). login/spawn
    // callers pass `None`.
    csq_core::providers::codex::surface::write_config_toml(&base, slot_num, Some(&model)).map_err(
        |e| {
            format!(
                "write codex config.toml: {}",
                csq_core::cli_deps::sanitize::redact_display(e)
            )
        },
    )?;
    let _ = app.emit(
        "slot-model-changed",
        serde_json::json!({ "slot": slot, "model": model, "surface": "codex" }),
    );
    Ok(())
}

/// Records that the user has read and acknowledged the Codex
/// terms-of-service disclosure. Writes
/// `accounts/codex-tos-accepted.json` at 0o600. Idempotent.
#[tauri::command]
pub fn acknowledge_codex_tos(base_dir: String) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    csq_core::providers::codex::tos::acknowledge(&base)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "acknowledge codex tos: {}",
                csq_core::cli_deps::sanitize::redact_display(e)
            )
        })
}

// ── PR-G5 — Gemini desktop UI commands ──────────────────────────
//
// FR-G-UI-01: AddAccountModal Gemini panel needs ToS gate, paste
// (AI Studio API key) or file picker (Vertex SA), and an inline
// warning when `~/.gemini/oauth_creds.json` is present.
//
// FR-G-UI-02: ChangeModelModal needs a static-list switch — the
// model id catalog is small and frozen client-side; the desktop
// only submits canonical ids so the boundary check is `is_known_gemini_model`.
//
// All Gemini commands live in csq-core; the Tauri commands here are
// thin: validate at the IPC boundary, delegate the orchestration to
// csq-core fns. None of the return types carry secret material —
// keys are stored in the platform vault and never echoed to IPC.

/// Returns `true` when the user has previously acknowledged the
/// Gemini terms-of-service disclosure. Used by the desktop modal to
/// decide whether to render the disclosure or skip straight to the
/// provisioning panel. Mirrors `is_acknowledged` for Codex.
#[tauri::command]
pub fn is_gemini_tos_acknowledged(base_dir: String) -> Result<bool, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    Ok(csq_core::providers::gemini::tos::is_acknowledged(&base))
}

/// Records that the user has read and acknowledged the Gemini
/// terms-of-service disclosure. Writes
/// `accounts/gemini-tos-accepted.json` at 0o600. Idempotent.
#[tauri::command]
pub fn acknowledge_gemini_tos(base_dir: String) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    csq_core::providers::gemini::tos::acknowledge(&base)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "acknowledge gemini tos: {}",
                csq_core::cli_deps::sanitize::redact_display(e)
            )
        })
}

/// Probes whether `~/.gemini/oauth_creds.json` exists. The Add
/// Account Gemini panel renders an informational note when this
/// returns `Some(...)` so the user knows that binding the slot to
/// API-key mode means gemini-cli will use the API key csq provides
/// (via `GEMINI_API_KEY` env var) for this slot — the OAuth
/// credentials remain on disk untouched and would still be picked
/// up by a separate Code Assist OAuth slot if one is bound. Earlier
/// revisions framed this probe as ToS-driven enforcement
/// (ADR-G01/G12) — that framing was retracted in an internal journal entry
/// Returns the absolute path so the note can name the file
/// concretely.
#[tauri::command]
pub fn gemini_probe_tos_residue() -> Result<Option<String>, String> {
    let home =
        dirs::home_dir().ok_or_else(|| "could not resolve user home directory".to_string())?;
    Ok(csq_core::providers::gemini::tos::probe_oauth_residue(&home)
        .map(|p| p.display().to_string()))
}

/// Provisions a Gemini slot with an AI Studio API key (paste mode).
/// The plaintext key NEVER touches disk under `accounts/` — it goes
/// straight to the platform-native vault (macOS Keychain, Linux
/// Secret Service, Windows DPAPI). The binding marker
/// `credentials/gemini-<N>.json` carries metadata only (auth mode,
/// model name, timestamp).
///
/// Boundary validation: rejects empty, oversized (> 200 bytes),
/// control-character, non-`AIza`-prefixed input, and slots already
/// bound to a non-Gemini surface (Codex / Anthropic OAuth).
#[tauri::command]
pub fn gemini_provision_api_key(base_dir: String, slot: u16, key: String) -> Result<(), String> {
    use csq_core::providers::gemini::provisioning::provision_api_key_via_vault;
    use secrecy::SecretString;

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("key must not be empty".into());
    }
    if trimmed.len() < 30 {
        return Err(format!(
            "key too short ({} bytes; AI Studio keys are 30+ bytes)",
            trimmed.len()
        ));
    }
    if trimmed.len() > 200 {
        return Err(format!("key too long ({} bytes; max 200)", trimmed.len()));
    }
    if trimmed.chars().any(|c| c.is_ascii_control()) {
        return Err("key contains control characters — paste likely truncated".into());
    }
    if !trimmed.starts_with("AIza") {
        return Err(
            "expected an AI Studio API key (prefix `AIza`); for Vertex AI, use the \
             Vertex SA tab instead"
                .into(),
        );
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    if let Some(existing) = csq_core::accounts::binding_guard::conflicting_bound_surface(
        &base,
        slot_num,
        csq_core::providers::catalog::Surface::Gemini,
    ) {
        return Err(format!(
            "slot {slot} is bound to {} — run `csq logout {slot}` to rebind to Gemini",
            existing.label()
        ));
    }

    let vault = csq_core::platform::secret::open_default_vault()
        .map_err(|e| format!("secret vault unavailable ({}): {e}", e.error_kind_tag()))?;

    let secret = SecretString::new(trimmed.to_string().into());
    provision_api_key_via_vault(&base, slot_num, &secret, vault.as_ref())
        .map_err(|e| format!("provision api key: {}", e.redacted_message()))?;
    Ok(())
}

/// Provisions a Gemini slot with a Vertex AI service account JSON
/// path. The path is canonicalised and validated (regular file, ≤ 64
/// KiB, not a symlink) before the binding marker is written. The
/// JSON contents are not parsed here — gemini-cli does that on first
/// call. Returns the canonical path that ended up in the marker so
/// the UI can echo it back to the user.
#[tauri::command]
pub fn gemini_provision_vertex_sa(
    base_dir: String,
    slot: u16,
    sa_path: String,
) -> Result<String, String> {
    use csq_core::providers::gemini::provisioning::provision_vertex_sa;

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let trimmed = sa_path.trim();
    if trimmed.is_empty() {
        return Err("Vertex SA JSON path must not be empty".into());
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err(format!(
            "Vertex SA JSON path must be absolute (got `{trimmed}`)"
        ));
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    if let Some(existing) = csq_core::accounts::binding_guard::conflicting_bound_surface(
        &base,
        slot_num,
        csq_core::providers::catalog::Surface::Gemini,
    ) {
        return Err(format!(
            "slot {slot} is bound to {} — run `csq logout {slot}` to rebind to Gemini",
            existing.label()
        ));
    }

    let canonical = provision_vertex_sa(&base, slot_num, &path)
        .map_err(|e| format!("provision vertex sa: {}", e.redacted_message()))?;
    Ok(canonical.display().to_string())
}

// ── an internal ticket PR-2 — cloud-Claude desktop provisioning ──────────────
//
// Desktop parity for the `csq setkey claude --backend vertex|bedrock` CLI
// (PR-1). Both commands are thin IPC wrappers: validate at the boundary,
// then delegate to `bind_cloud_claude_backend_to_slot`, which owns the
// fail-closed conflict guard (a cloud backend binds only over a bare slot
// or an existing cloud slot), the SSRF/DNS-label validation of
// project/region, the SA-path validation (regular file, ≤ 64 KiB, not a
// symlink), the residency gate, and the locked `config-N/settings.json`
// RMW. Nothing here re-implements that logic.
//
// Enterprise-only: cloud-Claude routing (Vertex/Bedrock Claude access) is
// an enterprise entitlement, so `bind_cloud_claude_backend_to_slot` and
// `CloudClaudeBackendSpec` are `#[cfg(feature = "enterprise")]`. The
// commands and their `generate_handler!` registration carry the same gate,
// and the renderer only surfaces the cloud-Claude card when
// `get_build_edition()` returns `"enterprise"`.
//
// The Bedrock bearer token arrives as an IPC in-argument (mirroring
// `gemini_provision_api_key`'s `key: String`) — a secret in a return type
// is forbidden (`rules/tauri-commands.md` §3), but an inbound secret arg
// is the same shape the Gemini API-key path already uses.

/// Maps a cloud-Claude [`ConfigError`](csq_core::error::ConfigError) to user-actionable modal text
/// without leaking the on-disk settings path. `SlotSurfaceConflict` and
/// `MergeConflict` (input-validation rejects from the backend) already
/// carry clean, path-free Display strings; `InvalidJson` is the only
/// variant that embeds a path, so it is collapsed to a generic message.
#[cfg(feature = "enterprise")]
fn cloud_claude_error_text(e: csq_core::error::ConfigError) -> String {
    use csq_core::error::ConfigError;
    match e {
        ConfigError::InvalidJson { .. } => {
            "cloud-Claude provisioning failed writing the slot settings".to_string()
        }
        other => other.to_string(),
    }
}

/// Provisions a `ClaudeCode` slot to route Anthropic Claude through Google
/// Vertex AI (an internal ticket). Writes the cloud env block CC reads on startup
/// (`CLAUDE_CODE_USE_VERTEX`, `ANTHROPIC_VERTEX_PROJECT_ID`,
/// `CLOUD_ML_REGION`, `GOOGLE_APPLICATION_CREDENTIALS`) into the per-slot
/// `config-N/settings.json`. The `sa_path` is the GCP service-account JSON
/// (validated by the backend: regular file, ≤ 64 KiB, not a symlink,
/// canonicalised); `project`/`region` are DNS-label-validated by the
/// backend before interpolation into the GCP endpoint (SSRF defense).
///
/// Fail-closed: binding a cloud backend over an Anthropic OAuth slot, a
/// Codex/Gemini/native slot, or a real 3P-bearer slot is REFUSED by the
/// backend (`SlotSurfaceConflict`) — surfaced here as the modal error.
///
/// Enterprise-only.
#[cfg(feature = "enterprise")]
#[tauri::command]
pub fn cloud_claude_provision_vertex(
    base_dir: String,
    slot: u16,
    project: String,
    region: String,
    sa_path: String,
    model: Option<String>,
) -> Result<(), String> {
    use csq_core::accounts::third_party::{
        bind_cloud_claude_backend_to_slot, CloudClaudeBackendSpec,
    };

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;

    let project = project.trim();
    if project.is_empty() {
        return Err("Vertex project ID must not be empty".into());
    }
    let region = region.trim();
    if region.is_empty() {
        return Err("Vertex region must not be empty".into());
    }
    let sa_trimmed = sa_path.trim();
    if sa_trimmed.is_empty() {
        return Err("Vertex SA JSON path must not be empty".into());
    }
    let path = PathBuf::from(sa_trimmed);
    if !path.is_absolute() {
        return Err(format!(
            "Vertex SA JSON path must be absolute (got `{sa_trimmed}`)"
        ));
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    bind_cloud_claude_backend_to_slot(
        &base,
        slot_num,
        &CloudClaudeBackendSpec::Vertex {
            project,
            region,
            sa_path: &path,
            model: model.as_deref(),
        },
    )
    .map_err(cloud_claude_error_text)
}

/// Provisions a `ClaudeCode` slot to route Anthropic Claude through AWS
/// Bedrock (an internal ticket). Writes `CLAUDE_CODE_USE_BEDROCK`, `AWS_REGION`,
/// and `AWS_BEARER_TOKEN_BEDROCK` into the per-slot `config-N/settings.json`.
/// `region` is DNS-label-validated by the backend; `bearer_token` shape is
/// validated by the backend (`validate_key_shape`). The token is an inbound
/// IPC argument and is NEVER echoed back over IPC (no secret in the return
/// type — `rules/tauri-commands.md` §3).
///
/// Fail-closed on a non-bare / non-cloud slot, identical to the Vertex path.
///
/// Enterprise-only.
#[cfg(feature = "enterprise")]
#[tauri::command]
pub fn cloud_claude_provision_bedrock(
    base_dir: String,
    slot: u16,
    region: String,
    bearer_token: String,
    model: Option<String>,
) -> Result<(), String> {
    use csq_core::accounts::third_party::{
        bind_cloud_claude_backend_to_slot, CloudClaudeBackendSpec,
    };

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;

    let region = region.trim();
    if region.is_empty() {
        return Err("Bedrock region must not be empty".into());
    }
    let token = bearer_token.trim();
    if token.is_empty() {
        return Err("AWS Bedrock bearer token must not be empty".into());
    }
    if token.chars().any(|c| c.is_ascii_control()) {
        return Err("bearer token contains control characters — paste likely truncated".into());
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    bind_cloud_claude_backend_to_slot(
        &base,
        slot_num,
        &CloudClaudeBackendSpec::Bedrock {
            region,
            model: model.as_deref(),
            bearer_token: token,
        },
    )
    .map_err(cloud_claude_error_text)
}

/// Acquires the per-account [`AccountLoginLock`] for a desktop Gemini
/// login, or returns a user-facing `Err`.
///
/// Extracted from [`gemini_provision_oauth`] so the acquire/refuse
/// branch is unit-testable without a Tauri `AppHandle` / `State` —
/// mirrors the CLI's `acquire_login_lock` helper in
/// `csq/src/cli/commands/login.rs` (called there with `bypass_hint:
/// None`, since gemini has no `--legacy-shell`-style escape hatch).
/// `account` is the raw slot number (not `AccountNum`) purely for
/// rendering in the error string, since callers already have both
/// forms in scope.
fn acquire_gemini_desktop_login_lock(
    base: &std::path::Path,
    account_num: AccountNum,
) -> Result<AccountLoginLock, String> {
    let account = account_num.get();
    match AccountLoginLock::acquire(base, account_num) {
        Ok(AcquireOutcome::Acquired(guard)) => Ok(guard),
        Ok(AcquireOutcome::Held { pid: Some(pid), .. }) => Err(format!(
            "gemini login already in progress for slot {account} (PID {pid}) — \
             wait for it to finish or cancel it before starting a new one"
        )),
        Ok(AcquireOutcome::Held { pid: None, .. }) => Err(format!(
            "gemini login already in progress for slot {account} — \
             wait for it to finish before starting a new one"
        )),
        // No path, no `{e}` — see `login_lock_io_error_tag`'s doc comment.
        Err(e) => Err(format!(
            "could not acquire login lock for slot {account} ({}) — check \
             that the accounts directory is writable and try again",
            login_lock_io_error_tag(&e)
        )),
    }
}

/// Records a Gemini slot binding in Code Assist OAuth mode. csq drives
/// the Google OAuth dance ITSELF (Round-7 — operator standard
/// "everything must work right from csq"); the operator no longer
/// needs to run `gemini` interactively first.
///
/// Flow:
/// 1. If `~/.gemini/oauth_creds.json` exists with valid+fresh tokens,
///    skip OAuth (idempotent path).
/// 2. Otherwise, csq's `oauth_flow::run()` binds a loopback listener,
///    opens the user's browser to Google's OAuth authorize endpoint
///    with gemini-cli's extracted client_id + cloud-platform/userinfo
///    scopes, waits for the callback with the auth code, exchanges
///    for tokens at `oauth2.googleapis.com/token`, and writes
///    `~/.gemini/oauth_creds.json` in gemini-cli's exact JSON shape.
/// 3. Writes the per-slot Code Assist OAuth binding marker.
///
/// gemini-cli v0.41.2+ removed the `auth` subcommand entirely — there
/// is NO non-interactive surface for triggering OAuth via gemini-cli.
/// Pre-Round-7 csq tried to delegate to gemini-cli per
/// `feedback_delegate_to_reference_client`; the upstream's UX broke
/// that pattern. csq now owns the OAuth flow but writes the token
/// file in the format gemini-cli still reads — so the next `csq run
/// <slot>` (with `selectedType=oauth-personal` pinned in the per-slot
/// `.gemini/settings.json` via
/// `csq-core/src/providers/gemini/probe.rs::reassert_settings_drift`)
/// sees the OAuth state without prompting.
///
/// Boundary validation: rejects invalid account numbers and slots
/// already bound to a non-Gemini surface (Codex / Anthropic OAuth).
///
/// # Cross-process exclusion
///
/// A concurrent `csq login N --provider gemini` running in a
/// terminal for the SAME slot would otherwise race this command's
/// call into `oauth_login::perform` — both drive the OAuth dance and
/// write the SAME shared `~/.gemini/oauth_creds.json` (gemini-cli has
/// no per-slot credential store), and both write the same per-slot
/// `profiles.json` + identity marker on completion, so the last
/// writer wins silently. The per-account [`AccountLoginLock`]
/// (UX-R1-H3, shared with the CLI's `acquire_login_lock` and
/// [`claude_login_subprocess`]) closes that gap; acquired
/// here, before the `spawn_blocking` call into `perform`, and held
/// for the lifetime of this command.
///
/// # Performance
///
/// On the idempotent path (valid oauth_creds.json), synchronous and
/// fast: file read + JSON parse + binding write, milliseconds.
///
/// On the OAuth path (missing/stale tokens), it BLOCKS until the
/// user completes the browser dance — typically 30-90 seconds. The
/// 10-minute hard timeout in `oauth_flow::run()` bounds the worst
/// case. Wrap in `spawn_blocking` so the Tauri runtime worker stays
/// free; the renderer should show a "Browser opened — finish signing
/// in" banner during the wait.
///
/// # UI flow
///
/// The Add Account modal does NOT need to instruct the user to run
/// `gemini` first (Round-7 — that bad UX is gone). It can invoke
/// this command directly; csq's loopback listener + browser launch
/// + token exchange handles everything end-to-end.
///
/// # Failure modes
///
/// - OAuth flow failed (browser open failed, callback timeout, state
///   mismatch, token exchange returned non-2xx) → `OauthFlowFailed`
///   wrapping a specific `OauthFlowError` variant with diagnostic.
/// - oauth_creds.json present but unreadable (e.g. mode 0) →
///   `GeminiOauthCredsUnreadable`: "check file permissions (expected
///   mode 0600)".
/// - Slot bound to a non-Gemini surface → `OtherSurfaceBound`:
///   "run `csq logout N` to rebind".
/// - Binding write fails → `BindingWriteFailed` (rare; FS / perms).
/// - HOME unset → `CwdResolveFailed`.
#[tauri::command]
pub async fn gemini_provision_oauth(base_dir: String, slot: u16) -> Result<(), String> {
    use csq_core::providers::gemini::oauth_login;

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let base = PathBuf::from(&base_dir);

    // Validated BEFORE the lock acquire, not after: `AccountLoginLock::acquire`
    // calls `create_dir_all(base_dir)` as a convenience for a legitimately
    // missing (but creatable) base dir, which would silently paper over a
    // genuinely bogus `base_dir` — the caller would get a confusing
    // filesystem error (or, worse, the directory would be silently created)
    // instead of the clear, established `"base directory does not exist"`
    // this IPC boundary always returns (see every other command in this
    // file). Checked explicitly here so that contract holds regardless of
    // the lock's own directory-creation convenience behavior.
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    // Cross-process guard (see doc comment above): a concurrent
    // `csq login N --provider gemini` (or another desktop instance —
    // not expected, but the lock is cheap insurance) for this same
    // slot is refused here rather than racing the shared
    // `~/.gemini/oauth_creds.json` write / OAuth flow. Non-blocking
    // try-lock — reports contention immediately instead of hanging
    // the modal on what looks like a slow OAuth flow.
    let _cross_process_lock = acquire_gemini_desktop_login_lock(&base, slot_num)?;

    // All other boundary validation (base_dir existence, other-surface
    // conflict, .env shadow auth) lives inside `oauth_login::perform`
    // — centralized so Tauri / CLI / future callers route through
    // exactly one set of checks. Wrap in spawn_blocking because the
    // function does synchronous filesystem I/O (read of
    // `~/.gemini/oauth_creds.json`, JSON parse, atomic binding-marker
    // write); keeping that off the Tauri runtime worker preserves
    // event-loop responsiveness even though the operation is fast
    // (milliseconds, no subprocess, no browser wait — an internal journal entry).
    //
    // Redact at the IPC boundary: `GeminiOauthCredsMalformed` /
    // `GeminiOauthCredsUnreadable` / `BaseDirMissing` carry a `path`
    // field directly, and `BindingWriteFailed` wraps `ProvisionError`
    // (its own path fields redacted via `ProvisionError::redacted_message`) —
    // `OauthLoginError::redacted_message` handles all of these by
    // variant. `redact_tokens` on top is defense-in-depth for any
    // secret material that reaches a Display string via `{0}`
    // passthrough (round-2 redteam MED; an internal ticket for the path half).
    tokio::task::spawn_blocking(move || oauth_login::perform(&base, slot_num))
        .await
        .map_err(|e| format!("internal: spawn_blocking join failed: {e}"))?
        .map_err(|e| csq_core::error::redact_tokens(&e.redacted_message()))?;
    Ok(())
}

/// Switches the model name stored in the slot's Gemini binding
/// marker. The settings reassertion writer picks up the new value on
/// the next `csq run <slot>` (or session swap). Validates against the
/// static list (`is_known_gemini_model`) — the desktop static picker
/// submits canonical ids only, so aliases (`pro`, `flash`) are
/// refused at this boundary. Returns `()`.
#[tauri::command]
pub fn gemini_switch_model(
    app: AppHandle,
    base_dir: String,
    slot: u16,
    model: String,
) -> Result<(), String> {
    use csq_core::providers::gemini::provisioning::{is_known_gemini_model, set_model_name};

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let model_trimmed = model.trim();
    if !is_known_gemini_model(model_trimmed) {
        return Err(format!(
            "unknown Gemini model `{model_trimmed}` — desktop submits canonical ids only \
             (auto, gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite, gemini-3-pro-preview)"
        ));
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    set_model_name(&base, slot_num, model_trimmed).map_err(|e| {
        format!(
            "switch gemini model on slot {slot} to `{model_trimmed}`: {} ({})",
            e.error_kind_tag(),
            e.redacted_message()
        )
    })?;

    let _ = app.emit(
        "slot-model-changed",
        serde_json::json!({ "slot": slot, "model": model_trimmed, "surface": "gemini" }),
    );
    Ok(())
}

// ── Unit tests ──────────────────────────────────────────────────
//
// Tests the input-validation and mapping logic that runs before
// any filesystem or network I/O. The core logic (discovery, swap,
// quota) is tested exhaustively in csq-core; these tests verify
// the IPC boundary catches bad inputs before they reach core code.

#[cfg(test)]
mod tests {
    use super::*;

    // ── should_emit_url_without_code_diagnostic truth table ─────
    //
    // Pins the gate that prevents the URL-without-code diagnostic
    // from misfiring on user Ctrl-C after the URL is printed but
    // before a code shape is emitted. Only success-with-orphan-URL
    // is a "format may have changed" event; everything else routes
    // through the upstream "user may have cancelled" path.
    // Origin: redteam follow-up to PRs an internal ticket-an internal ticket.

    #[test]
    fn diagnostic_fires_on_success_with_url_and_no_code() {
        assert!(should_emit_url_without_code_diagnostic(true, true, false));
    }

    #[test]
    fn diagnostic_skipped_on_user_cancel_after_url() {
        // The exact regression: codex-cli printed the URL, user
        // killed the process before a code-shape was emitted, exit
        // status is non-zero. Must NOT report "format may have changed".
        assert!(!should_emit_url_without_code_diagnostic(false, true, false));
    }

    #[test]
    fn diagnostic_skipped_when_no_url_was_seen() {
        // codex-cli failed before reaching the URL stage (network,
        // missing dependency, etc.). Upstream "user may have cancelled"
        // is also wrong but the format-change diagnostic is worse.
        assert!(!should_emit_url_without_code_diagnostic(true, false, false));
        assert!(!should_emit_url_without_code_diagnostic(
            false, false, false
        ));
    }

    #[test]
    fn diagnostic_skipped_when_code_was_seen() {
        // Normal success path — code reached the user. No diagnostic.
        assert!(!should_emit_url_without_code_diagnostic(true, true, true));
        assert!(!should_emit_url_without_code_diagnostic(true, false, true));
    }

    // ── acquire_codex_desktop_login_lock: cross-process exclusion ──
    //
    // `complete_codex_login` (the real Tauri command) needs an
    // `AppHandle` + `State<'_, AppState>`, which is impractical to
    // fake outside `tauri::test::mock_app()` (see the sibling
    // placeholder in `claude_login_subprocess.rs`'s test module for
    // the same tracked gap). The lock acquire/refuse branch is
    // extracted into this pure helper specifically so it is testable
    // without that machinery — mirrors the CLI's `acquire_login_lock`.

    #[test]
    fn acquire_codex_desktop_login_lock_refuses_when_held() {
        use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};

        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(31u16).unwrap();

        // Hold the lock ourselves first. Same-process, second `open()`
        // — flock is scoped to the open file description, not the
        // process, so this genuinely reproduces cross-process
        // contention (same pattern `login_lock.rs`'s own tests use).
        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let err = match acquire_codex_desktop_login_lock(dir.path(), account) {
            Err(e) => e,
            Ok(_) => panic!("must refuse while another guard holds the account's lock"),
        };
        assert!(
            err.contains("already in progress"),
            "error must name the contention, not some other failure: {err}"
        );
        assert!(
            err.contains("31"),
            "error must name the contended slot: {err}"
        );
    }

    #[test]
    fn acquire_codex_desktop_login_lock_succeeds_when_free() {
        use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};

        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(32u16).unwrap();

        let guard = acquire_codex_desktop_login_lock(dir.path(), account)
            .expect("must succeed when nothing else holds the account's lock");

        // Prove the returned guard genuinely HOLDS the flock (not a
        // guard that already dropped, or a no-op stand-in): a second
        // acquire attempt for the same account, while `guard` is
        // still alive, must observe contention.
        match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Held { .. } => {}
            AcquireOutcome::Acquired(_) => {
                panic!("returned guard must still hold the lock while alive")
            }
        }
        drop(guard);
    }

    #[test]
    fn acquire_codex_desktop_login_lock_is_per_account() {
        use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};

        let dir = tempfile::TempDir::new().unwrap();
        let held_account = AccountNum::try_from(33u16).unwrap();
        let other_account = AccountNum::try_from(34u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), held_account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        acquire_codex_desktop_login_lock(dir.path(), other_account)
            .expect("a different account's slot must not be blocked");
    }

    // ── login_lock_io_error_tag / L1: no filesystem path over IPC ──
    //
    // `AccountLoginLock::acquire`'s `Err` arm carries a bare `std::io::Error`
    // whose `Display` commonly embeds the absolute lock path (the lock file
    // is hand-opened via `OpenOptions`, so there is no structured `path`
    // field to redact by variant — same shape `redact_home_anywhere`'s own
    // doc comment names). `security.md` MUST-2 / `tauri-commands.md` §
    // Anti-Patterns ban that path reaching the renderer; the fix is to never
    // interpolate `{e}` at all and instead classify by `ErrorKind`, whose
    // `Debug` is a small fixed vocabulary that can never contain one.

    #[test]
    fn login_lock_io_error_tag_maps_known_kinds() {
        assert_eq!(
            login_lock_io_error_tag(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            "permission_denied"
        );
        assert_eq!(
            login_lock_io_error_tag(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            "not_found"
        );
        assert_eq!(
            login_lock_io_error_tag(&std::io::Error::from(std::io::ErrorKind::AlreadyExists)),
            "already_exists"
        );
        assert_eq!(
            login_lock_io_error_tag(&std::io::Error::from(std::io::ErrorKind::Interrupted)),
            "io_other"
        );
    }

    /// The tag is a fixed `&'static str` picked by `ErrorKind` alone, so it
    /// structurally cannot echo whatever path-bearing text the OS put in the
    /// underlying `io::Error`'s `Display` — proven here with an adversarial
    /// message carrying a path, to make the non-leak an assertion rather
    /// than an inference from the source.
    #[test]
    fn login_lock_io_error_tag_ignores_the_error_message_entirely() {
        let poisoned = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied (os error 13) at /Users/attacker/.claude/accounts/.login-4.lock",
        );
        let tag = login_lock_io_error_tag(&poisoned);
        assert_eq!(tag, "permission_denied");
        assert!(
            !tag.contains('/'),
            "tag must never carry path fragments: {tag}"
        );
    }

    /// End-to-end: a genuine filesystem failure (base dir made unwritable)
    /// reaches `acquire_codex_desktop_login_lock`'s `Err(e)` arm, and the
    /// resulting renderer-facing string names neither the tempdir nor any
    /// path separator — only the fixed tag and the slot number. Unix-only:
    /// directory-mode-based permission injection is not portable to Windows
    /// (`test(login): gate the failure-injection fixtures to unix`).
    #[cfg(unix)]
    #[test]
    fn acquire_codex_desktop_login_lock_filesystem_error_omits_the_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(35u16).unwrap();

        // No write permission on base_dir -> OpenOptions::create(true) on
        // the lock file inside it fails with PermissionDenied.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = acquire_codex_desktop_login_lock(dir.path(), account);

        // Restore write permission before the TempDir guard tries to clean
        // up, regardless of what the assertions below find.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("acquire must fail against an unwritable base_dir"),
        };
        assert!(
            err.contains("permission_denied"),
            "error must carry the fixed-vocabulary tag: {err}"
        );
        assert!(err.contains("35"), "error must still name the slot: {err}");
        assert!(
            !err.contains(&dir.path().display().to_string()),
            "error must not carry the lock file's path: {err}"
        );
        assert!(
            !err.contains('/'),
            "error must carry no path separator at all: {err}"
        );
    }

    // ── codex_login_preconditions: base-dir check precedes the lock ──
    //
    // `AccountLoginLock::acquire` convenience-creates its base_dir via
    // `create_dir_all`. Without an explicit `base.is_dir()` check
    // BEFORE the lock acquire, a missing/bad base_dir would be
    // silently created instead of rejected — the exact regression
    // caught on this PR (the desktop convention, pinned by 49 sibling
    // call sites incl. `acknowledge_codex_tos_rejects_missing_base_dir`
    // / `list_codex_models_rejects_missing_base_dir` below, is reject
    // not create).

    #[test]
    fn codex_login_preconditions_rejects_missing_base_dir() {
        let err = match codex_login_preconditions("/nonexistent/csq-base", 1) {
            Err(e) => e,
            Ok(_) => panic!("must reject a nonexistent base_dir"),
        };
        // Assert on the SPECIFIC message, not merely `is_err()` — a
        // regression that drops the explicit check still errors (the
        // lock acquire creates the dir then succeeds, so the actual
        // observed failure without this test's target fix is that the
        // call SUCCEEDS: `is_err()` alone would not have caught it).
        assert_eq!(
            err, "base directory does not exist: /nonexistent/csq-base",
            "got: {err}"
        );
        assert!(
            !std::path::Path::new("/nonexistent/csq-base").exists(),
            "the bad path must NOT have been created as a side effect"
        );
    }

    #[test]
    fn codex_login_preconditions_rejects_invalid_account() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = match codex_login_preconditions(&dir.path().to_string_lossy(), 0) {
            Err(e) => e,
            Ok(_) => panic!("must reject account 0"),
        };
        assert!(err.contains("invalid account"), "got: {err}");
    }

    #[test]
    fn codex_login_preconditions_succeeds_and_holds_lock_for_valid_input() {
        use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};

        let dir = tempfile::TempDir::new().unwrap();
        let (account_num, base, guard) =
            codex_login_preconditions(&dir.path().to_string_lossy(), 41).unwrap();
        assert_eq!(account_num.get(), 41);
        assert_eq!(base, dir.path());

        // The returned guard genuinely holds the lock while alive.
        match AccountLoginLock::acquire(dir.path(), account_num).unwrap() {
            AcquireOutcome::Held { .. } => {}
            AcquireOutcome::Acquired(_) => panic!("guard must still hold the lock while alive"),
        }
        drop(guard);
    }

    // ── list_providers ─────────────────────────────────────────

    #[test]
    fn list_providers_includes_ollama() {
        let providers = list_providers().unwrap();
        let ollama = providers
            .iter()
            .find(|p| p.id == "ollama")
            .expect("ollama should appear in the desktop provider list");
        assert_eq!(ollama.auth_type, "none");
        assert!(ollama.default_base_url.is_some());
    }

    #[test]
    fn list_providers_includes_anthropic() {
        let providers = list_providers().unwrap();
        assert!(providers.iter().any(|p| p.id == "claude"));
    }

    #[test]
    fn list_providers_auth_types_are_valid() {
        let providers = list_providers().unwrap();
        for p in &providers {
            assert!(
                ["oauth", "bearer", "none"].contains(&p.auth_type.as_str()),
                "unexpected auth_type '{}' for provider '{}'",
                p.auth_type,
                p.id
            );
        }
    }

    // ── set_provider_key validation ────────────────────────────
    //
    // These tests exercise the validation that runs before any
    // filesystem access. Each case returns Err before touching disk.

    #[test]
    fn set_provider_key_rejects_unknown_provider() {
        let err = set_provider_key("/fake".into(), "nonexistent".into(), "key".into()).unwrap_err();
        assert!(err.contains("unknown provider"));
    }

    #[test]
    fn set_provider_key_rejects_oauth_provider() {
        let err = set_provider_key("/fake".into(), "claude".into(), "key".into()).unwrap_err();
        assert!(err.contains("uses OAuth"));
    }

    #[test]
    fn set_provider_key_rejects_empty_key() {
        let err = set_provider_key("/fake".into(), "mm".into(), "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn set_provider_key_rejects_oversized_key() {
        let long_key = "x".repeat(5000);
        let err = set_provider_key("/fake".into(), "mm".into(), long_key).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn set_provider_key_rejects_key_shorter_than_min() {
        // Seven-char key passes the old "non-empty" gate but is
        // obviously not a real API key — MM JWTs are kilobytes, Z.AI
        // keys are 40+ chars. Must match the csq-core shape gate.
        let err = set_provider_key("/fake".into(), "mm".into(), "short12".into()).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn set_provider_key_rejects_key_with_control_char() {
        // ESC (0x1b) slipping through the Bearer form's password
        // input is the desktop twin of the CLI bug in an internal journal entry
        let key = "valid-prefix\x1b-rest".to_string();
        let err = set_provider_key("/fake".into(), "mm".into(), key).unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn set_provider_key_order_rejects_too_short_before_too_long() {
        // Sanity: the order of checks matters only when all three
        // could apply. Verify "too long" still fires before "too
        // short" — a 5000-char key with control chars should still
        // hit the too-long branch, not control-char, because the
        // length ceiling is a cheaper check and a huge input is
        // almost certainly a clipboard mishap.
        let key = "x".repeat(5000);
        let err = set_provider_key("/fake".into(), "mm".into(), key).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    // ── bind_keyless_provider validation ───────────────────────

    #[test]
    fn bind_keyless_provider_rejects_unknown_provider() {
        let err = bind_keyless_provider("/fake".into(), "nonexistent".into(), 1, None).unwrap_err();
        assert!(err.contains("unknown provider"));
    }

    #[test]
    fn bind_keyless_provider_rejects_keyed_provider() {
        let err = bind_keyless_provider("/fake".into(), "mm".into(), 1, None).unwrap_err();
        assert!(err.contains("not keyless"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_rejects_invalid_slot() {
        let err = bind_keyless_provider("/fake".into(), "ollama".into(), 0, None).unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_rejects_missing_base_dir() {
        let err = bind_keyless_provider("/nonexistent/base/dir".into(), "ollama".into(), 5, None)
            .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn bind_keyed_provider_refuses_oauth_slot_twin_parity() {
        // CLI/desktop twin parity (`discovery_codex_login_cli_desktop_twin_parity`):
        // the desktop 3P bind inherits the core surface-conflict guard, so the
        // an internal ticket clobber (silent OAuth override + orphaned by_slot) is unreachable
        // from the Tauri UI. Plant a post-M4-12 Anthropic OAuth slot (by_slot →
        // identity, NO legacy mirror) and assert the bind is refused.
        use csq_core::accounts::identity_store::{credentials_path_for, identity_path, IdentityId};
        use csq_core::accounts::profiles::{profiles_path, save, ProfilesFile};
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let idir = identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&idir).unwrap();
        std::fs::write(
            idir.join("identity.json"),
            br#"{"email":"x","provider":"anthropic","created_at":"t","key_id":null}"#,
        )
        .unwrap();
        std::fs::write(credentials_path_for(dir.path(), uuid), b"{}").unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("3".to_string(), uuid);
        save(&profiles_path(dir.path()), &pf).unwrap();

        let err = bind_keyed_provider(
            dir.path().to_string_lossy().into_owned(),
            "mm".into(),
            3,
            "sk-test-minimax-123".into(),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("Anthropic OAuth") && err.contains("csq logout 3"),
            "desktop bind must surface the surface-conflict refusal: {err}"
        );
        assert!(!dir.path().join("config-3/settings.json").exists());
    }

    #[test]
    fn bind_keyless_provider_rejects_empty_model_override() {
        // An all-whitespace model from the UI dropdown would silently
        // write `ANTHROPIC_MODEL=""` and make CC unusable. Reject
        // before the filesystem write.
        let err = bind_keyless_provider("/fake".into(), "ollama".into(), 1, Some("   ".into()))
            .unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_ollama_writes_settings() {
        // End-to-end: real temp dir, real ollama bind. Verifies the
        // command writes the slot's settings.json with the placeholder
        // auth token and base URL.
        let dir = tempfile::TempDir::new().unwrap();
        let result = bind_keyless_provider(
            dir.path().to_string_lossy().into_owned(),
            "ollama".into(),
            9,
            None,
        );
        assert!(result.is_ok(), "bind should succeed: {result:?}");

        let settings_path = dir.path().join("config-9/settings.json");
        assert!(settings_path.exists());
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert!(content.contains("\"ANTHROPIC_AUTH_TOKEN\": \"ollama\""));
        assert!(content.contains("localhost:11434"));
    }

    // ── set_slot_model_write validation ─────────────────────

    #[test]
    fn set_slot_model_rejects_invalid_slot() {
        let err = set_slot_model_write("/fake".into(), 0, "gemma4".into()).unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn set_slot_model_rejects_empty_model() {
        let err = set_slot_model_write("/fake".into(), 1, "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn set_slot_model_rejects_missing_base_dir() {
        let err =
            set_slot_model_write("/nonexistent/base/dir".into(), 1, "gemma4".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn set_slot_model_errors_when_slot_not_bound() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = set_slot_model_write(
            dir.path().to_string_lossy().into_owned(),
            7,
            "gemma4".into(),
        )
        .unwrap_err();
        assert!(err.contains("not bound"), "got: {err}");
    }

    #[test]
    fn set_slot_model_rewrites_every_model_key() {
        // Bind an ollama slot, then retarget its model. All five
        // MODEL_KEYS in config-N/settings.json should reflect the
        // new value. Other env keys (ANTHROPIC_BASE_URL,
        // ANTHROPIC_AUTH_TOKEN) survive untouched.
        let dir = tempfile::TempDir::new().unwrap();
        csq_core::accounts::third_party::bind_provider_to_slot(
            dir.path(),
            "ollama",
            csq_core::types::AccountNum::try_from(5u16).unwrap(),
            None,
            None,
        )
        .unwrap();

        set_slot_model_write(
            dir.path().to_string_lossy().into_owned(),
            5,
            "qwen3:latest".into(),
        )
        .unwrap();

        let path = dir.path().join("config-5/settings.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for key in csq_core::session::merge::MODEL_KEYS {
            assert_eq!(
                v.pointer(&format!("/env/{}", key)).and_then(|x| x.as_str()),
                Some("qwen3:latest"),
                "{key} should reflect the new model"
            );
        }
        // Base URL and auth token survived.
        assert_eq!(
            v.pointer("/env/ANTHROPIC_BASE_URL")
                .and_then(|x| x.as_str()),
            Some("http://localhost:11434")
        );
        assert_eq!(
            v.pointer("/env/ANTHROPIC_AUTH_TOKEN")
                .and_then(|x| x.as_str()),
            Some("ollama")
        );
    }

    #[test]
    fn bind_keyless_provider_with_model_override_writes_chosen_model() {
        let dir = tempfile::TempDir::new().unwrap();
        bind_keyless_provider(
            dir.path().to_string_lossy().into_owned(),
            "ollama".into(),
            11,
            Some("qwen3:latest".into()),
        )
        .unwrap();

        let content = std::fs::read_to_string(dir.path().join("config-11/settings.json")).unwrap();
        assert!(
            content.contains("\"ANTHROPIC_MODEL\": \"qwen3:latest\""),
            "expected model override in settings, got: {content}"
        );
    }

    #[test]
    fn list_ollama_models_returns_vec() {
        // Can't assume Ollama is installed in CI — just assert the
        // command returns Ok (possibly empty). Exhaustive parsing
        // tests live in csq_core::providers::ollama.
        let result = list_ollama_models();
        assert!(result.is_ok());
    }

    // ── provider_cli_installed gating ──────────────────────────

    #[test]
    fn provider_cli_installed_rejects_unknown_binary() {
        // Security gate: only the known surface binaries are probed. An
        // arbitrary caller-supplied string returns false without touching PATH.
        assert!(!provider_cli_installed("evil-binary".into()));
        assert!(!provider_cli_installed("rm".into()));
        assert!(!provider_cli_installed("".into()));
        assert!(!provider_cli_installed("codex; rm -rf /".into()));
    }

    /// an internal journal entry W3-5: `kimi`/`grok` join the known-binary allowlist so
    /// the Add Account modal's native-CLI pre-flight (mirroring the
    /// codex/gemini `cli-missing` prompt) can probe them. Regression
    /// mirrors `find_cli_binary_finds_codex_in_path` in
    /// `csq_core::accounts::login`, exercised through the desktop wrapper.
    #[cfg(unix)]
    #[test]
    fn provider_cli_installed_finds_kimi_and_grok_on_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        for name in ["kimi", "grok"] {
            let bin = dir.path().join(name);
            std::fs::write(&bin, "#!/bin/sh").unwrap();
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();
        }

        // testing.md Rule 6: env mutation MUST hold the workspace-shared
        // test_env lock (cargo test is multi-threaded).
        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        let empty_home = tempfile::TempDir::new().unwrap();
        unsafe {
            std::env::set_var("PATH", dir.path());
            std::env::set_var("HOME", empty_home.path());
        }

        let kimi_found = provider_cli_installed("kimi".into());
        let grok_found = provider_cli_installed("grok".into());

        unsafe {
            match prev_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(_shared_env_guard);

        assert!(
            kimi_found,
            "kimi on PATH must be found through the allowlist gate"
        );
        assert!(
            grok_found,
            "grok on PATH must be found through the allowlist gate"
        );
    }

    /// C6 (an internal journal entry issue 1) — regression for the known-install-dir
    /// fallback gap. A self-managed kimi install lands at
    /// `~/.kimi-code/bin/kimi` and is NOT symlinked onto `$PATH` (that's
    /// exactly the shape `known_install_dirs` exists to catch — spec/13
    /// §5). The old `find_cli_binary`-only resolver has no awareness of
    /// that dir, so this test fails on the pre-fix code (empty PATH walk,
    /// no known-dir fallback) and passes once `provider_cli_installed`
    /// chains through `cli_deps::install_path::find_in_path`. Mirrors
    /// `find_in_path_falls_back_to_known_kimi_dir` in
    /// `csq_core::cli_deps::install_path`.
    #[cfg(unix)]
    #[test]
    fn provider_cli_installed_finds_kimi_via_known_install_dir_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::TempDir::new().unwrap();
        let bin_dir = home.path().join(".kimi-code").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bin = bin_dir.join("kimi");
        std::fs::write(&bin, "#!/bin/sh").unwrap();
        let mut perms = std::fs::metadata(&bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin, perms).unwrap();

        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        unsafe {
            // Empty PATH — the walk must find nothing, forcing the
            // known-install-dir fallback to be the ONLY path to a hit.
            std::env::set_var("PATH", "");
            std::env::set_var("HOME", home.path());
        }

        let found = provider_cli_installed("kimi".into());

        unsafe {
            match prev_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(_shared_env_guard);

        assert!(
            found,
            "kimi installed at ~/.kimi-code/bin (not on PATH) must be found \
             via the known-install-dir fallback"
        );
    }

    // ── rename_account validation ──────────────────────────────

    #[test]
    fn rename_account_rejects_invalid_account_number() {
        let err = rename_account("/fake".into(), 0, "test".into()).unwrap_err();
        assert!(err.contains("invalid account"));
    }

    #[test]
    fn rename_account_rejects_empty_name() {
        let err = rename_account("/fake".into(), 1, "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    /// RN1-D3: `rename_account` rejects labels exceeding 256 characters.
    #[test]
    fn rename_account_rejects_oversize_label() {
        // Arrange: construct a 257-character label.
        let long_name = "a".repeat(257);
        // Act
        let err = rename_account("/fake".into(), 1, long_name).unwrap_err();
        // Assert
        assert!(
            err.contains("exceeds 256"),
            "expected 'exceeds 256' in error, got: {err}"
        );
    }

    /// RN1-D3: `rename_account` rejects labels containing ASCII control
    /// characters (e.g. tab U+0009, newline U+000A, null U+0000).
    #[test]
    fn rename_account_rejects_control_char_label() {
        for control in ["\t", "\n", "\x00", "\x1b"] {
            let name = format!("legit{control}name");
            let err = rename_account("/fake".into(), 1, name.clone()).unwrap_err();
            assert!(
                err.contains("control characters"),
                "expected 'control characters' in error for input {:?}, got: {err}",
                name
            );
        }
    }

    // ── ClaudeLoginView conversion ─────────────────────────────

    #[test]
    fn claude_login_view_from_login_request() {
        let req = LoginRequest {
            auth_url: "https://example.com/auth".into(),
            state: "state123".into(),
            account: 5,
            expires_in_secs: 600,
        };
        let view = ClaudeLoginView::from(req);
        assert_eq!(view.auth_url, "https://example.com/auth");
        assert_eq!(view.state, "state123");
        assert_eq!(view.account, 5);
        assert_eq!(view.expires_in_secs, 600);
    }

    // ── PR-C9a (an internal journal entry finding 5) — IPC audit: whitelist, not blacklist ─

    /// Recursively collect every object key under `v`. The JSON is an
    /// arbitrary `serde_json::Value`; this walks nested objects +
    /// arrays so flatten / nested-struct shapes are inspected too.
    fn collect_json_keys(v: &serde_json::Value, out: &mut std::collections::HashSet<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, sub) in map {
                    out.insert(k.clone());
                    collect_json_keys(sub, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for sub in arr {
                    collect_json_keys(sub, out);
                }
            }
            _ => {}
        }
    }

    /// Whitelist audit helper — fails if `actual` contains any key
    /// not in `expected`. Pre-PR-C9a the IPC tests blacklisted a
    /// fixed set of token-shaped keys (`access_token`, etc.), but
    /// that list missed Codex-specific shapes (`sess-*`, `rt_*`,
    /// `OPENAI_API_KEY` with caps, `account_id`, `tokens`). A
    /// whitelist closes that gap: any future field addition that
    /// accidentally includes a token must be explicitly added to
    /// `expected`, forcing the author to see the audit.
    #[track_caller]
    fn assert_ipc_keys_whitelisted<T: serde::Serialize>(value: &T, expected: &[&str]) {
        let json = serde_json::to_value(value).expect("serialize");
        let mut actual: std::collections::HashSet<String> = std::collections::HashSet::new();
        collect_json_keys(&json, &mut actual);
        let expected_set: std::collections::HashSet<String> =
            expected.iter().map(|s| (*s).to_string()).collect();
        let extra: Vec<&String> = actual.difference(&expected_set).collect();
        assert!(
            extra.is_empty(),
            "IPC payload contains non-whitelisted keys {:?}. \
             Audit the type — if the new field is safe, add it to the \
             whitelist explicitly. Whitelist (not blacklist) is mandatory \
             per an internal journal entry finding 5.",
            extra
        );
    }

    /// AccountView exposes the `surface` field and never leaks
    /// credential material. This is the Tauri IPC audit per
    /// `tauri-commands.md` MUST Rule 3.
    #[test]
    fn account_view_serializes_surface_without_secrets() {
        let v = AccountView {
            id: 1,
            label: "Work".into(),
            source: "anthropic".into(),
            surface: "claude-code".into(),
            has_credentials: true,
            has_quota: false,
            five_hour_pct: 0.0,
            five_hour_resets_in: None,
            seven_day_pct: 0.0,
            seven_day_resets_in: None,
            updated_at: 0.0,
            token_status: "healthy".into(),
            expires_in_secs: None,
            last_refresh_error: None,
            provider_id: None,
            billing_mode: "subscription".to_string(),
            quota_kind: "utilization".to_string(),
            balance_display: None,
            gemini_counter_today: None,
            gemini_rate_limit_reset_at: None,
            gemini_selected_model: None,
            gemini_effective_model: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""surface":"claude-code""#));
        // The four PR-G5 Gemini fields are `skip_serializing_if =
        // "Option::is_none"` so claude-code slots produce a payload
        // identical to the pre-PR-G5 shape — no new keys leak into
        // the wire format for non-Gemini accounts.
        assert!(!json.contains("gemini_counter_today"));
        assert!(!json.contains("gemini_rate_limit_reset_at"));
        assert!(!json.contains("gemini_selected_model"));
        assert!(!json.contains("gemini_effective_model"));
        // Whitelist the full set of AccountView fields. Any future
        // addition must be added here explicitly so an author must
        // see the audit when introducing a field.
        assert_ipc_keys_whitelisted(
            &v,
            &[
                "id",
                "label",
                "source",
                "surface",
                "has_credentials",
                "five_hour_pct",
                "five_hour_resets_in",
                "seven_day_pct",
                "seven_day_resets_in",
                "updated_at",
                "token_status",
                "expires_in_secs",
                "last_refresh_error",
                "provider_id",
                // HIGH-1 (an internal ticket redteam): has_quota tells the renderer
                // whether a quota row was actually found for this slot —
                // a plain bool, no credential material.
                "has_quota",
                // Phase B (an internal journal entry): billing_mode is sent on
                // every account so the renderer can branch on
                // pay-per-token vs subscription vs local. Audited
                // safe — the field is a fixed-vocabulary tag
                // (`subscription` | `api-key` | `local`) with no
                // credential material.
                "billing_mode",
                // Phase B' (an internal journal entry D5): catalog quota_kind is
                // surfaced so the renderer can branch on Unknown slots
                // (pay-per-token) and render the new BillingLedger
                // view instead of stuck-at-zero 5h/7d bars. Audited
                // safe — fixed-vocabulary tag from the catalog
                // (`utilization` | `counter` | `unknown`).
                "quota_kind",
                // `balance_display` is skip_serializing_if=Option::is_none,
                // so it doesn't appear in the serialized payload for
                // subscription/utilization accounts (None here). Audited safe —
                // it is a formatted monetary amount string ("$196.42"), not a
                // credential, key, or path. It IS whitelisted here (a superset
                // is fine) AND exercised with a populated `Some` value by
                // `account_view_balance_variant_serializes_whitelisted` below,
                // so the MUST-3 audit actually gates the field on the wire.
                "balance_display",
                //
                // PR-G5 Gemini fields are skip_serializing_if=Option::is_none,
                // so they don't appear in the serialized whitelist for
                // non-Gemini accounts. They're added to the whitelist
                // entry below in the gemini-populated test instead.
            ],
        );
    }

    /// an internal ticket redteam (security M2): exercise the MUST-3 whitelist audit with
    /// `balance_display` POPULATED (`Some`). The None-case test above cannot
    /// gate the field because `skip_serializing_if=Option::is_none` drops it
    /// from the wire; this test proves the populated field is a single scalar
    /// key (no flattened sub-key leak) and is whitelisted.
    #[test]
    fn account_view_balance_variant_serializes_whitelisted() {
        let v = AccountView {
            id: 11,
            label: "DeepSeek".into(),
            source: "third_party".into(),
            surface: "claude-code".into(),
            has_credentials: true,
            has_quota: false,
            five_hour_pct: 0.0,
            five_hour_resets_in: None,
            seven_day_pct: 0.0,
            seven_day_resets_in: None,
            updated_at: 0.0,
            token_status: "healthy".into(),
            expires_in_secs: None,
            last_refresh_error: None,
            provider_id: Some("deepseek".into()),
            billing_mode: "api-key".to_string(),
            quota_kind: "balance".to_string(),
            balance_display: Some("$196.42".into()),
            gemini_counter_today: None,
            gemini_rate_limit_reset_at: None,
            gemini_selected_model: None,
            gemini_effective_model: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            json.contains(r#""balance_display":"$196.42""#),
            "populated balance_display must serialize: {json}"
        );
        // The populated field must be gated by the whitelist audit — a
        // formatted monetary string, no credential/key/path.
        assert_ipc_keys_whitelisted(
            &v,
            &[
                "id",
                "label",
                "source",
                "surface",
                "has_credentials",
                "five_hour_pct",
                "five_hour_resets_in",
                "seven_day_pct",
                "seven_day_resets_in",
                "updated_at",
                "token_status",
                "expires_in_secs",
                "last_refresh_error",
                "provider_id",
                "has_quota",
                "billing_mode",
                "quota_kind",
                "balance_display",
            ],
        );
    }

    // ── PR-C8 Codex command IPC contract ───────────────────────
    //
    // Structural audit on every new Serialize type per
    // `tauri-commands.md` MUST Rule 3. an internal journal entry finding 5 flips
    // the blacklist harness to a per-struct whitelist so a future
    // `#[serde(flatten)] extra: CodexCredentials` slip is caught.

    #[test]
    fn codex_start_login_view_keys_whitelisted() {
        let v = csq_core::providers::codex::desktop_login::StartLoginView {
            account: 7,
            tos_required: true,
            keychain: "absent".into(),
            awaiting_keychain_decision: false,
            // Round-2 redteam MEDIUM-5 (an internal journal entry) — surface the
            // ChatGPT Security Settings prerequisite to the desktop UI
            // BEFORE the device-auth subprocess starts.
            device_auth_prereq_message:
                csq_core::providers::codex::desktop_login::DEVICE_AUTH_PREREQ_MESSAGE.into(),
            device_auth_prereq_url:
                csq_core::providers::codex::desktop_login::DEVICE_AUTH_PREREQ_URL.into(),
        };
        assert_ipc_keys_whitelisted(
            &v,
            &[
                "account",
                "tos_required",
                "keychain",
                "awaiting_keychain_decision",
                "device_auth_prereq_message",
                "device_auth_prereq_url",
            ],
        );
    }

    #[test]
    fn codex_complete_login_view_keys_whitelisted() {
        let v = csq_core::providers::codex::desktop_login::CompleteLoginView {
            account: 5,
            label: "codex-5/abc".into(),
        };
        assert_ipc_keys_whitelisted(&v, &["account", "label"]);
    }

    #[test]
    fn codex_device_code_info_keys_whitelisted() {
        let v = csq_core::providers::codex::desktop_login::DeviceCodeInfo {
            user_code: "ABCD-EFGH".into(),
            verification_url: "https://chat.openai.com/codex/verify".into(),
        };
        assert_ipc_keys_whitelisted(&v, &["user_code", "verification_url"]);
    }

    #[test]
    fn codex_model_list_keys_whitelisted() {
        let v = csq_core::providers::codex::models::bundled();
        // CodexModelList = { models: [CodexModelEntry], source, fetched_at }
        // CodexModelEntry = { id, label }
        assert_ipc_keys_whitelisted(
            &v,
            &[
                // top-level
                "models",
                "source",
                "fetched_at",
                // per-entry
                "id",
                "label",
            ],
        );
    }

    /// Regression: a hypothetical flatten slip would introduce
    /// keys like `access_token` or `tokens` into the IPC payload.
    /// The whitelist helper must flag any extra key — this test
    /// synthesizes that scenario by serializing a tuple struct
    /// with a token-shaped field and asserting the helper complains.
    #[test]
    #[should_panic(expected = "non-whitelisted keys")]
    fn whitelist_helper_panics_on_extra_key() {
        #[derive(serde::Serialize)]
        struct Leak {
            account: u32,
            access_token: String, // would-be leak
        }
        let v = Leak {
            account: 1,
            access_token: "sk-ant-oat01-dangerous".into(),
        };
        assert_ipc_keys_whitelisted(&v, &["account"]);
    }

    // ── acknowledge_codex_tos validation ──────────────────────

    #[tokio::test]
    async fn acknowledge_codex_tos_rejects_missing_base_dir() {
        let err = acknowledge_codex_tos("/nonexistent/csq-base".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[tokio::test]
    async fn acknowledge_codex_tos_writes_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::codex::tos::is_acknowledged(dir.path()));
    }

    #[tokio::test]
    async fn acknowledge_codex_tos_is_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::codex::tos::is_acknowledged(dir.path()));
    }

    // ── start_codex_login validation ──────────────────────────

    #[tokio::test]
    async fn start_codex_login_rejects_invalid_account() {
        let err = start_codex_login("/tmp".into(), 0).await.unwrap_err();
        assert!(err.contains("invalid account"), "got: {err}");
    }

    #[tokio::test]
    async fn start_codex_login_returns_tos_required_when_marker_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let view = start_codex_login(dir.path().to_string_lossy().into_owned(), 2)
            .await
            .unwrap();
        assert_eq!(view.account, 2);
        assert!(
            view.tos_required,
            "fresh base_dir has no marker → tos_required must be true"
        );
    }

    #[tokio::test]
    async fn start_codex_login_returns_tos_not_required_after_acknowledge() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        let view = start_codex_login(dir.path().to_string_lossy().into_owned(), 2)
            .await
            .unwrap();
        assert!(!view.tos_required);
    }

    // GH an internal ticket retired `refuse_login_if_native_bound` and the three
    // tests that lived here (`_refuses_kimi_bound_slot`,
    // `_refuses_grok_bound_slot`, `_allows_unbound_slot`). Coverage for the
    // new cleanup-not-refuse behavior lives at the layer that now performs
    // it: `complete_login_clears_stale_{gemini,native}_marker_after_login`
    // (`csq-core/src/providers/codex/desktop_login.rs`) for the Codex twin,
    // and `finalize_login_clears_stale_{gemini,native}_marker`
    // (`csq-core/src/accounts/login.rs`) for the Anthropic path every other
    // former caller of this guard (`start_claude_login_race`,
    // `start_claude_login_subprocess`, `start_claude_login`,
    // `submit_oauth_code`) funnels through.

    // ── list_codex_models validation ──────────────────────────

    #[tokio::test]
    async fn list_codex_models_rejects_missing_base_dir() {
        let err = list_codex_models("/nonexistent/csq-base".into())
            .await
            .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[tokio::test]
    async fn list_codex_models_no_account_uses_cli_probe_or_bundled() {
        // No Codex account → HTTP fetch fails ("no codex account
        // provisioned"). Without the codex-cli probe (PR-an internal ticket-fix /
        // /autonomize item 2), this would fall straight through to
        // bundled. With the probe, it falls through to codex-cli IF
        // installed in the test env, otherwise to bundled. Either
        // verdict satisfies the contract: the picker MUST get a
        // non-empty list with a source other than Live.
        let dir = tempfile::TempDir::new().unwrap();
        let list = list_codex_models(dir.path().to_string_lossy().into_owned())
            .await
            .unwrap();
        use csq_core::providers::codex::models::ModelSource;
        assert!(
            matches!(list.source, ModelSource::CodexCli | ModelSource::Bundled),
            "no Codex account → expected CodexCli or Bundled; got {:?}",
            list.source,
        );
        assert!(!list.models.is_empty(), "list must never be empty");
    }

    #[test]
    fn account_view_surface_codex_variant_roundtrips() {
        let v = AccountView {
            id: 3,
            label: "codex-3".into(),
            source: "codex".into(),
            surface: "codex".into(),
            has_credentials: true,
            has_quota: true,
            five_hour_pct: 10.0,
            five_hour_resets_in: Some(3600),
            seven_day_pct: 5.0,
            seven_day_resets_in: Some(86_400),
            updated_at: 1_775_722_800.0,
            token_status: "healthy".into(),
            expires_in_secs: Some(7200),
            last_refresh_error: None,
            provider_id: None,
            billing_mode: "subscription".to_string(),
            quota_kind: "utilization".to_string(),
            balance_display: None,
            gemini_counter_today: None,
            gemini_rate_limit_reset_at: None,
            gemini_selected_model: None,
            gemini_effective_model: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""source":"codex""#));
        assert!(json.contains(r#""surface":"codex""#));
    }

    #[test]
    fn account_view_surface_gemini_variant_serializes_quota_fields() {
        // PR-G5: when a Gemini slot has counter / 429 / model fields
        // populated, all four optional fields appear in the wire
        // payload. None of them carry secret material — keys live in
        // the platform vault, paths are absolute filesystem strings.
        let v = AccountView {
            id: 9,
            label: "gemini-9".into(),
            source: "manual".into(),
            surface: "gemini".into(),
            has_credentials: true,
            has_quota: false,
            five_hour_pct: 0.0,
            five_hour_resets_in: None,
            seven_day_pct: 0.0,
            seven_day_resets_in: None,
            updated_at: 0.0,
            token_status: "healthy".into(),
            expires_in_secs: None,
            last_refresh_error: None,
            provider_id: None,
            billing_mode: "subscription".to_string(),
            quota_kind: "utilization".to_string(),
            balance_display: None,
            gemini_counter_today: Some(42),
            gemini_rate_limit_reset_at: Some("2026-04-26T13:00:00Z".into()),
            gemini_selected_model: Some("gemini-3-pro-preview".into()),
            gemini_effective_model: Some("gemini-2.5-pro".into()),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""surface":"gemini""#));
        assert!(json.contains(r#""gemini_counter_today":42"#));
        assert!(json.contains(r#""gemini_rate_limit_reset_at":"2026-04-26T13:00:00Z""#));
        assert!(json.contains(r#""gemini_selected_model":"gemini-3-pro-preview""#));
        assert!(json.contains(r#""gemini_effective_model":"gemini-2.5-pro""#));
        // No secret-shaped keys leak into the IPC payload.
        assert!(!json.contains("api_key"));
        assert!(!json.contains("AIza"));
    }

    // ── an internal ticket — utilization quota surface-match gate ─────────────────
    //
    // Origin: an internal ticket + an internal journal entry H2. Codex slots (and any future
    // utilization-shape surface) MUST surface their own 5h/7d numbers
    // through the IPC payload; the gate is `quota.surface ==
    // account.surface`, NOT `account.source == Anthropic`. The
    // surface-match gate is also the structural defense against the
    // an internal journal entry H2 leakage path: a slot ID rebound from one surface
    // to another with a stale quota.json[N] from the prior occupant must
    // NOT ship the prior surface's numbers.

    /// Helper: write a minimal Codex credential blob into a tempdir,
    /// returning the path. Mirrors the Codex auth.json shape that
    /// `discover_codex` recognises.
    fn seed_codex_slot(creds_dir: &std::path::Path, slot: u16) {
        std::fs::write(
            creds_dir.join(format!("codex-{slot}.json")),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"eyJacc","refresh_token":"rt_x","id_token":"eyJid","account_id":"uuid"},"last_refresh":"2026-04-22T00:00:00Z"}"#,
        )
        .unwrap();
    }

    /// Helper: write a minimal Anthropic ClaudeCode credential blob.
    fn seed_claude_slot(creds_dir: &std::path::Path, slot: u16) {
        std::fs::write(
            creds_dir.join(format!("{slot}.json")),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();
    }

    /// Helper: write a quota.json with the given account entries.
    fn write_quota_file(base: &std::path::Path, rows: &[(u16, &str, f64, f64)]) {
        use csq_core::quota::{AccountQuota, QuotaFile, UsageWindow};
        let mut f = QuotaFile::empty();
        f.schema_version = 2;
        for (slot, surface, five_h, seven_d) in rows {
            let mut q = AccountQuota {
                surface: (*surface).to_string(),
                ..AccountQuota::default()
            };
            q.five_hour = Some(UsageWindow {
                used_percentage: *five_h,
                resets_at: 4_000_000_000,
            });
            q.seven_day = Some(UsageWindow {
                used_percentage: *seven_d,
                resets_at: 4_000_500_000,
            });
            q.updated_at = 1_775_722_800.0;
            f.set(*slot, q);
        }
        csq_core::quota::state::save_state(base, &f).unwrap();
    }

    /// Codex slot with a codex-surfaced quota row → IPC payload surfaces
    /// the 5h/7d numbers. This is the v2.7.0 user-visible gap closed by
    /// an internal ticket.
    #[test]
    fn get_accounts_codex_slot_surfaces_codex_quota() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        seed_codex_slot(&creds_dir, 7);
        write_quota_file(dir.path(), &[(7, "codex", 42.0, 18.0)]);

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 7)
            .expect("codex slot 7 visible");
        assert_eq!(v.surface, "codex");
        assert_eq!(v.source, "codex");
        assert_eq!(v.five_hour_pct, 42.0, "codex 5h utilization must surface");
        assert_eq!(v.seven_day_pct, 18.0, "codex 7d utilization must surface");
        assert!(v.five_hour_resets_in.is_some());
        assert!(v.seven_day_resets_in.is_some());
    }

    /// **2026-05-25 codex token-badge regression (host slot 8).** A Codex
    /// slot must derive its token status from the ChatGPT JWT `exp` claim, NOT
    /// from the Anthropic `credentials.json` path. Pre-fix, the desktop badge
    /// builder routed every Codex slot through `expect_anthropic()`, so the
    /// load failed and the badge showed `missing` ("No token") even for a
    /// healthy Codex login. This pins the Codex branch: a far-future JWT exp
    /// yields a `healthy` status with a positive `expires_in_secs`.
    #[test]
    fn get_accounts_codex_slot_token_status_from_jwt_not_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // JWT with exp=4102444800 (year 2100): header.payload.sig, payload is
        // base64url({"exp":4102444800}).
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.sig";
        std::fs::write(
            creds_dir.join("codex-7.json"),
            format!(
                r#"{{"auth_mode":"chatgpt","tokens":{{"access_token":"{jwt}","refresh_token":"rt","id_token":"{jwt}","account_id":"uuid"}},"last_refresh":"2026-04-22T00:00:00Z"}}"#
            ),
        )
        .unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 7)
            .expect("codex slot 7 visible");
        assert_eq!(v.source, "codex");
        assert_ne!(
            v.token_status, "missing",
            "codex slot must NOT report `missing` — that was the No-token regression"
        );
        assert_eq!(v.token_status, "healthy", "far-future JWT exp → healthy");
        assert!(
            v.expires_in_secs.map(|s| s > 0).unwrap_or(false),
            "codex slot must carry a positive expires_in_secs from the JWT exp; got {:?}",
            v.expires_in_secs
        );
    }

    /// **2026-05-26 Gemini token-badge follow-up to an internal journal entry** The Codex
    /// fix introduced a Codex-specific token-status branch, but Gemini slots
    /// remained routed through the Anthropic else branch — which loads the
    /// Anthropic `credentials.json` at the slot's UUID path and reports
    /// `missing` for any Gemini slot (Gemini creds live at
    /// `credentials/gemini-<N>.json`, never at `credentials.json`). This
    /// pins the Gemini branch added at csq/src/desktop/commands/mod.rs:183:
    /// a Gemini slot surfaces with `token_status="healthy"` and
    /// `expires_in_secs=None` (no countdown — Gemini auth has no single
    /// JWT exp the badge can render). Sibling of the Codex fix; closes the
    /// same `account-terminal-separation.md` MUST Rule 4 bug class.
    #[test]
    fn get_accounts_gemini_slot_token_status_is_healthy_no_countdown() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Minimal v=1 Gemini binding (api_key mode) — the shape
        // `read_binding` in providers::gemini::provisioning accepts.
        let raw = serde_json::json!({
            "v": 1,
            "auth": { "mode": "api_key" },
            "model_name": "auto",
            "created_unix_secs": 0_u64,
        });
        std::fs::write(creds_dir.join("gemini-13.json"), raw.to_string()).unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 13)
            .expect("gemini slot 13 visible");
        assert_eq!(v.source, "gemini");
        // Critical: the badge MUST NOT have a countdown for Gemini. Pre-fix
        // the Anthropic else branch would either show `missing` (no creds
        // at uuid) — semantically misleading because the slot IS healthy —
        // or `Some(secs)` if an Anthropic credentials.json coincidentally
        // existed at the UUID, painting a Gemini slot with an Anthropic TTL.
        assert!(
            v.expires_in_secs.is_none(),
            "gemini slot must never carry an expires_in_secs countdown; got {:?}",
            v.expires_in_secs
        );
        // The status reflects whether credentials are present (discover_gemini's
        // has_credentials signal). It MUST NOT be a token-load-fail "missing"
        // when the binding itself is healthy.
        assert!(
            v.token_status == "healthy" || v.token_status == "missing",
            "gemini token_status must be the third-party-shaped binary (healthy/missing); got {}",
            v.token_status
        );
    }

    /// R2 desktop-lens LOW-3: the identity-store path (`resolve_slot_to_uuid`
    /// Some → `credentials-codex.json` at the UUID) — the post-A++ host slot-8
    /// shape — must also derive token status from the JWT, not show `missing`.
    /// The sibling test above covers the pure-legacy `credentials/codex-<N>.json`
    /// leg; this pins the UUID-resolved leg.
    #[test]
    fn get_accounts_codex_uuid_path_token_status_from_jwt() {
        use csq_core::accounts::identity_store::{credentials_codex_path_for, IdentityId};
        use csq_core::accounts::profiles::{profiles_path, save, ProfilesFile};

        let dir = tempfile::TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("8".to_string(), uuid);
        save(&profiles_path(dir.path()), &pf).unwrap();

        // identity.json provider=codex + credentials-codex.json at the UUID
        // path; NO legacy credentials/codex-8.json mirror.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.sig";
        let id_dir = csq_core::accounts::identity_store::identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(
            id_dir.join("identity.json"),
            br#"{"email":"codex:abc","provider":"codex","created_at":"t","key_id":null}"#,
        )
        .unwrap();
        std::fs::write(
            credentials_codex_path_for(dir.path(), uuid),
            format!(
                r#"{{"auth_mode":"chatgpt","tokens":{{"access_token":"{jwt}","refresh_token":"rt","id_token":"{jwt}","account_id":"uuid"}},"last_refresh":"2026-04-22T00:00:00Z"}}"#
            ),
        )
        .unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 8)
            .expect("codex slot 8 visible via UUID path");
        assert_eq!(
            v.source, "codex",
            "must surface as codex, not dimmed anthropic"
        );
        assert_eq!(
            v.token_status, "healthy",
            "UUID-path codex slot must derive healthy from JWT exp; got {}",
            v.token_status
        );
        assert!(v.expires_in_secs.map(|s| s > 0).unwrap_or(false));
    }

    /// Anthropic slot still works (regression): the surface-match gate
    /// must keep claude-code-quota visible on claude-code slots.
    #[test]
    fn get_accounts_anthropic_slot_still_surfaces_claude_code_quota() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        seed_claude_slot(&creds_dir, 4);
        write_quota_file(dir.path(), &[(4, "claude-code", 30.0, 60.0)]);

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 4)
            .expect("claude slot 4 visible");
        assert_eq!(v.surface, "claude-code");
        assert_eq!(v.source, "anthropic");
        assert_eq!(v.five_hour_pct, 30.0);
        assert_eq!(v.seven_day_pct, 60.0);
    }

    /// Decouple regression: the token badge "expiring" warning fires at
    /// 1h (`TOKEN_WARN_SECS`), NOT at the daemon's 2h refresh window. A
    /// token with ~90 min left is mid-refresh-window and MUST read
    /// "healthy" (the refresher tops it up around the 2h line); only
    /// below 1h does it warn. Pins the fix for the "many accounts
    /// Expires 1h" false alarm — when the badge threshold equalled the
    /// 2h refresh trigger, every routine pre-refresh moment (and every
    /// synchronized slot at once) lit up "expiring".
    #[test]
    fn get_accounts_token_badge_warns_below_one_hour_not_two() {
        fn seed_with_expiry_ms(creds_dir: &std::path::Path, slot: u16, expires_at_ms: u64) {
            std::fs::write(
                creds_dir.join(format!("{slot}.json")),
                format!(
                    r#"{{"claudeAiOauth":{{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":{expires_at_ms},"scopes":[]}}}}"#
                ),
            )
            .unwrap();
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // ~90 min left: inside the 2h refresh window but ABOVE the 1h
        // warn line → MUST be healthy (was "expiring" before the decouple).
        seed_with_expiry_ms(&creds_dir, 1, now_ms + 90 * 60 * 1000);
        // ~30 min left: below the 1h warn line → "expiring".
        seed_with_expiry_ms(&creds_dir, 2, now_ms + 30 * 60 * 1000);
        // ~5h left: healthy control.
        seed_with_expiry_ms(&creds_dir, 3, now_ms + 5 * 60 * 60 * 1000);

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let status = |id: u16| {
            views
                .iter()
                .find(|v| v.id == id)
                .map(|v| v.token_status.clone())
                .unwrap_or_else(|| "MISSING".to_string())
        };
        assert_eq!(
            status(1),
            "healthy",
            "90 min left is inside the 2h refresh window but above the 1h warn line — must NOT warn"
        );
        assert_eq!(
            status(2),
            "expiring",
            "30 min left is below the 1h warn line — must warn"
        );
        assert_eq!(status(3), "healthy", "5h left — healthy control");
    }

    /// an internal journal entry H2 regression: a slot ID rebound across surfaces
    /// must NOT leak the prior occupant's quota. Seed a Codex slot at
    /// id 13 but write a stale claude-code-surfaced quota.json[13]
    /// (simulating an Anthropic slot that previously held id 13). The
    /// IPC payload must ship zeros, not the stale numbers — even though
    /// the slot ID matches.
    #[test]
    fn get_accounts_rebound_slot_does_not_leak_prior_surface_quota() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        seed_codex_slot(&creds_dir, 13);
        // Prior occupant was Anthropic — stale row carries surface="claude-code".
        write_quota_file(dir.path(), &[(13, "claude-code", 80.0, 95.0)]);

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 13)
            .expect("codex slot 13 visible");
        assert_eq!(v.surface, "codex");
        assert_eq!(
            v.five_hour_pct, 0.0,
            "stale claude-code quota MUST NOT leak to a rebound codex slot"
        );
        assert_eq!(
            v.seven_day_pct, 0.0,
            "stale claude-code quota MUST NOT leak to a rebound codex slot"
        );
        assert!(v.five_hour_resets_in.is_none());
        assert!(v.seven_day_resets_in.is_none());
    }

    // ── HIGH-1 (an internal ticket redteam) — Kimi desktop quota rendering ───────
    //
    // Kimi is the first surface where the account's OWN dispatch
    // `Surface` never equals the persisted quota row's `surface` string
    // for EITHER of its two shapes: the native-CLI slot writes
    // "kimi-cli" (its Surface::Kimi.as_str() is "kimi"), and the 3P
    // Bearer slot writes "kimi" (its dispatch Surface is ClaudeCode /
    // "claude-code"). Both shapes previously fell through the bare
    // `q.surface == a.surface.as_str()` gate and rendered no quota at
    // all — these tests pin the fix.

    /// 3P Bearer Kimi slot: quota row surface is "kimi", account surface
    /// is "claude-code" (dispatch runs through the `claude` CLI). Must
    /// still surface real 5h/7d bars, not the pay-per-token ledger the
    /// catalog's `QuotaKind::Unknown` (a polling-dispatch flag) would
    /// otherwise route it to.
    #[test]
    fn get_accounts_kimi_3p_slot_surfaces_utilization_quota() {
        let dir = tempfile::TempDir::new().unwrap();
        csq_core::accounts::third_party::bind_provider_to_slot(
            dir.path(),
            "kimi",
            csq_core::types::AccountNum::try_from(13u16).unwrap(),
            Some("sk-kimi-test-key"),
            None,
        )
        .unwrap();
        write_quota_file(dir.path(), &[(13, "kimi", 34.0, 12.0)]);

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 13)
            .expect("kimi 3P slot 13 visible");
        assert_eq!(v.source, "third_party");
        assert_eq!(v.provider_id.as_deref(), Some("kimi"));
        assert_eq!(
            v.quota_kind, "utilization",
            "kimi 3P slot must render bars, not the pay-per-token ledger \
             (catalog quota_kind=Unknown is a polling-dispatch flag \
             telling tick_3p to skip the probe, NOT a rendering flag)"
        );
        assert!(
            v.has_quota,
            "kimi 3P slot with a matching quota row must report has_quota=true"
        );
        assert_eq!(v.five_hour_pct, 34.0);
        assert_eq!(v.seven_day_pct, 12.0);
    }

    /// Native Kimi CLI slot: quota row surface is "kimi-cli", account
    /// surface is "kimi" (`Surface::Kimi.as_str()`). Must surface real
    /// bars — the native session IS polled by the dedicated
    /// `usage_poller::kimi`, unlike Grok's genuine vendor-managed
    /// subscription with no csq quota endpoint.
    #[test]
    fn get_accounts_kimi_native_slot_surfaces_utilization_quota() {
        let dir = tempfile::TempDir::new().unwrap();
        csq_core::providers::native::write_binding(
            dir.path(),
            csq_core::types::AccountNum::try_from(14u16).unwrap(),
            csq_core::providers::catalog::Surface::Kimi,
        )
        .unwrap();
        write_quota_file(dir.path(), &[(14, "kimi-cli", 55.0, 20.0)]);

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 14)
            .expect("kimi native slot 14 visible");
        assert_eq!(v.source, "native");
        assert_eq!(v.surface, "kimi");
        assert_eq!(
            v.quota_kind, "utilization",
            "native kimi slot must render bars, not the static \
             'Subscription · vendor-managed' native-quota text"
        );
        assert!(
            v.has_quota,
            "native kimi slot with a matching 'kimi-cli' row must report has_quota=true"
        );
        assert_eq!(v.five_hour_pct, 55.0);
        assert_eq!(v.seven_day_pct, 20.0);
    }

    /// Negative control: Grok has no dedicated poller and must keep the
    /// "native" (vendor-managed subscription) rendering path unchanged
    /// by the Kimi carve-out above.
    #[test]
    fn get_accounts_grok_native_slot_still_renders_native_quota_kind() {
        let dir = tempfile::TempDir::new().unwrap();
        csq_core::providers::native::write_binding(
            dir.path(),
            csq_core::types::AccountNum::try_from(15u16).unwrap(),
            csq_core::providers::catalog::Surface::Grok,
        )
        .unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 15)
            .expect("grok native slot 15 visible");
        // Round-8: was `"native"`. Grok is csq-polled now (this PR fixes
        // `parse_grok_billing`), so it renders on the balance path even
        // before its first row lands — exactly as a 3P balance provider
        // does. `has_quota` stays false, which is what distinguishes
        // "no row yet" from "measured zero".
        assert_eq!(v.quota_kind, "balance");
        assert!(!v.has_quota);
    }

    /// The case the maintainer actually hit: a Grok native slot WITH a
    /// real balance row must render that balance, not the static
    /// "Subscription · vendor-managed" string. Before this PR the row
    /// never existed (the parser failed every tick) AND the desktop
    /// routed the surface to "native", so the two defects masked each
    /// other — fixing only the parser would have changed nothing visible.
    #[test]
    fn get_accounts_grok_native_slot_with_a_balance_row_renders_the_balance() {
        let dir = tempfile::TempDir::new().unwrap();
        let slot = csq_core::types::AccountNum::try_from(15u16).unwrap();
        csq_core::providers::native::write_binding(
            dir.path(),
            slot,
            csq_core::providers::catalog::Surface::Grok,
        )
        .unwrap();

        use csq_core::quota::{AccountQuota, BalanceInfo, QuotaFile};
        let mut f = QuotaFile::empty();
        f.schema_version = 2;
        let q = AccountQuota {
            surface: "grok".to_string(),
            kind: "balance".to_string(),
            balance: Some(BalanceInfo {
                currency: "USD".to_string(),
                remaining: 165.36,
            }),
            updated_at: 1_785_000_000.0,
            ..AccountQuota::default()
        };
        f.set(15, q);
        csq_core::quota::state::save_state(dir.path(), &f).unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 15)
            .expect("grok native slot 15 visible");
        assert_eq!(
            v.quota_kind, "balance",
            "a polled Grok slot must render its balance, not vendor-managed"
        );
        assert!(
            v.has_quota,
            "a slot with a real balance row must report has_quota=true"
        );
    }

    /// The maintainer's LIVE row, verbatim from `quota.json` slot 16 on
    /// 2026-08-04: a weekly-credit Grok subscription writes BOTH a real
    /// `seven_day` window (7% used) AND a `$0.00` on-demand balance,
    /// because `on_demand_cap`/`on_demand_used` are 0 on that plan.
    ///
    /// The CLI renders "7% 2d20h" for this row; the desktop rendered
    /// "Balance $0.00 remaining", hiding a live usage window behind a
    /// zero. The cause was a display shape keyed on provider IDENTITY
    /// (`Native { Grok } => "balance"`) rather than on the row — the
    /// desktop twin of the CLI fix in 080430f0, which the desktop never
    /// received (the `discovery_codex_login_cli_desktop_twin_parity`
    /// class).
    ///
    /// Non-vacuity: with either gate reverted this test FAILS —
    /// `quota_kind` returns to "balance" without the demotion, and
    /// `balance_display` returns to `Some("$0.00")` without the filter.
    /// Both are asserted because `AccountList.svelte`'s balance arm
    /// fires on `quota_kind === 'balance' || account.balance_display`,
    /// so either one alone still routes the slot to the wrong renderer.
    #[test]
    fn get_accounts_grok_slot_with_window_and_zero_balance_renders_the_window() {
        let dir = tempfile::TempDir::new().unwrap();
        let slot = csq_core::types::AccountNum::try_from(16u16).unwrap();
        csq_core::providers::native::write_binding(
            dir.path(),
            slot,
            csq_core::providers::catalog::Surface::Grok,
        )
        .unwrap();

        use csq_core::quota::{AccountQuota, BalanceInfo, QuotaFile, UsageWindow};
        let mut f = QuotaFile::empty();
        f.schema_version = 2;
        let q = AccountQuota {
            surface: "grok".to_string(),
            // Deliberately the ADVERSARIAL tag, not the one the current
            // poller writes. `usage_poller::grok` would write "utilization"
            // for a windowed row, but the implementation under test never
            // reads `kind` — it derives from `five_hour`/`seven_day`. With
            // `kind: "utilization"` the fixture is INERT: the test would pass
            // identically against a hypothetical `if q.kind == "utilization"`
            // implementation, so it could not discriminate the two
            // (`instrument-discipline.md` MUST-2).
            //
            // `"balance"` makes it discriminating AND is the more realistic
            // adversarial shape: a row written before the poller's precedence
            // landed, or by any future writer that tags from provider
            // identity. The row is the authority; its tag is not.
            kind: "balance".to_string(),
            five_hour: None,
            seven_day: Some(UsageWindow {
                used_percentage: 7.0,
                // 4_102_444_800 = 2100-01-01 (testing.md Rule 1). MUST stay far-future:
                // this fixture round-trips through the loader, whose `clear_expired`
                // NULLS a past window — the row then falls back to `balance` and the
                // assertions below invert. A near-future literal here detonated on
                // 2026-08-07T11:12:35Z and reddened every PR in flight.
                resets_at: 4_102_444_800,
            }),
            // The on-demand allowance on a weekly-credit plan: present,
            // and zero. Presence is NOT evidence of a pay-per-token plan.
            balance: Some(BalanceInfo {
                currency: "USD".to_string(),
                remaining: 0.0,
            }),
            updated_at: 1_785_683_111.0,
            ..AccountQuota::default()
        };
        f.set(16, q);
        csq_core::quota::state::save_state(dir.path(), &f).unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 16)
            .expect("grok native slot 16 visible");

        assert_eq!(
            v.quota_kind, "utilization",
            "a Grok row carrying a usage window must render bars, not a balance"
        );
        assert_eq!(
            v.balance_display, None,
            "a $0.00 on-demand allowance must not be rendered as the slot's balance \
             while a real usage window exists"
        );
        assert_eq!(
            v.seven_day_pct, 7.0,
            "the window the balance was hiding must reach the frontend"
        );
        assert_eq!(
            v.five_hour_pct, 0.0,
            "the absent 5h window must not be fabricated from the 7d value"
        );
        assert!(v.has_quota, "a slot with a real row reports has_quota=true");
    }

    /// The gate is provider-agnostic BY DESIGN, and nothing else covered that.
    ///
    /// `balance_display` is filtered on the row alone — unlike the `quota_kind`
    /// demotion, which is additionally conditioned on `quota_kind == "balance"`.
    /// So a slot catalogued `utilization` (here a 3P bearer provider) whose row
    /// carries BOTH a window and a balance must ALSO lose `balance_display`.
    ///
    /// Without this, such a slot reached the balance renderer through
    /// `AccountList.svelte`'s `|| account.balance_display` disjunct and hid its
    /// window — the same defect as grok-16, on a surface nobody had connected
    /// to Grok. The class is per-PLAN, not per-provider; this test is what
    /// stops a future reader from "tidying" the filter into a Grok-only check.
    #[test]
    fn get_accounts_balance_display_gate_is_provider_agnostic() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        seed_claude_slot(&creds_dir, 9);

        use csq_core::quota::{AccountQuota, BalanceInfo, QuotaFile, UsageWindow};
        let mut f = QuotaFile::empty();
        f.schema_version = 2;
        let q = AccountQuota {
            surface: "claude-code".to_string(),
            kind: "utilization".to_string(),
            five_hour: Some(UsageWindow {
                used_percentage: 12.0,
                resets_at: 4_102_444_800,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: 55.0,
                resets_at: 4_102_444_800,
            }),
            balance: Some(BalanceInfo {
                currency: "USD".to_string(),
                remaining: 0.0,
            }),
            updated_at: 1_785_683_111.0,
            ..AccountQuota::default()
        };
        f.set(9, q);
        csq_core::quota::state::save_state(dir.path(), &f).unwrap();

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views.iter().find(|v| v.id == 9).expect("slot 9 visible");

        assert_eq!(
            v.balance_display, None,
            "the balance filter is row-driven and provider-agnostic — a \
             window-carrying row loses balance_display on EVERY surface, not \
             just Grok"
        );
        assert_eq!(v.five_hour_pct, 12.0, "the 5h window must survive");
        assert_eq!(v.seven_day_pct, 55.0, "the 7d window must survive");
    }

    /// `has_quota` distinguishes "no row yet" from "measured 0%" — a
    /// freshly-added slot with no `quota.json` entry MUST report
    /// `has_quota=false`, not merely the serialization-default 0.0
    /// percentages.
    #[test]
    fn get_accounts_unpolled_slot_reports_has_quota_false() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        seed_claude_slot(&creds_dir, 21);
        // No quota.json written at all — the daemon hasn't polled yet.

        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 21)
            .expect("fresh claude slot 21 visible");
        assert!(
            !v.has_quota,
            "no quota row yet must report has_quota=false, not a bare 0.0"
        );
        assert_eq!(v.five_hour_pct, 0.0);
    }

    // ── PR-C9a an internal journal entry — set_codex_slot_model surface verification ─

    /// an internal journal entry finding 9: `set_codex_slot_model` must refuse when
    /// the target slot is not a Codex slot. Without this the command
    /// would write a `config.toml` into a ClaudeCode slot's directory,
    /// poisoning surface classification (config.toml is a Codex-unique
    /// marker per spec 07 §7.2.2). This test pins the refusal — we do
    /// NOT need a Tauri runtime because the early refusal returns
    /// before `app.emit` runs; the fn signature takes `AppHandle` but
    /// we synthesize the rejection path without entering the emit.
    ///
    /// Structural: we can't easily fake an `AppHandle` in a unit test,
    /// so we drive this through the core-level path — seeding a
    /// ClaudeCode slot via the same setup the test helpers use and
    /// asserting that `discover_all` classifies it as ClaudeCode.
    /// The command itself is exercised at higher-level integration
    /// tests but this pins the discovery classification that the
    /// command's refusal key-reads.
    #[test]
    fn set_codex_slot_model_guards_classification_via_discover_all() {
        use csq_core::accounts::discovery;
        use csq_core::providers::catalog::Surface;

        let dir = tempfile::TempDir::new().unwrap();
        // Seed a ClaudeCode slot (credentials/5.json).
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("5.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let accounts = discovery::discover_all(dir.path());
        let slot_5 = accounts
            .iter()
            .find(|a| a.id == 5)
            .expect("slot 5 must be discoverable");
        assert_eq!(
            slot_5.surface,
            Surface::ClaudeCode,
            "slot 5 seeded as ClaudeCode → set_codex_slot_model must refuse it"
        );
    }

    /// Happy-path classification: a seeded Codex slot MUST be
    /// classified as `Surface::Codex` by `discover_all`, which is
    /// the key lookup `set_codex_slot_model` uses. Without this the
    /// refusal would fire on valid Codex slots too.
    #[test]
    fn set_codex_slot_model_allows_codex_slot_via_discover_all() {
        use csq_core::accounts::discovery;
        use csq_core::providers::catalog::Surface;

        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Minimal Codex credential shape.
        std::fs::write(
            creds_dir.join("codex-7.json"),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"eyJacc","refresh_token":"rt_x","id_token":"eyJid","account_id":"uuid"},"last_refresh":"2026-04-22T00:00:00Z"}"#,
        )
        .unwrap();

        let accounts = discovery::discover_all(dir.path());
        let slot_7 = accounts
            .iter()
            .find(|a| a.id == 7)
            .expect("slot 7 must be discoverable");
        assert_eq!(
            slot_7.surface,
            Surface::Codex,
            "Codex slot 7 must classify as Surface::Codex so set_codex_slot_model accepts it"
        );
    }

    // ── PR-C9a an internal journal entry finding 2 — device-code parse is on scrubbed line ─

    /// Pins the trust-boundary narrowing: if a codex-cli process
    /// substitution prints `"Go to https://legit enter FOOB-AR23 sk-ant-oat01-bad"`
    /// the scrubber removes `sk-ant-oat01-bad` — but more importantly,
    /// the parse runs on the scrubbed line, so any token-shaped
    /// substring that the parser might otherwise mis-extract is
    /// already replaced. This test pins `redact_tokens` behaviour for
    /// the typical Codex-adjacent token shapes.
    #[test]
    fn redact_tokens_strips_sk_ant_and_rt_and_jwt_shapes() {
        use csq_core::error::redact_tokens;
        // rt_* requires ≥20 body chars per TOKEN_PREFIXES_WITH_BODY in
        // csq-core error.rs — this reflects real Codex refresh tokens
        // which are 87-char base64url bodies (an internal journal entry).
        let raw =
            "Visit https://chatgpt.com/auth/device code FOOB-AR23 token=sk-ant-oat01-abcdef1234 \
                   eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.sigPaddingLongEnough \
                   rt_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";
        let scrubbed = redact_tokens(raw);
        assert!(
            !scrubbed.contains("sk-ant-oat01-abcdef1234"),
            "sk-ant-* token must be redacted: {scrubbed}"
        );
        assert!(
            !scrubbed.contains("rt_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"),
            "rt_* refresh shape must be redacted (≥20 body): {scrubbed}"
        );
        // The device-code substring must survive — we rely on this
        // to still pass through to the parser.
        assert!(
            scrubbed.contains("FOOB-AR23"),
            "device-code shape must survive redaction: {scrubbed}"
        );
    }

    // ── PR-G5 — Gemini desktop UI command boundary tests ───────
    //
    // These exercise the Tauri-boundary input validation that runs
    // before any csq-core orchestration. Core fns are tested
    // exhaustively in csq-core::providers::gemini::provisioning.

    #[test]
    fn is_gemini_tos_acknowledged_rejects_missing_base_dir() {
        let err = is_gemini_tos_acknowledged("/nonexistent/csq-base".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn is_gemini_tos_acknowledged_returns_false_when_marker_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let acked = is_gemini_tos_acknowledged(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(!acked);
    }

    #[test]
    fn is_gemini_tos_acknowledged_returns_true_after_acknowledge() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(is_gemini_tos_acknowledged(dir.path().to_string_lossy().into_owned()).unwrap());
    }

    #[test]
    fn acknowledge_gemini_tos_rejects_missing_base_dir() {
        let err = acknowledge_gemini_tos("/nonexistent/csq-base".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn acknowledge_gemini_tos_writes_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::gemini::tos::is_acknowledged(
            dir.path()
        ));
    }

    #[test]
    fn acknowledge_gemini_tos_is_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::gemini::tos::is_acknowledged(
            dir.path()
        ));
    }

    #[test]
    fn gemini_provision_api_key_rejects_invalid_account() {
        let err = gemini_provision_api_key(
            "/tmp".into(),
            0,
            "AIzaFAKETESTKEYDONOTUSE0000000000000000".into(),
        )
        .unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_empty_key() {
        let err = gemini_provision_api_key("/tmp".into(), 1, "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_too_short_key() {
        let err = gemini_provision_api_key("/tmp".into(), 1, "AIzaShort".into()).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_oversized_key() {
        let long = "A".repeat(300);
        let err = gemini_provision_api_key("/tmp".into(), 1, long).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_control_characters() {
        // ESC byte mid-paste — same shape the Bearer form was bitten
        // by in an internal journal entry Refuse at the boundary.
        let key = "AIzaSy\x1bXX_xxxxxxxxxxxxxxxxxxxxxxxxxx".to_string();
        let err = gemini_provision_api_key("/tmp".into(), 1, key).unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_non_aiza_prefix() {
        // 30+ bytes so the length check passes, but no AIza prefix.
        let key = "sk-ant-XX_xxxxxxxxxxxxxxxxxxxxxxxx".to_string();
        let err = gemini_provision_api_key("/tmp".into(), 1, key).unwrap_err();
        assert!(err.contains("AIza"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_missing_base_dir() {
        let err = gemini_provision_api_key(
            "/nonexistent/csq-base".into(),
            1,
            "AIzaFAKETESTKEYDONOTUSE0000000000000000".into(),
        )
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_refuses_codex_bound_slot() {
        // Seed a Codex marker; provision call should refuse with a
        // pointer to `csq logout`.
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-3.json"), b"{}").unwrap();

        let err = gemini_provision_api_key(
            dir.path().to_string_lossy().into_owned(),
            3,
            "AIzaFAKETESTKEYDONOTUSE0000000000000000".into(),
        )
        .unwrap_err();
        assert!(err.contains("Codex"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_refuses_claude_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join("4.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let err = gemini_provision_api_key(
            dir.path().to_string_lossy().into_owned(),
            4,
            "AIzaFAKETESTKEYDONOTUSE0000000000000000".into(),
        )
        .unwrap_err();
        assert!(err.contains("Claude"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_refuses_native_bound_slot() {
        // redteam R2 MED-2: `detect_other_surface_binding` was blind to
        // native (Kimi/Grok) bindings, so this desktop provision path would
        // silently dual-bind a native-bound slot onto Gemini too.
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();
        csq_core::providers::native::write_binding(
            dir.path(),
            slot,
            csq_core::providers::catalog::Surface::Grok,
        )
        .unwrap();

        let err = gemini_provision_api_key(
            dir.path().to_string_lossy().into_owned(),
            5,
            "AIzaFAKETESTKEYDONOTUSE0000000000000000".into(),
        )
        .unwrap_err();
        assert!(err.contains("Grok"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn gemini_provision_vertex_sa_rejects_relative_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = gemini_provision_vertex_sa(
            dir.path().to_string_lossy().into_owned(),
            1,
            "./relative/sa.json".into(),
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn gemini_provision_vertex_sa_rejects_empty_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            gemini_provision_vertex_sa(dir.path().to_string_lossy().into_owned(), 1, "  ".into())
                .unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    // ── an internal ticket — desktop Tauri commands MUST NOT leak raw
    // filesystem paths (or the operator's username, which a $HOME
    // prefix reveals) to the renderer over the error channel. Each
    // test below deterministically triggers a path-bearing error
    // from csq-core and asserts the returned `Err(String)` does not
    // contain the operator's home directory.

    /// Runs `f` with `$HOME` pointed at `home`, serialized against
    /// sibling tests via the workspace-wide env-mutation mutex
    /// (`rules/testing.md` §4/4b shared-env discipline).
    fn with_mocked_home<R>(home: &std::path::Path, f: impl FnOnce() -> R) -> R {
        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home);
        }
        let out = f();
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        out
    }

    #[test]
    fn gemini_provision_vertex_sa_error_does_not_leak_home_path() {
        let home = tempfile::TempDir::new().unwrap();
        let base = home.path().join(".claude").join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        // Block `write_binding`'s `create_dir_all(parent)` by putting a
        // FILE where the `credentials/` directory must go — deterministically
        // triggers `ProvisionError::Io { path: <credentials dir>, .. }`.
        std::fs::write(base.join("credentials"), b"not a directory").unwrap();

        let sa_path = home.path().join("sa.json");
        std::fs::write(&sa_path, br#"{"type":"service_account"}"#).unwrap();

        let err = with_mocked_home(home.path(), || {
            gemini_provision_vertex_sa(
                base.to_string_lossy().into_owned(),
                5,
                sa_path.to_string_lossy().into_owned(),
            )
            .unwrap_err()
        });

        let home_str = home.path().to_string_lossy().into_owned();
        assert!(!err.contains(&home_str), "path leaked to renderer: {err}");
        assert!(err.contains('~'), "expected a redacted ~/ path: {err}");
    }

    #[test]
    fn get_rotation_config_error_does_not_leak_home_path() {
        let home = tempfile::TempDir::new().unwrap();
        let base = home.path().join(".claude").join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        // Corrupt rotation.json so `rotation_config::load` returns
        // `ConfigError::InvalidJson { path: <rotation.json>, .. }`.
        std::fs::write(base.join("rotation.json"), b"{not valid json").unwrap();

        let err = with_mocked_home(home.path(), || {
            get_rotation_config(base.to_string_lossy().into_owned()).unwrap_err()
        });

        let home_str = home.path().to_string_lossy().into_owned();
        assert!(!err.contains(&home_str), "path leaked to renderer: {err}");
        assert!(err.contains('~'), "expected a redacted ~/ path: {err}");
    }

    // `gemini_switch_model` takes an `AppHandle`, which — per the
    // established convention two tests down
    // (`gemini_switch_model_unknown_model_message_lists_canonical_ids`)
    // — cannot be easily faked in a unit test here. The `Malformed`
    // path it would hit via `set_model_name` -> `read_binding` is
    // pinned directly against `ProvisionError::redacted_message` in
    // `csq-core/src/providers/gemini/provisioning.rs`
    // (`redacted_message_strips_path_on_malformed_variant`), which is
    // the exact redaction call the command's `map_err` closure makes.

    #[test]
    fn gemini_provision_vertex_sa_refuses_codex_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-2.json"), b"{}").unwrap();

        let sa_path = dir.path().join("sa.json");
        std::fs::write(&sa_path, br#"{"type":"service_account"}"#).unwrap();

        let err = gemini_provision_vertex_sa(
            dir.path().to_string_lossy().into_owned(),
            2,
            sa_path.to_string_lossy().into_owned(),
        )
        .unwrap_err();
        assert!(err.contains("Codex"), "got: {err}");
    }

    // ── cloud_claude_provision_{vertex,bedrock} boundary tests ────────────
    //
    // These pin the IPC-boundary validation that fires BEFORE the backend
    // `bind_cloud_claude_backend_to_slot` call (slot range, non-empty
    // fields, absolute SA path, control-char token, base-dir existence).
    // The backend's own SSRF / SA-file / slot-conflict / residency guards
    // are tested exhaustively in
    // `csq_core::accounts::third_party` — not re-exercised here.

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_vertex_rejects_invalid_account() {
        let err = cloud_claude_provision_vertex(
            "/tmp".into(),
            0,
            "my-project".into(),
            "us-east5".into(),
            "/abs/sa.json".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_vertex_rejects_empty_project() {
        let err = cloud_claude_provision_vertex(
            "/tmp".into(),
            1,
            "  ".into(),
            "us-east5".into(),
            "/abs/sa.json".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("project ID must not be empty"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_vertex_rejects_empty_region() {
        let err = cloud_claude_provision_vertex(
            "/tmp".into(),
            1,
            "my-project".into(),
            "  ".into(),
            "/abs/sa.json".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("region must not be empty"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_vertex_rejects_empty_sa_path() {
        let err = cloud_claude_provision_vertex(
            "/tmp".into(),
            1,
            "my-project".into(),
            "us-east5".into(),
            "   ".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("path must not be empty"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_vertex_rejects_relative_sa_path() {
        let err = cloud_claude_provision_vertex(
            "/tmp".into(),
            1,
            "my-project".into(),
            "us-east5".into(),
            "./relative/sa.json".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_vertex_rejects_missing_base_dir() {
        let err = cloud_claude_provision_vertex(
            "/nonexistent/csq-base".into(),
            1,
            "my-project".into(),
            "us-east5".into(),
            "/abs/sa.json".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_bedrock_rejects_invalid_account() {
        let err = cloud_claude_provision_bedrock(
            "/tmp".into(),
            0,
            "us-east-1".into(),
            "bedrock-bearer-token".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_bedrock_rejects_empty_region() {
        let err = cloud_claude_provision_bedrock(
            "/tmp".into(),
            1,
            "  ".into(),
            "bedrock-bearer-token".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("region must not be empty"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_bedrock_rejects_empty_token() {
        let err = cloud_claude_provision_bedrock(
            "/tmp".into(),
            1,
            "us-east-1".into(),
            "   ".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_bedrock_rejects_control_char_token() {
        // ESC byte mid-paste — same truncation shape the Gemini API-key
        // path guards against. Refuse at the boundary.
        let token = "bedrock\x1btoken".to_string();
        let err = cloud_claude_provision_bedrock("/tmp".into(), 1, "us-east-1".into(), token, None)
            .unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn cloud_claude_provision_bedrock_rejects_missing_base_dir() {
        let err = cloud_claude_provision_bedrock(
            "/nonexistent/csq-base".into(),
            1,
            "us-east-1".into(),
            "bedrock-bearer-token".into(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    // ── gemini_provision_oauth boundary tests ─────────────────────────────
    //
    // The full happy-path (`gemini auth login` shell-out + binding write)
    // requires gemini-cli on PATH and an interactive browser flow; that
    // path is covered by manual smoke. Boundary tests pin the validation
    // checks that fire BEFORE the shell-out.

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(f)
    }

    #[test]
    fn gemini_provision_oauth_rejects_invalid_account() {
        let err = block_on(gemini_provision_oauth("/tmp".into(), 0)).unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn gemini_provision_oauth_rejects_missing_base_dir() {
        let err = block_on(gemini_provision_oauth("/nonexistent/csq-base".into(), 1)).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn gemini_provision_oauth_refuses_codex_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-5.json"), b"{}").unwrap();

        let err = block_on(gemini_provision_oauth(
            dir.path().to_string_lossy().into_owned(),
            5,
        ))
        .unwrap_err();
        assert!(err.contains("Codex"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn gemini_provision_oauth_refuses_claude_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join("6.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let err = block_on(gemini_provision_oauth(
            dir.path().to_string_lossy().into_owned(),
            6,
        ))
        .unwrap_err();
        assert!(err.contains("Claude"), "got: {err}");
    }

    // ── acquire_gemini_desktop_login_lock: cross-process exclusion ──
    //
    // `gemini_provision_oauth` (the real Tauri command) needs no
    // `AppHandle` / `State<'_, AppState>` (unlike `complete_codex_login`),
    // so it is tested directly below via `block_on`. These tests target
    // the extracted helper alone, mirroring the CLI's
    // `acquire_login_lock` coverage and the codex desktop helper's
    // shape.

    #[test]
    fn acquire_gemini_desktop_login_lock_refuses_when_held() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(51u16).unwrap();

        // Hold the lock ourselves first. Same-process, second `open()`
        // — flock is scoped to the open file description, not the
        // process, so this genuinely reproduces cross-process
        // contention (same pattern `login_lock.rs`'s own tests use).
        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let err = match acquire_gemini_desktop_login_lock(dir.path(), account) {
            Err(e) => e,
            Ok(_) => panic!("must refuse while another guard holds the account's lock"),
        };
        assert!(
            err.contains("already in progress"),
            "error must name the contention, not some other failure: {err}"
        );
        assert!(
            err.contains("51"),
            "error must name the contended slot: {err}"
        );
    }

    #[test]
    fn acquire_gemini_desktop_login_lock_succeeds_when_free() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(52u16).unwrap();

        let guard = acquire_gemini_desktop_login_lock(dir.path(), account)
            .expect("must succeed when nothing else holds the account's lock");

        // Prove the returned guard genuinely HOLDS the flock (not a
        // guard that already dropped, or a no-op stand-in): a second
        // acquire attempt for the same account, while `guard` is
        // still alive, must observe contention.
        match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Held { .. } => {}
            AcquireOutcome::Acquired(_) => {
                panic!("returned guard must still hold the lock while alive")
            }
        }
        drop(guard);
    }

    #[test]
    fn acquire_gemini_desktop_login_lock_is_per_account() {
        let dir = tempfile::TempDir::new().unwrap();
        let held_account = AccountNum::try_from(53u16).unwrap();
        let other_account = AccountNum::try_from(54u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), held_account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        acquire_gemini_desktop_login_lock(dir.path(), other_account)
            .expect("a different account's slot must not be blocked");
    }

    /// End-to-end: a genuine filesystem failure (base dir made unwritable)
    /// reaches `acquire_gemini_desktop_login_lock`'s `Err(e)` arm, and the
    /// resulting renderer-facing string names neither the tempdir nor any
    /// path separator — only the fixed tag and the slot number. Unix-only:
    /// directory-mode-based permission injection is not portable to Windows
    /// (`test(login): gate the failure-injection fixtures to unix`).
    #[cfg(unix)]
    #[test]
    fn acquire_gemini_desktop_login_lock_filesystem_error_omits_the_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(59u16).unwrap();

        // No write permission on base_dir -> OpenOptions::create(true) on
        // the lock file inside it fails with PermissionDenied.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = acquire_gemini_desktop_login_lock(dir.path(), account);

        // Restore write permission before the TempDir guard tries to clean
        // up, regardless of what the assertions below find.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("acquire must fail against an unwritable base_dir"),
        };
        assert!(
            err.contains("permission_denied"),
            "error must carry the fixed-vocabulary tag: {err}"
        );
        assert!(err.contains("59"), "error must still name the slot: {err}");
        assert!(
            !err.contains(&dir.path().display().to_string()),
            "error must not carry the lock file's path: {err}"
        );
        assert!(
            !err.contains('/'),
            "error must carry no path separator at all: {err}"
        );
    }

    // ── gemini_provision_oauth: cross-process lock is the FIRST thing
    //    it does (after cheap input validation) ──
    //
    // `gemini_provision_oauth` acquires the login lock before the
    // `spawn_blocking` call into `oauth_login::perform` (which drives
    // the shared `~/.gemini/oauth_creds.json` read/OAuth-flow) — so a
    // held-lock test never reaches any filesystem/network/browser
    // activity and is safe (and fast) to run unattended.

    #[test]
    fn gemini_provision_oauth_refuses_when_login_lock_held_by_another_process() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(55u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let err = block_on(gemini_provision_oauth(
            dir.path().to_string_lossy().into_owned(),
            55,
        ))
        .expect_err(
            "gemini_provision_oauth must refuse when the account's login lock \
             is held, not fall through to oauth_login::perform",
        );
        assert!(
            err.contains("already in progress"),
            "must be the lock-contention message: {err}"
        );
        assert!(err.contains("55"), "must name the contended slot: {err}");
    }

    #[test]
    fn gemini_provision_oauth_lock_check_precedes_binding_guard_check() {
        // Safe RED/GREEN discriminator that does NOT risk touching a
        // live OAuth flow: pre-bind the slot to Claude (so
        // `oauth_login::perform`'s OWN `binding_guard` check would
        // fire with an "OtherSurfaceBound"/"Claude" error if the lock
        // check were absent or came after it), then hold the account's
        // login lock. Post-fix, the lock check runs FIRST and the
        // error must be the lock-contention message, never the
        // binding-guard one — proving the ordering, not just presence.
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(58u16).unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join("58.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let err = block_on(gemini_provision_oauth(
            dir.path().to_string_lossy().into_owned(),
            58,
        ))
        .expect_err("must refuse — either lock contention or Claude-bound, never Ok");
        assert!(
            err.contains("already in progress"),
            "lock check must run BEFORE oauth_login::perform's binding_guard              check — got the wrong error, meaning the lock was bypassed or              checked too late: {err}"
        );
        assert!(
            !err.contains("Claude"),
            "must not have fallen through to perform()'s binding_guard check: {err}"
        );
    }

    #[test]
    fn gemini_provision_oauth_lock_is_per_account_not_global() {
        // A held lock on account 56 must NOT block account 57 — the
        // lock file is `.login-<N>.lock`, keyed by account number.
        // Account 57 has no Gemini/Codex/Claude binding on disk, so
        // if the lock were global this would still fail — but on
        // a *different* error than lock contention.
        let dir = tempfile::TempDir::new().unwrap();
        let held_account = AccountNum::try_from(56u16).unwrap();
        let other_account = AccountNum::try_from(57u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), held_account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        // acquire_gemini_desktop_login_lock alone (not the full
        // `gemini_provision_oauth`, which would go on to
        // `spawn_blocking` into the live OAuth flow for the "free"
        // case — out of scope, and unsafe to exercise, in a unit test).
        acquire_gemini_desktop_login_lock(dir.path(), other_account)
            .expect("a different account's slot must not be blocked");
    }

    // ── list_native_clis ─────────────────────────────────────────

    #[test]
    fn list_native_clis_includes_kimi_and_grok() {
        let clis = list_native_clis().unwrap();
        let ids: Vec<&str> = clis.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"kimi-cli"), "got: {ids:?}");
        assert!(ids.contains(&"grok"), "got: {ids:?}");
        let kimi = clis.iter().find(|c| c.id == "kimi-cli").unwrap();
        assert_eq!(kimi.surface, "kimi");
        assert_eq!(kimi.binary, "kimi");
        assert_eq!(kimi.display_name, "Kimi (native CLI)");
        let grok = clis.iter().find(|c| c.id == "grok").unwrap();
        assert_eq!(grok.surface, "grok");
        assert_eq!(grok.binary, "grok");
        // Pre-existing failure fixed in-session (zero-tolerance.md Rule 1):
        // this assertion predates an internal journal entry Wave A's empirical finding
        // that grok-cli's own default model is "grok-4.5" (native.rs::GROK
        // — `descriptor_carries_wave_b_vendor_fields` pins the same value).
        // The stale "" expectation was introduced by e0f85f79 (W3-7,
        // pre-0135) and never updated when C1 landed the real default.
        assert_eq!(grok.default_model, "grok-4.5");
    }

    // ── start_native_login (an internal journal entry C8) ────────────────────
    //
    // Validation parity with the retired `provision_native_cli`
    // (an internal journal entry W3-5): unknown id / invalid slot / missing base dir
    // / conflicting binding all reject through the SAME
    // `resolve_native_login_request` helper `complete_native_login`
    // shares — these tests exercise it via the cheaper, side-effect-free
    // `start_native_login` entry point.

    #[test]
    fn start_native_login_rejects_unknown_id() {
        let err = start_native_login("/tmp".into(), "not-a-native-cli".into(), 1).unwrap_err();
        assert!(err.contains("unknown native CLI id"), "got: {err}");
    }

    #[test]
    fn start_native_login_rejects_invalid_slot() {
        let err = start_native_login("/tmp".into(), "kimi-cli".into(), 0).unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn start_native_login_rejects_missing_base_dir() {
        let err =
            start_native_login("/nonexistent/csq-base".into(), "kimi-cli".into(), 1).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn start_native_login_refuses_codex_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-5.json"), b"{}").unwrap();

        let err = start_native_login(
            dir.path().to_string_lossy().into_owned(),
            "kimi-cli".into(),
            5,
        )
        .unwrap_err();
        assert!(err.contains("Codex"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn start_native_login_refuses_other_native_surface() {
        let dir = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();
        csq_core::providers::native::write_binding(
            dir.path(),
            slot,
            csq_core::providers::catalog::Surface::Kimi,
        )
        .unwrap();

        // Same slot, different native surface (Grok) — must refuse rather
        // than silently permitting a later complete_native_login to
        // clobber the Kimi binding.
        let err = start_native_login(dir.path().to_string_lossy().into_owned(), "grok".into(), 7)
            .unwrap_err();
        assert!(err.contains("Kimi"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn start_native_login_allows_idempotent_reprovision_same_surface() {
        // Re-starting a login for a slot already bound to the SAME native
        // surface must succeed (a real re-login refreshes the marker via
        // `native::write_binding`'s idempotent overwrite) rather than
        // refusing itself.
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().to_string_lossy().into_owned();
        csq_core::providers::native::write_binding(
            dir.path(),
            AccountNum::try_from(9u16).unwrap(),
            csq_core::providers::catalog::Surface::Kimi,
        )
        .unwrap();

        // test-hermeticity.md MUST-1b: `start_native_login` transitively reads
        // process-global PATH (via `find_cli_binary`/`find_in_path` to derive
        // `cli_installed`, unasserted here but still evaluated on every call).
        // This test doesn't care what PATH resolves to, but it must not race
        // a concurrent PATH-mutating sibling — hold the shared lock for the
        // read even though this test never sets PATH itself.
        let _shared_env_guard = csq_core::platform::test_env::lock();
        let view = start_native_login(base, "kimi-cli".into(), 9).unwrap();
        assert_eq!(view.native_id, "kimi-cli");
    }

    #[cfg(unix)]
    #[test]
    fn start_native_login_reports_cli_installed_via_known_dir_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::TempDir::new().unwrap();
        let bin_dir = home.path().join(".kimi-code").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bin = bin_dir.join("kimi");
        std::fs::write(&bin, "#!/bin/sh").unwrap();
        let mut perms = std::fs::metadata(&bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin, perms).unwrap();

        let base_dir = tempfile::TempDir::new().unwrap();

        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev_path = std::env::var_os("PATH");
        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("PATH", "");
            std::env::set_var("HOME", home.path());
        }

        let view = start_native_login(
            base_dir.path().to_string_lossy().into_owned(),
            "kimi-cli".into(),
            1,
        );

        unsafe {
            match prev_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(_shared_env_guard);

        assert!(view.unwrap().cli_installed);
    }

    // ── cancel_native_login_from (an internal journal entry C8) ──────────────
    //
    // Unit-tested via the pure inner (mirrors `consume_prefs_recovery_from`)
    // rather than the `#[tauri::command]` wrapper — avoids constructing a
    // full `tauri::test::mock_app()` + `AppState` (8 fields, all
    // irrelevant here except `native_login_children`) just to reach the
    // id-resolution + kill contract.

    #[test]
    fn cancel_native_login_from_rejects_unknown_id() {
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        let err = cancel_native_login_from(&children, "not-a-native-cli").unwrap_err();
        assert!(err.contains("unknown native CLI id"), "got: {err}");
    }

    #[test]
    fn cancel_native_login_from_is_noop_when_nothing_running() {
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        assert!(cancel_native_login_from(&children, "grok").is_ok());
        assert!(cancel_native_login_from(&children, "kimi-cli").is_ok());
    }

    // ── reserve_native_login_slot: the atomic TOCTOU guard (redteam R1 MED) ──

    #[test]
    fn reserve_native_login_slot_refuses_second_same_surface() {
        use csq_core::providers::catalog::Surface;
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        assert!(reserve_native_login_slot(&children, Surface::Kimi, "Kimi").is_ok());
        // A second reservation for the SAME surface is refused under the same
        // lock the first acquired — the check-then-spawn TOCTOU is closed.
        let err = reserve_native_login_slot(&children, Surface::Kimi, "Kimi").unwrap_err();
        assert!(err.contains("already in progress"), "got: {err}");
    }

    #[test]
    fn reserve_native_login_slot_allows_different_surface() {
        use csq_core::providers::catalog::Surface;
        // 0135 C8 design point: a Kimi login in flight must NOT block a
        // concurrent Grok login — they are independent vendor binaries.
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        assert!(reserve_native_login_slot(&children, Surface::Kimi, "Kimi").is_ok());
        assert!(reserve_native_login_slot(&children, Surface::Grok, "Grok").is_ok());
    }

    // ── NativeLoginReservationCleanup: belt-and-suspenders (redteam R2 LOW-1 + LOW-2) ──

    #[test]
    fn reservation_cleanup_removes_own_untouched_reservation_when_not_spawned() {
        use csq_core::providers::catalog::Surface;
        // The ordinary pre-spawn-error path: `spawned` stays false, so the
        // guard's Drop must clear the (still-`None`) reservation it never
        // got a chance to overwrite with a real child.
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        reserve_native_login_slot(&children, Surface::Kimi, "Kimi").unwrap();
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let _cleanup = NativeLoginReservationCleanup {
                children: children.clone(),
                surface: Surface::Kimi,
                spawned: spawned.clone(),
            };
            // Dropped at end of this block.
        }
        assert!(
            !children.lock().unwrap().contains_key(&Surface::Kimi),
            "an untouched (never-spawned) reservation must be cleared on drop"
        );
    }

    #[test]
    fn reservation_cleanup_does_not_clobber_a_second_reservation_after_spawn_and_wait_clear() {
        use csq_core::providers::catalog::Surface;
        // Reproduces the LOW-1 TOCTOU exactly: call A reserves, "spawns"
        // (spawned=true) and its wait closure clears the entry (mirrors
        // `spawn_native_device_auth_piped`'s wait closure post-wait
        // `remove`) — all BEFORE call A's `NativeLoginReservationCleanup`
        // drops. In the gap, call B reserves the SAME surface fresh. Call
        // A's guard, dropping last, must NOT delete call B's reservation.
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));

        // Call A: reserve, "spawn" (flag flips true), wait closure clears.
        reserve_native_login_slot(&children, Surface::Kimi, "Kimi").unwrap();
        let spawned_a = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleanup_a = NativeLoginReservationCleanup {
            children: children.clone(),
            surface: Surface::Kimi,
            spawned: spawned_a.clone(),
        };
        spawned_a.store(true, std::sync::atomic::Ordering::Release);
        // Wait closure's post-wait clear (mirrors
        // `spawn_native_device_auth_piped`'s `wait` closure).
        children.lock().unwrap().remove(&Surface::Kimi);

        // Call B: a fresh, independent login for the SAME surface races in
        // during the gap between call A's wait-clear and its
        // `NativeLoginReservationCleanup` drop.
        reserve_native_login_slot(&children, Surface::Kimi, "Kimi").unwrap();
        assert!(
            children.lock().unwrap().contains_key(&Surface::Kimi),
            "precondition: call B's reservation is present before call A's guard drops"
        );

        // Call A's guard now drops (end of scope). Because `spawned_a` is
        // true, it must NOT touch the map — call B's fresh reservation
        // must survive.
        drop(cleanup_a);

        assert!(
            children.lock().unwrap().contains_key(&Surface::Kimi),
            "call A's belt-and-suspenders cleanup must not clobber call B's \
             fresh reservation for the same surface"
        );
    }

    #[test]
    fn reservation_cleanup_ignores_other_surfaces() {
        use csq_core::providers::catalog::Surface;
        // The guard is keyed to its OWN surface only — a reservation for a
        // different surface must survive regardless of `spawned`.
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        reserve_native_login_slot(&children, Surface::Grok, "Grok").unwrap();
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let _cleanup = NativeLoginReservationCleanup {
                children: children.clone(),
                surface: Surface::Kimi,
                spawned,
            };
        }
        assert!(
            children.lock().unwrap().contains_key(&Surface::Grok),
            "cleanup for Kimi must not touch a Grok reservation"
        );
    }

    #[test]
    fn reservation_cleanup_clears_on_panic_before_spawn() {
        use csq_core::providers::catalog::Surface;
        // LOW-2: a panic inside `login_native_with` (before spawn ever
        // registers a real child) must still clear the reservation — Rust
        // runs `Drop` impls during unwinding, so the guard fires even
        // though no code after the panic point ever executes normally.
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        reserve_native_login_slot(&children, Surface::Grok, "Grok").unwrap();
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let children_for_closure = children.clone();
        let spawned_for_closure = spawned.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _cleanup = NativeLoginReservationCleanup {
                children: children_for_closure,
                surface: Surface::Grok,
                spawned: spawned_for_closure,
            };
            panic!("simulated login_native_with panic before spawn");
        }));

        assert!(
            result.is_err(),
            "the panic must propagate — caught here only to observe the post-unwind state"
        );
        assert!(
            !children.lock().unwrap().contains_key(&Surface::Grok),
            "a pre-spawn panic must still clear the reservation via Drop-during-unwind"
        );
    }

    #[test]
    fn reservation_cleanup_leaves_entry_on_panic_after_spawn() {
        use csq_core::providers::catalog::Surface;
        // A panic AFTER a successful spawn (spawned == true) must NOT
        // clear the entry — a real subprocess may still be running and
        // `cancel_native_login` needs the map entry to reach it.
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        reserve_native_login_slot(&children, Surface::Grok, "Grok").unwrap();
        children
            .lock()
            .unwrap()
            .insert(Surface::Grok, None /* stand-in for Some(child_arc) */);
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let children_for_closure = children.clone();
        let spawned_for_closure = spawned.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _cleanup = NativeLoginReservationCleanup {
                children: children_for_closure,
                surface: Surface::Grok,
                spawned: spawned_for_closure,
            };
            panic!("simulated login_native_with panic after spawn");
        }));

        assert!(result.is_err());
        assert!(
            children.lock().unwrap().contains_key(&Surface::Grok),
            "a post-spawn panic must NOT clear the entry — cancel_native_login \
             still needs it to reach the (possibly still-running) child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancel_native_login_from_kills_registered_child() {
        use csq_core::providers::catalog::Surface;
        // A live child registered as a Grok login is killed by cancel. Uses a
        // harmless `sleep` child rather than a real vendor binary.
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let handle = Arc::new(Mutex::new(child));
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        children
            .lock()
            .unwrap()
            .insert(Surface::Grok, Some(handle.clone()));

        assert!(cancel_native_login_from(&children, "grok").is_ok());

        // The child was SIGKILLed — reaping it reports a non-success status.
        let status = handle.lock().unwrap().wait().expect("wait killed child");
        assert!(!status.success(), "killed child must not exit successfully");
    }

    // ── spawn_native_device_auth_piped argv/env (an internal journal entry C8) ──
    //
    // Confirms the production spawn closure builds the right argv + env
    // for the vendor binary and registers/deregisters the child in the
    // per-surface concurrency map — without requiring a real kimi/grok
    // binary. Drives it through the SAME `login_native_with` entry point
    // `complete_native_login` uses (rather than reaching into
    // `SpawnedNativeLogin`'s private fields, which carry no test
    // accessors by design — the DI seam IS the closure boundary). The
    // stand-in script never writes a real vendor credential file, so
    // `login_native_with`'s post-exit verification fails; that failure
    // is expected and orthogonal to what this test pins (argv, env,
    // and per-surface registration lifecycle). Mirrors
    // `provider_cli_installed_finds_kimi_and_grok_on_path`'s PATH-stub
    // technique.
    #[cfg(unix)]
    #[test]
    fn spawn_native_device_auth_piped_builds_argv_and_env_and_registers_child() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("grok");
        // Writes its own argv + the isolation env var's VALUE into a
        // file inside the home dir it was told to use, so the test can
        // assert both without a real grok binary or private-field access.
        std::fs::write(
            &script,
            "#!/bin/sh\necho \"argv:$@ home_env:$GROK_HOME\" > \"$GROK_HOME/observed.txt\"\nexit 0\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", dir.path());
        }

        let base = tempfile::TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let surface = csq_core::providers::catalog::Surface::Grok;
        let children: NativeLoginChildren = Arc::new(Mutex::new(HashMap::new()));
        let children_for_spawn = children.clone();
        let registered_during_spawn = std::cell::Cell::new(false);
        let spawned_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let result = csq_core::providers::native_login::login_native_with(
            base.path(),
            slot,
            surface,
            |home, binary, args, home_env| {
                let spawned = spawn_native_device_auth_piped(
                    home,
                    binary,
                    args,
                    home_env,
                    surface,
                    &children_for_spawn,
                    &spawned_flag,
                );
                registered_during_spawn
                    .set(children_for_spawn.lock().unwrap().contains_key(&surface));
                spawned
            },
            |_code| {},
        );

        unsafe {
            match prev_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
        drop(_shared_env_guard);

        // Expected failure: the stand-in script never wrote grok's real
        // credential file, so `finish_native_login`'s post-exit
        // verification rejects it. This test pins argv/env/registration,
        // not full login success (that's `native_login.rs`'s job).
        assert!(
            result.is_err(),
            "expected finish_native_login to reject a missing credential file"
        );
        assert!(
            registered_during_spawn.get(),
            "child must be registered in the per-surface map while spawn is in flight"
        );
        assert!(
            !children.lock().unwrap().contains_key(&surface),
            "child must be deregistered once the wait closure reaps it"
        );
        assert!(
            spawned_flag.load(std::sync::atomic::Ordering::Acquire),
            "spawned flag must be set once the real child is registered (redteam R2 LOW-1)"
        );

        let home = csq_core::providers::native::native_home_path(base.path(), slot, surface);
        let observed = std::fs::read_to_string(home.join("observed.txt"))
            .expect("spawned script must have run inside its vendor home");
        assert!(
            observed.contains("argv:login --device-auth"),
            "got: {observed:?}"
        );
        assert!(
            observed.contains(&format!("home_env:{}", home.display())),
            "got: {observed:?}"
        );
    }

    /// Surface-dispatch rejection: `login_native_with` (and therefore
    /// `complete_native_login`, which calls it) refuses a non-native
    /// surface before ever invoking the spawn closure. Regression for
    /// the 0135 C8 directive that the desktop layer never bypasses the
    /// core surface gate.
    #[test]
    fn login_native_with_rejects_non_native_surface_before_spawning() {
        let base = tempfile::TempDir::new().unwrap();
        let spawn_called = std::cell::Cell::new(false);
        let err = csq_core::providers::native_login::login_native_with(
            base.path(),
            AccountNum::try_from(1u16).unwrap(),
            csq_core::providers::catalog::Surface::Codex,
            |_home, _binary, _args, _home_env| {
                spawn_called.set(true);
                Err(std::io::Error::other("must not be reached"))
            },
            |_code| {},
        )
        .unwrap_err();
        assert!(
            !spawn_called.get(),
            "spawn must not run for a non-native surface"
        );
        assert!(err.to_string().contains("not a native-CLI surface"));
    }

    // gemini_switch_model takes AppHandle so we test the shape via a
    // structural seed: set_model_name is the csq-core fn it calls.
    // The boundary checks (invalid slot / unknown model) are in
    // is_known_gemini_model + AccountNum::try_from which are
    // exercised at csq-core. Here we pin the unknown-model rejection
    // string the UI surfaces.

    #[test]
    fn gemini_switch_model_unknown_model_message_lists_canonical_ids() {
        // Synthesises the exact error-string format the boundary
        // would return — calls the validator the command also calls.
        use csq_core::providers::gemini::provisioning::is_known_gemini_model;
        let bad = "pro";
        assert!(!is_known_gemini_model(bad));
        let msg = format!(
            "unknown Gemini model `{bad}` — desktop submits canonical ids only \
             (auto, gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite, gemini-3-pro-preview)"
        );
        assert!(msg.contains("auto"));
        assert!(msg.contains("gemini-2.5-pro"));
        assert!(msg.contains("gemini-3-pro-preview"));
    }

    // ── remove_account: D7 vault-delete regression ─────────────────────────

    /// D7 regression: `remove_account` on a Gemini ApiKey slot must delete
    /// the vault entry before `logout_account` removes the marker.
    ///
    /// Uses `CSQ_SECRET_BACKEND=in-memory` so the test runs without the
    /// real OS keychain. After `remove_account` returns Ok, both the
    /// binding marker and the vault entry must be gone.
    ///
    /// Vault emptiness after the command is verified via
    /// `delete_api_key_from_vault` returning Ok on a slot with no marker
    /// (the idempotent no-op path) — a post-hoc `vault.get` would require
    /// sharing the same `InMemoryVault` instance, which `open_default_vault`
    /// does not support across call sites. The csq-core unit tests in
    /// `provisioning::tests::delete_api_key_from_vault_removes_vault_entry_*`
    /// directly verify the vault-empty postcondition with a shared vault.
    #[test]
    fn remove_account_gemini_slot_succeeds_with_in_memory_vault() {
        use csq_core::providers::gemini::provisioning::{
            is_gemini_bound_slot, write_binding, AuthMode, GeminiBinding,
        };

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let slot_num = AccountNum::try_from(3u16).unwrap();

        // Provision the slot: write the Gemini binding marker.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(base, slot_num, &binding).unwrap();

        // Also create the minimal config-3/ structure that logout_account
        // checks for (credentials/3.json + config-3/.credentials.json).
        let config_dir = base.join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join(".credentials.json"), "{}").unwrap();
        std::fs::write(creds_dir.join("3.json"), "{}").unwrap();

        // Confirm the marker exists before removal.
        assert!(
            is_gemini_bound_slot(base, slot_num),
            "marker must exist before remove_account"
        );

        // Force in-memory vault so no OS keychain access fires in CI.
        // testing.md Rule 6: env mutation MUST hold the workspace-shared
        // test_env lock — cargo test is multi-threaded, and the sibling
        // chain-broken test mutates the same var (2026-06-11 ubuntu flake:
        // losing the race falls through to platform dispatch — headless
        // Linux errors BackendUnavailable; macOS hits the REAL keychain).
        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev = std::env::var("CSQ_SECRET_BACKEND").ok();
        unsafe { std::env::set_var("CSQ_SECRET_BACKEND", "in-memory") };
        let result = remove_account(base.to_string_lossy().into_owned(), 3);
        match prev {
            Some(v) => unsafe { std::env::set_var("CSQ_SECRET_BACKEND", v) },
            None => unsafe { std::env::remove_var("CSQ_SECRET_BACKEND") },
        }
        drop(_shared_env_guard);

        assert!(result.is_ok(), "remove_account must succeed: {result:?}");

        // Binding marker must be gone (config-3/ was removed by logout_account).
        assert!(
            !is_gemini_bound_slot(base, slot_num),
            "Gemini binding marker must be removed after remove_account"
        );
    }

    /// Round-4 FIX-1: when the `.chain-broken` sentinel is set, `remove_account`
    /// on a Gemini-bound slot MUST succeed (degrade) AND emit zero audit records.
    /// The vault delete and credential cleanup MUST still proceed.
    #[test]
    fn remove_account_gemini_proceeds_skips_audit_when_chain_broken() {
        use csq_core::providers::gemini::provisioning::{
            is_gemini_bound_slot, write_binding, AuthMode, GeminiBinding,
        };

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let slot_num = AccountNum::try_from(5u16).unwrap();

        // Provision the Gemini slot.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(base, slot_num, &binding).unwrap();
        let config_dir = base.join("config-5");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join(".credentials.json"), "{}").unwrap();
        std::fs::write(creds_dir.join("5.json"), "{}").unwrap();

        // Set the .chain-broken sentinel.
        csq_core::audit::set_chain_broken(base, "chain_broken_test");

        // remove_account MUST succeed even though the chain is broken.
        // testing.md Rule 6: shared test_env lock — see the sibling
        // in-memory-vault test for the race this prevents.
        let _shared_env_guard = csq_core::platform::test_env::lock();
        let prev = std::env::var("CSQ_SECRET_BACKEND").ok();
        unsafe { std::env::set_var("CSQ_SECRET_BACKEND", "in-memory") };
        let result = remove_account(base.to_string_lossy().into_owned(), 5);
        match prev {
            Some(v) => unsafe { std::env::set_var("CSQ_SECRET_BACKEND", v) },
            None => unsafe { std::env::remove_var("CSQ_SECRET_BACKEND") },
        }
        drop(_shared_env_guard);

        assert!(
            result.is_ok(),
            "remove_account must SUCCEED (degrade) when chain is broken: {result:?}"
        );

        // Credentials MUST be deleted — op proceeded despite no audit trail.
        assert!(
            !base.join("config-5").exists(),
            "config-5 must be removed even when chain is broken"
        );
        assert!(
            !is_gemini_bound_slot(base, slot_num),
            "Gemini binding marker must be removed even when chain is broken"
        );

        // Zero audit records on chain (intent skipped → no outcome).
        let runs_dir = base.join("csq-runs");
        if runs_dir.exists() {
            let chain_files: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
                .collect();
            assert!(
                chain_files.is_empty(),
                "no audit records must be written when chain is broken: {chain_files:?}"
            );
        }
    }

    /// D7: `remove_account` on a non-Gemini slot (ClaudeCode) must NOT
    /// touch the vault — the vault-delete branch only fires for Gemini.
    #[test]
    fn remove_account_non_gemini_slot_does_not_open_vault() {
        // Provision a minimal ClaudeCode account (no Gemini marker).
        // Even with CSQ_SECRET_BACKEND unset, the vault must never be
        // opened for a ClaudeCode slot, so the native OS keychain is
        // never touched and the test works in CI without credentials.
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let config_dir = base.join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join(".credentials.json"), "{}").unwrap();
        std::fs::write(creds_dir.join("1.json"), "{}").unwrap();

        // No CSQ_SECRET_BACKEND override — vault open must NOT be reached.
        let result = remove_account(base.to_string_lossy().into_owned(), 1);
        assert!(
            result.is_ok(),
            "remove_account for ClaudeCode slot must succeed: {result:?}"
        );
    }

    // ── move_account: validation + error mapping ──────────────────────────

    /// Happy path: move slot 1 → slot 4 succeeds when slot 1 is
    /// configured, slot 4 is empty, and no live process is bound.
    #[test]
    fn move_account_renames_config_dir_and_canonical() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let config_1 = base.join("config-1");
        std::fs::create_dir_all(&config_1).unwrap();
        std::fs::write(config_1.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config_1.join(".csq-account"), "1").unwrap();
        std::fs::write(creds_dir.join("1.json"), "{}").unwrap();

        let result = move_account(base.to_string_lossy().into_owned(), 1, 4);
        assert!(result.is_ok(), "move must succeed: {result:?}");
        let summary = result.unwrap();
        assert_eq!(summary.from, 1);
        assert_eq!(summary.to, 4);
        assert!(summary.config_dir_moved);
        assert!(!base.join("config-1").exists());
        assert!(base.join("config-4").exists());
        assert!(!creds_dir.join("1.json").exists());
        assert!(creds_dir.join("4.json").exists());
        // Marker rewritten inside moved dir.
        let marker = std::fs::read_to_string(base.join("config-4/.csq-account")).unwrap();
        assert_eq!(marker.trim(), "4");
    }

    /// SAME_SLOT: from and to identical → typed error.
    #[test]
    fn move_account_rejects_same_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let result = move_account(base.to_string_lossy().into_owned(), 2, 2);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.starts_with("SAME_SLOT:"),
            "expected SAME_SLOT prefix, got: {err}"
        );
    }

    /// NOT_CONFIGURED: from has no state → typed error.
    #[test]
    fn move_account_rejects_unconfigured_source() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("credentials")).unwrap();
        let result = move_account(base.to_string_lossy().into_owned(), 5, 6);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.starts_with("NOT_CONFIGURED:"),
            "expected NOT_CONFIGURED prefix, got: {err}"
        );
    }

    /// TARGET_EXISTS: to already has state → typed error, no clobber.
    #[test]
    fn move_account_rejects_existing_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Both source and target configured.
        for n in &[1u16, 4] {
            let cfg = base.join(format!("config-{n}"));
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(cfg.join(".credentials.json"), "{}").unwrap();
            std::fs::write(cfg.join(".csq-account"), n.to_string()).unwrap();
            std::fs::write(creds_dir.join(format!("{n}.json")), "{}").unwrap();
        }

        let result = move_account(base.to_string_lossy().into_owned(), 1, 4);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.starts_with("TARGET_EXISTS:"),
            "expected TARGET_EXISTS prefix, got: {err}"
        );
        // Source must NOT have been moved (no clobber).
        assert!(base.join("config-1").exists());
        assert!(base.join("config-4").exists());
    }

    /// HIGH-1 regression (redteam round 1, lens C deep-analyst):
    /// `move_account` returns a summary with `by_slot_swapped = true`
    /// after a coexisting fixture move — confirming Phase 2 M2-4 by_slot
    /// swap fires on the desktop path just as on the CLI path.
    ///
    /// This test does NOT verify the IPC socket call (that would require a
    /// live daemon); it verifies that `MoveAccountSummary::by_slot_swapped`
    /// is set correctly, which is only true when `profiles::swap_slot_mapping`
    /// ran. This is the structural proof that the desktop entry point exercises
    /// the same Phase 2 code path as the CLI.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn desktop_move_account_fires_slot_swap_ipc() {
        use csq_core::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture with 2 slots (slots 1 + 2 have by_slot entries).
        let dir = coexisting_fixture(2);
        let base = dir.path();

        // Act: desktop move_account slot 1 → slot 5.
        let result = move_account(base.to_string_lossy().into_owned(), 1, 5);

        // Assert: move succeeds and by_slot_swapped = true (Phase 2 ran on desktop path).
        assert!(
            result.is_ok(),
            "desktop move_account must succeed: {result:?}"
        );
        let summary = result.unwrap();
        assert_eq!(summary.from, 1);
        assert_eq!(summary.to, 5);
        assert!(
            summary.by_slot_swapped,
            "by_slot_swapped must be true on desktop path — Phase 2 M2-4 by_slot swap \
             must fire via the desktop Tauri command, not only via the CLI"
        );
        // The config dir must have been renamed.
        assert!(
            !base.join("config-1").exists(),
            "config-1 must be gone after move"
        );
        assert!(
            base.join("config-5").exists(),
            "config-5 must exist after move"
        );
    }

    /// M3-6 AC-8: desktop `move_account` Tauri command returns
    /// `MoveAccountSummary::live_pids_bound` populated when live handle
    /// dirs are bound to the source slot. Pre-M3-6 this path returned
    /// `Err("SLOT_IN_USE: ...")`; Phase 3 surfaces the bound PIDs as
    /// telemetry so the frontend can render a notice instead of an error.
    #[test]
    fn desktop_move_command_returns_summary_with_live_pids() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Configure slot 3: config dir + credentials + marker.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let config_3 = base.join("config-3");
        std::fs::create_dir_all(&config_3).unwrap();
        std::fs::write(config_3.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config_3.join(".csq-account"), "3").unwrap();
        std::fs::write(creds_dir.join("3.json"), "{}").unwrap();

        // Seed a handle dir bound to slot 3 with the current PID
        // (guaranteed-alive for the test's duration).
        let pid = std::process::id();
        let handle_dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle_dir).unwrap();
        std::fs::write(handle_dir.join(".csq-account"), "3").unwrap();

        // Act: desktop move slot 3 → slot 7 (live binding present).
        let result = move_account(base.to_string_lossy().into_owned(), 3, 7);

        // Assert: succeeds (no SLOT_IN_USE) AND live_pids_bound carries
        // the bound PID as telemetry.
        assert!(
            result.is_ok(),
            "desktop move_account must succeed with live binding (Phase 3): {result:?}"
        );
        let summary = result.unwrap();
        assert_eq!(summary.from, 3);
        assert_eq!(summary.to, 7);
        assert!(
            summary.live_pids_bound.contains(&pid),
            "live_pids_bound must contain the seeded PID {pid}; got {:?}",
            summary.live_pids_bound
        );
    }

    // ── get_account_usage: Phase B' billing ledger ────────────────────

    /// Smoke: empty home + empty base returns a zero summary.
    /// Confirms the command doesn't panic on a fresh install.
    #[test]
    fn get_account_usage_empty_state_returns_zero_summary() {
        let home_dir = tempfile::TempDir::new().unwrap();
        let claude_home = home_dir.path().join(".claude");
        let base = claude_home.join("accounts");
        std::fs::create_dir_all(&base).unwrap();

        let result = get_account_usage(base.to_string_lossy().into_owned(), 4);
        assert!(result.is_ok(), "empty state must not error: {result:?}");
        let s = result.unwrap();
        assert_eq!(s.event_count, 0);
        assert_eq!(s.total_cost_usd, 0.0);
        assert_eq!(s.last_7d_cost_usd, 0.0);
    }

    /// End-to-end (synchronous path): plant a CC transcript + a launch event,
    /// expect the aggregator to attribute correctly and the per-slot summary
    /// to be non-zero for the matched slot. Exercises the same helpers the
    /// Tauri command's background refresh uses (`aggregate_usage_pairs` +
    /// `summarize_slot`) — deterministic, no cache/thread timing.
    #[test]
    fn get_account_usage_attributes_session_to_correct_slot() {
        let home_dir = tempfile::TempDir::new().unwrap();
        let claude_home = home_dir.path().join(".claude");
        let base = claude_home.join("accounts");
        std::fs::create_dir_all(&base).unwrap();

        // Plant a CC transcript for /repo/x with a recent timestamp (so it is
        // inside the mtime window vs `now`).
        let now = chrono::Utc::now();
        let ts = now.to_rfc3339();
        let proj = claude_home.join("projects").join("-repo-x");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("sess1.jsonl"),
            format!(
                r#"{{"type":"assistant","cwd":"/repo/x","timestamp":"{ts}","sessionId":"sess1","message":{{"model":"deepseek-chat","usage":{{"input_tokens":10000,"output_tokens":5000}}}}}}"#
            ),
        )
        .unwrap();

        // Plant launch event for slot 4 in /repo/x just before session.
        csq_core::usage::launch_log::append(
            &base,
            &csq_core::usage::launch_log::LaunchEvent {
                ts: "2026-05-06T11:00:00Z".into(),
                event: "run".into(),
                slot: 4,
                pid: 12345,
                project_path: "/repo/x".into(),
            },
        )
        .unwrap();

        // Mark slot 4 as a DeepSeek (3P) slot via its base-URL binding so
        // `discover_all` classifies it ThirdParty(DeepSeek) and the aggregator's
        // provider-consistency gate keeps the deepseek transcript above.
        let config4 = base.join("config-4");
        std::fs::create_dir_all(&config4).unwrap();
        std::fs::write(
            config4.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_MODEL":"deepseek-v4-pro","ANTHROPIC_AUTH_TOKEN":"sk-test"}}"#,
        )
        .unwrap();

        let pairs = aggregate_usage_pairs(&base, now);

        // Slot 4 sees the event with the real transcript model (deepseek).
        let s4 = summarize_slot(&pairs, AccountNum::try_from(4u16).unwrap(), now);
        assert_eq!(s4.event_count, 1);
        assert_eq!(s4.total_input_tokens, 10000);
        assert_eq!(s4.total_output_tokens, 5000);

        // Slot 7 (no launch event) sees nothing.
        let s7 = summarize_slot(&pairs, AccountNum::try_from(7u16).unwrap(), now);
        assert_eq!(s7.event_count, 0);
    }

    /// The Tauri command is non-blocking: it returns a summary immediately
    /// (from cache — empty on first call) and never errors on a fresh base.
    /// The ~20s transcript scan happens on a background thread, so the first
    /// call must NOT block on it.
    #[test]
    fn get_account_usage_command_returns_immediately() {
        let home_dir = tempfile::TempDir::new().unwrap();
        let base = home_dir.path().join(".claude").join("accounts");
        std::fs::create_dir_all(&base).unwrap();

        let t0 = std::time::Instant::now();
        let result = get_account_usage(base.to_string_lossy().into_owned(), 4);
        let elapsed = t0.elapsed();
        assert!(result.is_ok(), "command must not error: {result:?}");
        // Well under any real scan time — proves the scan is off the call path.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "command should return immediately, took {elapsed:?}"
        );
    }

    /// Ledger-first (an internal ticket): when the daemon has published a slot's ledger,
    /// `get_account_usage` reads it DIRECTLY. Planting a ledger with NO matching
    /// transcripts on disk proves the numbers came from the published ledger —
    /// the live-scan fallback would return zero here. A sibling slot with no
    /// ledger still falls back to the (empty) live scan.
    #[test]
    fn get_account_usage_reads_daemon_written_ledger_first() {
        let home_dir = tempfile::TempDir::new().unwrap();
        let base = home_dir.path().join(".claude").join("accounts");
        std::fs::create_dir_all(&base).unwrap();

        // Daemon publishes slot 6's ledger directly (no transcripts exist).
        let slot = AccountNum::try_from(6u16).unwrap();
        let now = chrono::Utc::now();
        let ev = csq_core::usage::ledger::UsageEvent {
            ts: now.to_rfc3339(),
            session_id: "sess-led".into(),
            model: "deepseek-chat".into(),
            input_tokens: 12_345,
            output_tokens: 6_789,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            cost_usd_estimate: Some(0.05),
            source: csq_core::usage::ledger::UsageSource::ProjectsJsonl,
            project_path: None,
        };
        csq_core::usage::ledger::write_all(&base, slot, std::slice::from_ref(&ev)).unwrap();

        // The command surfaces the ledger's numbers → it read the published
        // ledger, not the (empty) live scan.
        let s = get_account_usage(base.to_string_lossy().into_owned(), 6).unwrap();
        assert_eq!(s.event_count, 1);
        assert_eq!(s.total_input_tokens, 12_345);
        assert_eq!(s.total_output_tokens, 6_789);
        assert!((s.total_cost_usd - 0.05).abs() < 1e-9);

        // A sibling slot with no published ledger falls back to the empty scan.
        let other = get_account_usage(base.to_string_lossy().into_owned(), 7).unwrap();
        assert_eq!(other.event_count, 0);
    }

    /// An empty-but-present ledger (a rolled-off slot) is treated as a
    /// cache-miss: `get_account_usage` returns zero and does not short-circuit
    /// on the empty file. On this cold cache the live-scan fall-through also
    /// yields zero (no transcripts), so the result is zero either way — this
    /// guards the empty-present-ledger INPUT, which no other read-path test
    /// exercises, against a panic/regression. (an internal ticket redteam R2 GAP-2.)
    #[test]
    fn get_account_usage_empty_present_ledger_returns_zero() {
        let home_dir = tempfile::TempDir::new().unwrap();
        let base = home_dir.path().join(".claude").join("accounts");
        std::fs::create_dir_all(&base).unwrap();

        let slot = AccountNum::try_from(5u16).unwrap();
        csq_core::usage::ledger::write_all(&base, slot, &[]).unwrap();
        assert!(csq_core::usage::ledger::ledger_path(&base, slot).exists());

        let s = get_account_usage(base.to_string_lossy().into_owned(), 5).unwrap();
        assert_eq!(s.event_count, 0);
        assert_eq!(s.total_input_tokens, 0);
    }

    /// IPC audit (tauri-commands.md MUST Rule 3 / an internal journal entry finding 5):
    /// `UsageSummaryView` is returned by `get_account_usage` to the renderer.
    /// Whitelist every key so a future field addition (e.g. a project path or
    /// session id) fails this test instead of silently shipping to IPC.
    #[test]
    fn usage_summary_view_keys_whitelisted() {
        let v = UsageSummaryView {
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            last_30d_input_tokens: 0,
            last_30d_output_tokens: 0,
            last_30d_cost_usd: 0.0,
            last_7d_input_tokens: 0,
            last_7d_output_tokens: 0,
            last_7d_cost_usd: 0.0,
            last_5d_input_tokens: 0,
            last_5d_output_tokens: 0,
            last_5d_cost_usd: 0.0,
            today_input_tokens: 0,
            today_output_tokens: 0,
            today_cost_usd: 0.0,
            event_count: 0,
            unestimated_cost_count: 0,
        };
        assert_ipc_keys_whitelisted(
            &v,
            &[
                "total_input_tokens",
                "total_output_tokens",
                "total_cost_usd",
                "last_30d_input_tokens",
                "last_30d_output_tokens",
                "last_30d_cost_usd",
                "last_7d_input_tokens",
                "last_7d_output_tokens",
                "last_7d_cost_usd",
                "last_5d_input_tokens",
                "last_5d_output_tokens",
                "last_5d_cost_usd",
                "today_input_tokens",
                "today_output_tokens",
                "today_cost_usd",
                "event_count",
                "unestimated_cost_count",
            ],
        );
    }

    /// INVALID_INPUT: out-of-range slot # → typed error before
    /// touching any filesystem state.
    #[test]
    fn move_account_rejects_invalid_account_num() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let result = move_account(base.to_string_lossy().into_owned(), 0, 4);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.starts_with("INVALID_INPUT:"),
            "expected INVALID_INPUT prefix, got: {err}"
        );
    }

    /// D7 real-keychain smoke: drives the bind → remove flow against
    /// the default `platform::secret` backend (macOS Keychain on this
    /// host, libsecret on Linux, DPAPI/Cred-Manager on Windows).
    ///
    /// `#[ignore]` so it does not run in CI — the OS keychain may
    /// require an unlocked login keychain or be unavailable on
    /// headless runners. Invoke explicitly with:
    ///
    ///   cargo test --package csq-desktop-lib \
    ///     remove_account_d7_real_keychain_smoke -- --ignored --nocapture
    ///
    /// Slot 99 is well above any realistic account count to avoid
    /// clobbering live slots. If the test fails to clean up, the
    /// stranded keychain entry can be removed manually with
    /// `security delete-generic-password -s csq.gemini.99 -a csq`
    /// (macOS).
    #[test]
    #[ignore]
    fn remove_account_d7_real_keychain_smoke() {
        use csq_core::platform::secret::{SecretError, SlotKey};
        use csq_core::providers::gemini::provisioning::{
            is_gemini_bound_slot, provision_api_key_via_vault,
        };
        use csq_core::providers::gemini::SURFACE_GEMINI;
        use secrecy::SecretString;

        // Hermeticity: open_default_vault (below) reads the process-global
        // CSQ_SECRET_BACKEND (platform/secret/mod.rs). This test is #[ignore]d (runs
        // only under --ignored, in isolation) so it cannot race in normal CI, but if
        // it is ever un-ignored it MUST serialize against the sibling vault tests that
        // mutate CSQ_SECRET_BACKEND. Hold the shared env lock + pin the default
        // backend (unset → real keychain, which this smoke test intends)
        // (testing.md Rule 6 / test-hermeticity.md MUST 1b — reader side).
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_SECRET_BACKEND");

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let slot_num = AccountNum::try_from(99u16).unwrap();
        let slot_key = SlotKey {
            surface: SURFACE_GEMINI,
            account: slot_num,
        };

        let vault = csq_core::platform::secret::open_default_vault()
            .expect("default vault must open on this platform");

        // Pre-condition: slot 99 must NOT exist in the vault. If it
        // does, the previous run did not clean up — refuse to proceed
        // rather than overwrite a real entry.
        match vault.get(slot_key) {
            Err(SecretError::NotFound { .. }) => {}
            Err(e) => panic!("unexpected vault error during pre-check: {e:?}"),
            Ok(_) => panic!(
                "vault entry for slot 99 already exists — clean up with \
                 `security delete-generic-password -s csq.gemini.99 -a csq` \
                 (macOS) or the platform equivalent before re-running"
            ),
        }

        let fake_key = SecretString::new("AIza-csq-d7-smoke-not-a-real-key".into());
        provision_api_key_via_vault(base, slot_num, &fake_key, vault.as_ref())
            .expect("provision_api_key_via_vault must succeed");

        assert!(
            is_gemini_bound_slot(base, slot_num),
            "binding marker must exist after provisioning"
        );
        // Vault entry must exist (a fresh vault handle reads the same
        // platform-native store).
        let v2 = csq_core::platform::secret::open_default_vault().unwrap();
        v2.get(slot_key)
            .expect("vault must contain the provisioned key");

        // Drive the desktop's remove path against the same base_dir.
        let result = remove_account(base.to_string_lossy().into_owned(), 99);
        assert!(result.is_ok(), "remove_account must succeed: {result:?}");

        assert!(
            !is_gemini_bound_slot(base, slot_num),
            "binding marker must be removed by remove_account"
        );

        // Vault entry MUST be gone — re-open a fresh vault to bypass
        // any per-instance caching and confirm the platform-native
        // store no longer holds the slot.
        let v3 = csq_core::platform::secret::open_default_vault().unwrap();
        match v3.get(slot_key) {
            Err(SecretError::NotFound { .. }) => {}
            Err(e) => panic!("unexpected vault error during post-check: {e:?}"),
            Ok(_) => panic!(
                "D7 REGRESSION: vault entry for slot 99 still exists \
                 after remove_account — `delete_api_key_from_vault` \
                 path is broken. Manually clean with \
                 `security delete-generic-password -s csq.gemini.99 -a csq`."
            ),
        }
    }

    // ── §5a regression helper (inline; csq-desktop cannot reach pub(crate)) ──
    //
    // Mirrors `csq_core::platform::fs::assert_no_tmp_leak_on_readonly_parent`.
    // Origin: security.md §5a, an internal journal entry B2, /redteam round 3 (2026-05-09).
    #[cfg(unix)]
    fn assert_no_tmp_leak_on_readonly_parent_inline<F, E>(dir: &std::path::Path, op: F)
    where
        F: FnOnce() -> Result<(), E>,
        E: std::fmt::Debug,
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = op();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            result.is_err(),
            "op must fail under read-only parent; got Ok"
        );
        let leaked: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
    }

    /// §5a regression — site 10 (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `set_slot_model_write` fails
    /// after the tmp file would have been created (settings dir read-only →
    /// write fails), no `.tmp.` file must remain.
    ///
    /// The slot's settings.json may carry an ANTHROPIC_AUTH_TOKEN;
    /// partial-failure must not leave it at umask 0o644.
    #[cfg(unix)]
    #[test]
    fn set_slot_model_write_partial_failure_cleans_tmp_file() {
        // Arrange: bind an Ollama slot so config-N/settings.json exists
        // with the required `env` object (ANTHROPIC_AUTH_TOKEN included).
        let dir = tempfile::TempDir::new().unwrap();
        csq_core::accounts::third_party::bind_provider_to_slot(
            dir.path(),
            "ollama",
            csq_core::types::AccountNum::try_from(7u16).unwrap(),
            None,
            None,
        )
        .unwrap();

        // Confirm the happy path works.
        set_slot_model_write(
            dir.path().to_string_lossy().into_owned(),
            7,
            "llama3.2:latest".into(),
        )
        .unwrap();

        // Act + Assert: read-only config dir → write fails → no tmp leak.
        let config_dir = dir.path().join("config-7");
        assert_no_tmp_leak_on_readonly_parent_inline(&config_dir, || {
            set_slot_model_write(
                dir.path().to_string_lossy().into_owned(),
                7,
                "llama3.2:latest".into(),
            )
        });
    }

    /// M6 PR-CA12: round-trip of capability-layer toggles via the
    /// IPC-layer commands. Confirms that get_* + set_* maintain
    /// shape parity with the on-disk format and survive a process
    /// boundary's worth of serde de/encode.
    #[test]
    fn capability_layer_toggles_round_trip_via_ipc_commands() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().to_string_lossy().into_owned();

        // Defaults on a fresh dir.
        let initial = get_capability_layer_toggles(base.clone()).unwrap();
        assert!(!initial.disable_capability_layer);
        assert!(!initial.disable_scaffold);
        assert!(!initial.disable_mcp_gate);
        assert!(!initial.disable_post_validate);
        assert!(!initial.disable_struct_out);

        // Flip three toggles + persist.
        let target = CapabilityLayerTogglesView {
            disable_capability_layer: false,
            disable_scaffold: true,
            disable_mcp_gate: false,
            disable_post_validate: true,
            disable_struct_out: true,
        };
        let echoed = set_capability_layer_toggles(base.clone(), target).unwrap();
        assert_eq!(
            echoed.disable_scaffold, target.disable_scaffold,
            "set_* must echo back the saved view"
        );

        // Read back — the next csq run would observe these values.
        let reloaded = get_capability_layer_toggles(base).unwrap();
        assert!(!reloaded.disable_capability_layer);
        assert!(reloaded.disable_scaffold);
        assert!(!reloaded.disable_mcp_gate);
        assert!(reloaded.disable_post_validate);
        assert!(reloaded.disable_struct_out);
    }

    /// M6 PR-CA12: get/set with a non-existent base dir errors with
    /// a descriptive message rather than silently using $CWD or
    /// failing into the deeper csq-core load path. Per
    /// `rules/tauri-commands.md` § Argument Validation.
    #[test]
    fn capability_layer_toggles_rejects_missing_base_dir() {
        let bogus = "/nonexistent/path/that/should/never/exist".to_string();
        let r = get_capability_layer_toggles(bogus.clone());
        assert!(r.is_err(), "must reject a missing base dir");
        let e = r.unwrap_err();
        assert!(
            e.contains("base directory does not exist"),
            "validation error must name the field, got: {e}"
        );
    }

    // ── balance_display — DeepSeek balance field ─────────────────────
    //
    // Pins the IPC pipeline that propagates `AccountQuota::balance` →
    // `AccountView::balance_display`. For DeepSeek slots the quota record
    // has `balance: Some(BalanceInfo { currency: "USD", remaining: 196.42 })`
    // and `five_hour` / `seven_day` are None. The formatted string MUST
    // appear as `balance_display` on the IPC view; non-balance slots
    // MUST have `balance_display = None`.

    /// Helper: write a `config-<slot>/settings.json` pointing at DeepSeek.
    fn write_deepseek_slot_settings(base: &std::path::Path, slot: u16, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
        );
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    /// Helper: write a quota.json with a balance-only record for `slot`.
    fn write_balance_quota_file(base: &std::path::Path, slot: u16, currency: &str, remaining: f64) {
        use csq_core::quota::{AccountQuota, BalanceInfo, QuotaFile};
        let mut f = QuotaFile::empty();
        f.schema_version = 2;
        let q = AccountQuota {
            surface: "claude-code".to_string(),
            balance: Some(BalanceInfo {
                currency: currency.to_string(),
                remaining,
            }),
            updated_at: 1_775_722_800.0,
            ..AccountQuota::default()
        };
        f.set(slot, q);
        csq_core::quota::state::save_state(base, &f).unwrap();
    }

    #[test]
    fn get_accounts_deepseek_slot_balance_display_usd() {
        // Arrange: DeepSeek slot 5 with $196.42 USD balance.
        let dir = tempfile::TempDir::new().unwrap();
        write_deepseek_slot_settings(dir.path(), 5, "sk-deepseek");
        write_balance_quota_file(dir.path(), 5, "USD", 196.42);

        // Act
        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 5)
            .expect("DeepSeek slot 5 must appear in the view");

        // Assert
        assert_eq!(v.source, "third_party");
        assert_eq!(v.quota_kind, "balance");
        assert_eq!(
            v.balance_display.as_deref(),
            Some("$196.42"),
            "USD balance must be formatted as '$196.42'"
        );
    }

    #[test]
    fn get_accounts_deepseek_slot_balance_display_non_usd() {
        // Arrange: DeepSeek slot 6 with a non-USD currency.
        let dir = tempfile::TempDir::new().unwrap();
        write_deepseek_slot_settings(dir.path(), 6, "sk-deepseek");
        write_balance_quota_file(dir.path(), 6, "CNY", 1400.50);

        // Act
        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 6)
            .expect("DeepSeek slot 6 must appear in the view");

        // Assert
        assert_eq!(
            v.balance_display.as_deref(),
            Some("1400.50 CNY"),
            "Non-USD balance must be formatted as '<amount> <currency>'"
        );
    }

    #[test]
    fn get_accounts_non_balance_slot_has_no_balance_display() {
        // Arrange: Codex slot (subscription model) — no balance field.
        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        seed_codex_slot(&creds_dir, 7);
        write_quota_file(dir.path(), &[(7, "codex", 25.0, 50.0)]);

        // Act
        let views = get_accounts(dir.path().to_string_lossy().into_owned()).unwrap();
        let v = views
            .iter()
            .find(|v| v.id == 7)
            .expect("Codex slot 7 must appear in the view");

        // Assert: subscription slots MUST NOT carry a balance_display.
        assert!(
            v.balance_display.is_none(),
            "Non-balance (Codex subscription) slot must have balance_display = None; got {:?}",
            v.balance_display
        );
    }
}

// ── Prefs-recovery IPC command (HIGH-1) ─────────────────────────────────────

/// Wire shape returned by [`consume_prefs_recovery`] to the renderer.
///
/// Fields match the Svelte `RecoveryPayload` interface so the frontend
/// can use `occurred_at` as the authoritative backend-clock timestamp
/// (MED-1 fix) and `reason` for any future contextual messaging.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PrefsRecoveryPayload {
    /// Log-tag prefix identifying the corruption class (e.g.
    /// `"desktop_prefs_empty"`, `"desktop_prefs_parse_value"`).
    pub reason: String,
    /// RFC-3339 UTC timestamp of when the recovery was detected by setup().
    /// Authoritative backend clock — the renderer must NOT use its own
    /// `new Date().toISOString()` as the recovery time (MED-1).
    pub occurred_at: String,
}

/// Consume-on-read prefs-recovery gate for late-subscribing renderers.
///
/// Returns the `PrefsRecoveryRecord` stored by setup() when
/// `load_desktop_prefs` returned `RecoveredFromCorrupt`, then CLEARS it
/// so a second call (or a component re-mount) returns `None`. The banner
/// therefore shows exactly once per app-launch regardless of how many
/// times the component mounts.
///
/// Returns `None` when:
/// - The last load was `Fresh` (no corruption).
/// - The record has already been consumed by a previous call.
/// - setup() has not yet run (impossible in normal flow; `None` is the safe default).
///
/// # HIGH-1 fix
///
/// Tauri's `emit` is fire-and-forget and fires synchronously in setup()
/// before the WebView spawns. A renderer `listen()` registered in
/// `onMount` is always too late for the setup() emit on cold-launch.
/// This command fills the gap: `onMount` calls `invoke('consume_prefs_recovery')`
/// to retrieve the cached record AND registers a `listen()` for future
/// re-emits, giving defense in depth.
#[tauri::command]
pub async fn consume_prefs_recovery(
    state: tauri::State<'_, AppState>,
) -> Result<Option<PrefsRecoveryPayload>, String> {
    consume_prefs_recovery_from(&state.prefs_recovery)
}

/// Pure inner of [`consume_prefs_recovery`] — takes the cached
/// `PrefsRecoveryRecord` (if any) and converts to the wire payload,
/// clearing the cache so the next call returns `None`.
///
/// Extracted so the take-and-clear contract can be unit-tested without
/// constructing a Tauri runtime (the `#[tauri::command]` wrapper takes
/// `tauri::State<'_, AppState>` which requires the full app handle to
/// instantiate).
fn consume_prefs_recovery_from(
    recovery: &std::sync::Mutex<Option<crate::desktop::PrefsRecoveryRecord>>,
) -> Result<Option<PrefsRecoveryPayload>, String> {
    let mut guard = recovery
        .lock()
        .map_err(|_| "prefs_recovery lock poisoned".to_string())?;
    Ok(guard.take().map(|r| PrefsRecoveryPayload {
        reason: r.reason.to_string(),
        occurred_at: r.occurred_at.clone(),
    }))
}

#[cfg(test)]
mod consume_prefs_recovery_tests {
    use super::{consume_prefs_recovery_from, PrefsRecoveryPayload};
    use crate::desktop::PrefsRecoveryRecord;
    use std::sync::Mutex;

    /// `consume_prefs_recovery` returns the cached record on first call
    /// AND clears the cache (`take()` semantics), so a second call returns
    /// `None`. This is the consume-on-read contract: the banner shows once
    /// per app-launch even if the component re-mounts (window close/reopen).
    ///
    /// Origin: R2 rust-desktop-specialist LOW-1. The R1 convergence claimed
    /// this test landed but the orchestrator-side `grep -c "fn consume_prefs_recovery_returns_then_clears\b"`
    /// returned 0 (per `redteam-discipline.md` Rule 2 verification primitive).
    /// This is the missing test, written in the converged form.
    #[test]
    fn consume_prefs_recovery_returns_then_clears() {
        let recovery = Mutex::new(Some(PrefsRecoveryRecord {
            reason: "desktop_prefs_parse_value",
            occurred_at: "2026-05-26T22:00:00Z".to_string(),
        }));

        // First call: returns the cached record.
        let first = consume_prefs_recovery_from(&recovery).unwrap();
        assert_eq!(
            first,
            Some(PrefsRecoveryPayload {
                reason: "desktop_prefs_parse_value".to_string(),
                occurred_at: "2026-05-26T22:00:00Z".to_string(),
            })
        );

        // Second call: cache was cleared by the first call's `take()`.
        let second = consume_prefs_recovery_from(&recovery).unwrap();
        assert_eq!(second, None);
    }

    /// `consume_prefs_recovery` returns `None` when the cache was never
    /// populated (fresh-install case: `LoadOutcome::Fresh` does not populate
    /// the cache).
    #[test]
    fn consume_prefs_recovery_returns_none_when_cache_is_empty() {
        let recovery: Mutex<Option<PrefsRecoveryRecord>> = Mutex::new(None);
        let result = consume_prefs_recovery_from(&recovery).unwrap();
        assert_eq!(result, None);

        // Calling again still returns None (idempotent).
        let again = consume_prefs_recovery_from(&recovery).unwrap();
        assert_eq!(again, None);
    }

    /// Lock poisoning returns a descriptive `String` error (fails closed —
    /// the user just doesn't see the banner, non-critical surface).
    #[test]
    fn consume_prefs_recovery_returns_descriptive_error_on_poison() {
        use std::panic::catch_unwind;
        use std::panic::AssertUnwindSafe;
        use std::sync::Arc;

        let recovery: Arc<Mutex<Option<PrefsRecoveryRecord>>> = Arc::new(Mutex::new(None));
        let recovery_for_panic = Arc::clone(&recovery);

        // Poison the mutex by panicking inside a critical section.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = recovery_for_panic.lock().unwrap();
            panic!("induce poisoning");
        }));

        // The mutex is now poisoned. `consume_prefs_recovery_from` should
        // return the descriptive error string without panicking.
        let result = consume_prefs_recovery_from(&recovery);
        assert!(matches!(result, Err(ref msg) if msg.contains("poisoned")));
    }
}
