//! Code Assist OAuth quota poller — Phase B' (an internal journal entry+0047) +
//! Stage 2 of an internal journal entry
//!
//! Per-tick: enumerate Gemini slots whose binding marker is in
//! [`AuthMode::CodeAssistOAuth`] mode; if any exist, read the user's
//! OAuth `access_token` from `~/.gemini/oauth_creds.json` ONCE, POST
//! to `cloudcode-pa.googleapis.com/v1internal:loadCodeAssist` to
//! discover the GCP project, POST to `:retrieveUserQuota` for
//! per-model `BucketInfo`, aggregate to a single (used%, resets_at)
//! pair, and write into `quota.json[<slot>]` for EVERY OAuth slot
//! (gemini-cli stores exactly one active OAuth identity, so all
//! OAuth-mode slots reflect the same identity's quota).
//!
//! Distinct from the sibling `gemini::drain_all` consumer (NDJSON
//! event log for ApiKey + VertexSa slots — those have no public quota
//! endpoint).
//!
//! # Defenses (redteam round 1 fixes)
//!
//! - **Per-tick HTTP timeout**: `CALL_TIMEOUT` (30s) wraps each HTTP
//!   call so a wedged endpoint cannot block the poller.
//! - **OAuth-identity dedup**: `~/.gemini/oauth_creds.json` is read
//!   ONCE per tick, the project + buckets are fetched ONCE, and the
//!   projection is written to every OAuth-mode slot. With N OAuth
//!   slots, we make 2 HTTP calls per tick — not 2N.
//! - **Project cache**: the `cloudaicompanionProject` is cached
//!   in-memory across ticks; only re-discovered on 401/403 from
//!   `:retrieveUserQuota`. Cuts steady-state HTTP load to 1 call per
//!   tick after the first successful discovery.
//! - **`quota.json.lock`**: acquired before load → save so concurrent
//!   writers (Anthropic, Codex, Gemini drain, this poller) serialize.
//! - **load_state failure does NOT clobber**: if quota.json is
//!   unreadable, log and skip the write — do NOT fall back to an
//!   empty file (which would wipe every other account).
//! - **Schema coherence on rebind**: a slot transitioning from
//!   ApiKey/VertexSa (Counter) to OAuth (Utilization) gets its
//!   counter / rate_limit / effective_model fields cleared so the
//!   on-disk row is internally consistent.
//! - **Extras merge, not clobber**: existing extras (from another
//!   surface or another poller) are preserved across the OAuth poll
//!   write.
//! - **OAuth creds I/O on blocking pool**: `std::fs::read_to_string`
//!   in `read_oauth_creds` is sync; called via `spawn_blocking` so
//!   slow `~/.gemini/` (NFS, encrypted home) does not pin the async
//!   runtime.
//! - **Token redaction**: every `warn!` formatting passes the error
//!   through `error::redact_tokens` so partial JSON (which can echo
//!   token bytes) does not leak into tracing.

use crate::error::redact_tokens;
use crate::providers::gemini::code_assist_quota::{
    aggregate_to_usage_window, build_headers, build_load_code_assist_body,
    build_retrieve_user_quota_body, read_oauth_creds, LoadCodeAssistResponse,
    RetrieveUserQuotaResponse, UsageWindowProjection, CLOUDCODE_PA_BASE_URL,
};
use crate::providers::gemini::provisioning::{read_binding, AuthMode};
use crate::quota::{state as quota_state, UsageWindow};
use crate::types::AccountNum;
use secrecy::ExposeSecret;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use tracing::{debug, warn};

use super::{HttpPostProbeFn, CALL_TIMEOUT};

/// In-memory cache + tick-coordination state shared across OAuth
/// poll ticks. Holds the `cloudaicompanionProject` per identity AND
/// an `oauth_creds_read_in_flight` guard.
///
/// Round-2 redteam HIGH: when `read_oauth_creds` is wedged on a
/// slow filesystem (NFS, encrypted home), the previous tick's
/// `spawn_blocking` worker is pinned. tokio's `timeout` on the
/// `.await` can't kill the blocking thread; we just orphan it. On
/// the next tick, naively spawning another read would pin a second
/// worker. Sustained wedge → blocking-pool exhaustion → all sibling
/// pollers stall.
///
/// The in-flight guard bounds the leak: if a previous read is still
/// running, the new tick skips its read and the entire poll cycle.
/// One wedged worker per OAuth identity, not one per tick.
pub type ProjectCache = Arc<Mutex<ProjectCacheState>>;

#[derive(Debug, Default)]
pub struct ProjectCacheState {
    pub project: Option<CachedProject>,
    /// True between the moment we kick off `read_oauth_creds` in
    /// `spawn_blocking` and the moment the [`InFlightGuard`] drops.
    /// While true, subsequent ticks skip rather than spawn another
    /// blocking read.
    pub oauth_creds_read_in_flight: bool,
}

/// RAII guard for the `oauth_creds_read_in_flight` flag. Acquired
/// at the top of a tick if no read is currently in flight, dropped
/// (clearing the flag) when the tick body returns through ANY exit
/// path: Ok, Err, ?-bubble, or panic.
///
/// Round-3 redteam HIGH: the flag was previously cleared inside the
/// `spawn_blocking` closure, which leaked when the closure panicked
/// or was cancelled before reaching the clear. RAII drop on the
/// outer scope makes the lifecycle panic-safe.
struct InFlightGuard {
    cache: ProjectCache,
}

impl InFlightGuard {
    /// Tries to set the flag to `true`. Returns `Some(guard)` if it
    /// was `false` (we successfully acquired). Returns `None` if a
    /// previous tick is still in flight — caller should skip.
    fn try_acquire(cache: &ProjectCache) -> Option<Self> {
        let mut guard = cache.lock().unwrap_or_else(|p| {
            // Poison handler — preserve project, only reset the
            // flag. (Round-3 LOW: the poison cause is unrelated to
            // the project value, no need to clobber it.)
            warn!(
                error_kind = "gemini_oauth_cache_poisoned",
                "gemini_oauth: project cache mutex was poisoned, resetting in-flight flag"
            );
            let mut g = p.into_inner();
            g.oauth_creds_read_in_flight = false;
            g
        });
        if guard.oauth_creds_read_in_flight {
            return None;
        }
        guard.oauth_creds_read_in_flight = true;
        drop(guard);
        Some(InFlightGuard {
            cache: Arc::clone(cache),
        })
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        guard.oauth_creds_read_in_flight = false;
    }
}

/// Single-entry project cache (gemini-cli stores one active OAuth
/// identity, so we only need one slot).
#[derive(Debug, Clone)]
pub struct CachedProject {
    /// Hash of the access_token prefix used to detect identity
    /// rotation. We don't store the full token to bound exposure.
    identity_fingerprint: u64,
    /// `projects/<name>` value cached from `:loadCodeAssist`.
    project: String,
}

/// Builds a stable, non-reversible fingerprint from an access_token.
/// Used only to detect identity rotation in the project cache —
/// hashes the FULL token string. Round-2 redteam HIGH: prefix-only
/// truncation collided across distinct ya29.* identities because
/// Google's tokens share a long deterministic-looking header before
/// the user-distinguishing entropy. Hashing the full token (~200
/// chars × DefaultHasher = ~1µs) eliminates the collision risk
/// without storing the token long-term.
fn fingerprint_token(token: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    hasher.finish()
}

/// Resolves the user's home directory at runtime. Pulled out so tests
/// can stub via `home_dir_for_test`.
fn home_dir() -> Option<std::path::PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        return Some(std::path::PathBuf::from(h));
    }
    #[cfg(windows)]
    {
        return std::env::var_os("USERPROFILE").map(std::path::PathBuf::from);
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Runs a single Code Assist OAuth quota poll tick.
///
/// Discovers OAuth-mode Gemini slots by walking
/// `<base_dir>/credentials/gemini-*.json` and reading the binding
/// marker. Slots in ApiKey or VertexSa mode are skipped (their quota
/// lives in `quota::state` via the event-driven `gemini::drain_all`
/// path).
pub async fn tick(base_dir: &Path, http_post: &HttpPostProbeFn, project_cache: &ProjectCache) {
    let home = match home_dir() {
        Some(h) => h,
        None => {
            warn!("gemini_oauth poller: HOME not set, skipping tick");
            return;
        }
    };

    let oauth_slots = enumerate_oauth_mode_slots(base_dir);
    if oauth_slots.is_empty() {
        debug!("gemini_oauth poller: no OAuth-mode slots, skipping tick");
        return;
    }

    debug!(
        slot_count = oauth_slots.len(),
        "gemini_oauth poller: tick starting"
    );

    // OAuth identity dedup: gemini-cli stores ONE active OAuth
    // identity in oauth_creds.json. All OAuth-mode slots refer to
    // the same identity's quota. Read creds once, fetch projection
    // once, write to every slot.
    //
    // No outer timeout: each inner spawn_blocking is wrapped in
    // CALL_TIMEOUT individually, and the inner timeouts cancel the
    // .await — that's the correct cancellation point. An outer
    // wrap of `CALL_TIMEOUT * N` only fires AFTER the sum of inners
    // already completed/timed out, making it dead code (round-2
    // redteam HIGH).
    let projection = match fetch_projection_for_identity(&home, http_post, project_cache).await {
        Ok(Some(p)) => Some(p),
        // Round-2 redteam MED: 200 + empty buckets is an explicit
        // "connected but no quota usage yet" signal. Don't skip
        // silently — write a sentinel row so the UI can render
        // "Connected — awaiting quota" instead of "no data" or
        // (worse) a stale entry from a prior identity.
        Ok(None) => None,
        Err(e) => {
            warn!(
                error_kind = "gemini_oauth_fetch_failed",
                reason = %redact_tokens(&e),
                "gemini_oauth poller: projection fetch failed, skipping tick writes"
            );
            return;
        }
    };

    // Round-3 redteam HIGH: track sentinel-vs-real EXPLICITLY by
    // whether `aggregate_to_usage_window` returned `None`. Inferring
    // from field shape (`used_percentage == 0.0 && limiting_*.is_none()`)
    // is wrong because a real bucket at 100%-remaining with no
    // `modelId` would deserialize to a Some(projection) with the
    // same field shape — UI would render "awaiting_quota" for an
    // account that's connected and idle.
    let is_sentinel = projection.is_none();
    let projection = projection.unwrap_or(UsageWindowProjection {
        used_percentage: 0.0,
        resets_at_iso: None,
        limiting_model: None,
        limiting_token_type: None,
    });

    // Write the same projection to every OAuth-mode slot.
    for slot in oauth_slots {
        if let Err(e) = write_quota(base_dir, slot, &projection, is_sentinel) {
            warn!(
                slot = slot.get(),
                error_kind = "gemini_oauth_write_failed",
                reason = %redact_tokens(&e.to_string()),
                "gemini_oauth poller: quota write failed"
            );
        }
    }
}

/// Reads the user's OAuth identity, fetches the (cached) project,
/// fetches the bucket info, and aggregates to a single projection.
/// Returns `Ok(None)` when the data is structurally complete but the
/// user has no usable buckets yet (e.g., fresh login, no quota usage
/// recorded). Returns `Err(String)` on any failure that should
/// trigger a tick skip.
async fn fetch_projection_for_identity(
    home: &Path,
    http_post: &HttpPostProbeFn,
    project_cache: &ProjectCache,
) -> Result<Option<UsageWindowProjection>, String> {
    // Round-2 redteam HIGH + round-3 follow-up: in-flight guard
    // with RAII cleanup. If a previous tick's read_oauth_creds is
    // still running on a wedged filesystem, skip rather than pin
    // another blocking-pool worker. The guard's Drop fires on every
    // exit path — Ok, Err, panic — so the flag never stays stuck
    // even if `read_oauth_creds` panics inside the spawn_blocking
    // closure.
    let _in_flight_guard = match InFlightGuard::try_acquire(project_cache) {
        Some(g) => g,
        None => {
            return Err(
                "previous read_oauth_creds still in flight — filesystem may be wedged, \
                 skipping this tick to avoid pinning another blocking-pool worker"
                    .to_string(),
            );
        }
    };

    // Filesystem read on the blocking pool — avoid stalling the async
    // runtime on a slow ~/.gemini/ (NFS, encrypted home). The
    // InFlightGuard's Drop clears the flag when this function
    // returns, regardless of how (Ok, Err, panic). spawn_blocking
    // tasks that outlive a tokio timeout-cancellation also drop the
    // closure when they complete; if the closure panics, the
    // poisoned mutex's recovery path in subsequent ticks will reset
    // both the flag (via guard.oauth_creds_read_in_flight = false in
    // poison handler) and the project cache.
    let home_owned = home.to_path_buf();
    let creds_result = tokio::task::spawn_blocking(move || read_oauth_creds(&home_owned)).await;
    let creds = creds_result
        .map_err(|e| format!("read_oauth_creds spawn_blocking: {e}"))?
        .map_err(|e| format!("oauth_creds: {e}"))?;

    let bearer = creds.access_token.expose_secret().to_string();
    let identity_fp = fingerprint_token(&bearer);
    let headers = build_headers(&bearer);

    // Step 1: project discovery (cached across ticks). Cache hit
    // means we skip loadCodeAssist entirely. Track whether the
    // project came from cache so we can invalidate on ANY downstream
    // failure (round-2 redteam HIGH: 401/403 isn't the only
    // staleness signal — 404 / 400 / wrong-data also indicate the
    // cached project is no longer valid for the current identity).
    let (project, project_came_from_cache) = {
        let cached = {
            let guard = project_cache.lock().unwrap_or_else(|p| {
                // Mutex poisoning: preserve project (round-3 LOW —
                // the poison cause is unrelated to the project
                // value), reset only the in-flight flag.
                warn!(
                    error_kind = "gemini_oauth_cache_poisoned",
                    "gemini_oauth: project cache mutex was poisoned"
                );
                let mut g = p.into_inner();
                g.oauth_creds_read_in_flight = false;
                g
            });
            guard
                .project
                .as_ref()
                .filter(|c| c.identity_fingerprint == identity_fp)
                .map(|c| c.project.clone())
        };
        match cached {
            Some(p) => (p, true),
            None => {
                let load_url = format!("{}:loadCodeAssist", CLOUDCODE_PA_BASE_URL);
                let load_body = build_load_code_assist_body();
                let http = Arc::clone(http_post);
                let headers_for_load = headers.clone();
                let load_resp = timeout(
                    CALL_TIMEOUT,
                    tokio::task::spawn_blocking(move || {
                        http(&load_url, &headers_for_load, &load_body)
                    }),
                )
                .await
                .map_err(|_| "loadCodeAssist timed out".to_string())?
                .map_err(|e| format!("loadCodeAssist spawn_blocking: {e}"))?
                .map_err(|e| format!("loadCodeAssist transport: {e}"))?;

                let (status, _h, body) = load_resp;
                if status != 200 {
                    return Err(format!("loadCodeAssist non-200: status={status}"));
                }
                let parsed: LoadCodeAssistResponse = serde_json::from_str(&body)
                    .map_err(|e| format!("loadCodeAssist parse: {e}"))?;
                let project = match parsed.project {
                    Some(p) => p,
                    None => {
                        debug!("gemini_oauth: loadCodeAssist returned no project");
                        return Ok(None);
                    }
                };
                // Round-3 redteam HIGH: do NOT cache the project
                // here. Caching before retrieveUserQuota succeeds
                // creates a 2-tick stuck state — if retrieveUserQuota
                // returns non-200 (project is wrong for this
                // identity), the freshly-cached invalid project
                // sticks. Cache only after BOTH calls succeed (see
                // post-retrieveUserQuota write below).
                (project, false)
            }
        }
    };

    // Step 2: retrieve quota with the discovered project.
    let quota_url = format!("{}:retrieveUserQuota", CLOUDCODE_PA_BASE_URL);
    let quota_body = build_retrieve_user_quota_body(&project);
    let http = Arc::clone(http_post);
    let quota_resp = timeout(
        CALL_TIMEOUT,
        tokio::task::spawn_blocking(move || http(&quota_url, &headers, &quota_body)),
    )
    .await
    .map_err(|_| "retrieveUserQuota timed out".to_string())?
    .map_err(|e| format!("retrieveUserQuota spawn_blocking: {e}"))?
    .map_err(|e| format!("retrieveUserQuota transport: {e}"))?;

    let (status, _h, body) = quota_resp;
    if status != 200 {
        // Round-2 redteam HIGH: broaden cache invalidation. ANY
        // non-200 from retrieveUserQuota AFTER a cache hit means
        // the cached project is no longer valid for the current
        // identity (401/403 = auth, 404 = project not found for
        // this caller, 400 = invalid project string, etc).
        // Round-3 redteam HIGH: cache-miss + non-200 doesn't need
        // explicit invalidation anymore because we deferred the
        // cache write to after retrieveUserQuota — there is nothing
        // to invalidate on the cache-miss path.
        if project_came_from_cache {
            let mut guard = project_cache.lock().unwrap_or_else(|p| p.into_inner());
            guard.project = None;
        }
        return Err(format!("retrieveUserQuota non-200: status={status}"));
    }

    // Both calls succeeded — NOW cache the project (round-3 fix).
    // No-op if the project came from cache (already cached).
    if !project_came_from_cache {
        let mut guard = project_cache.lock().unwrap_or_else(|p| p.into_inner());
        guard.project = Some(CachedProject {
            identity_fingerprint: identity_fp,
            project: project.clone(),
        });
    }

    let parsed: RetrieveUserQuotaResponse =
        serde_json::from_str(&body).map_err(|e| format!("retrieveUserQuota parse: {e}"))?;
    let buckets = parsed.buckets.unwrap_or_default();
    Ok(aggregate_to_usage_window(&buckets))
}

/// Enumerates Gemini slots whose binding marker is in OAuth mode.
/// Walks `<base_dir>/credentials/gemini-*.json`, reads each marker,
/// keeps slots where `auth = CodeAssistOAuth`. Returns slots in
/// numerical order so tick output is deterministic.
pub fn enumerate_oauth_mode_slots(base_dir: &Path) -> Vec<AccountNum> {
    let mut slots = Vec::new();
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(_) => return slots,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let stem = match name
            .strip_prefix("gemini-")
            .and_then(|s| s.strip_suffix(".json"))
        {
            Some(s) => s,
            None => continue,
        };
        let n: u16 = match stem.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let slot = match AccountNum::try_from(n) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let binding = match read_binding(base_dir, slot) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if matches!(binding.auth, AuthMode::CodeAssistOAuth) {
            slots.push(slot);
        }
    }
    slots.sort_by_key(|s| s.get());
    slots
}

/// Persists the Code Assist quota projection into `quota.json[<slot>]`
/// as a Utilization-shape Gemini row. Mirrors the Anthropic + Codex
/// poller write path: acquires `quota.json.lock` before
/// load+modify+save so concurrent writers serialize.
///
/// Schema coherence on rebind: a slot transitioning from
/// ApiKey/VertexSa (Counter) to OAuth (Utilization) gets its
/// Counter-mode fields explicitly cleared so the on-disk row is
/// internally consistent (no `kind=utilization` row with stale
/// `counter.requests_today` data).
fn write_quota(
    base_dir: &Path,
    slot: AccountNum,
    projection: &UsageWindowProjection,
    is_sentinel: bool,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;

    // load_state failure → SKIP the write. Falling back to
    // QuotaFile::empty would silently destroy every other account's
    // quota when the file is corrupt.
    let mut quota_file = match quota_state::load_state(base_dir) {
        Ok(qf) => qf,
        Err(e) => {
            warn!(
                slot = slot.get(),
                error_kind = "gemini_oauth_load_state_failed",
                reason = %redact_tokens(&e.to_string()),
                "gemini_oauth poller: quota.json unreadable, skipping write to avoid clobber"
            );
            return Ok(());
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let key = slot.get().to_string();
    let entry = quota_file.accounts.entry(key).or_default();

    entry.surface = "gemini".to_string();
    entry.kind = "utilization".to_string();
    entry.updated_at = now;

    // Code Assist resets are typically daily; map into the
    // seven_day window (the only multi-hour utilization window the
    // schema currently exposes) and set five_hour to None. The UI
    // MUST read `extras.code_assist_limiting_token_type` +
    // `extras.code_assist_window_kind` for accurate cadence labeling.
    //
    // Round-4 redteam MED: sentinel rows do NOT populate
    // `seven_day` at all. The sentinel intent is "connected, no
    // usable quota window yet" — that's exactly the `None`
    // semantics. The diagnostic `code_assist_status="awaiting_quota"`
    // in extras is the SOLE sentinel signal. Skipping the synthesized
    // window:
    //   (a) keeps Gemini OAuth sentinels out of the desktop UI's
    //       reset-rank pool (`AccountList.svelte`'s ranking filters
    //       on `seven_day_resets_in`),
    //   (b) keeps them out of the seven-day-reset sort,
    //   (c) eliminates the year-2100 anti-decay literal we'd need
    //       otherwise to dodge `clear_expired`.
    if is_sentinel {
        entry.seven_day = None;
    } else {
        let resets_at = projection
            .resets_at_iso
            .as_deref()
            .and_then(parse_iso8601_to_unix_secs)
            .unwrap_or(0);
        entry.seven_day = Some(UsageWindow {
            used_percentage: projection.used_percentage,
            resets_at,
        });
    }
    entry.five_hour = None;

    // Schema coherence on rebind: clear Counter-mode fields when
    // transitioning to Utilization. A slot that was ApiKey/VertexSa
    // accumulated counter / rate_limit / effective_model from
    // gemini::drain_all events; those are stale on a Utilization row.
    entry.counter = None;
    entry.rate_limit = None;
    entry.selected_model = None;
    entry.effective_model = None;
    entry.effective_model_first_seen_at = None;
    entry.mismatch_count_today = None;
    entry.is_downgrade = None;

    // Extras: merge instead of clobber. Preserves any keys other
    // surfaces or other ticks added; updates only the Code Assist
    // diagnostic fields.
    let mut merged = match entry.extras.take() {
        Some(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    if is_sentinel {
        // Round-3 redteam HIGH: real → awaiting transition. Sentinel
        // rows MUST NOT carry stale `code_assist_limiting_*` from a
        // prior "real" tick — the UI would render "Connected —
        // awaiting quota" alongside "limited by gemini-2.5-flash"
        // (a direct contradiction). Explicitly remove the limiting
        // fields here.
        merged.remove("code_assist_limiting_model");
        merged.remove("code_assist_limiting_token_type");
        merged.insert(
            "code_assist_status".into(),
            serde_json::Value::String("awaiting_quota".into()),
        );
    } else {
        // Round-2 redteam HIGH: only OVERWRITE the diagnostic
        // fields when the new projection has a value for them. A
        // projection with `limiting_model = None` from a "real"
        // tick previously caused unconditional remove() → clobber-
        // by-omission of a perfectly-good prior value.
        if let Some(m) = projection.limiting_model.as_deref() {
            merged.insert(
                "code_assist_limiting_model".into(),
                serde_json::Value::String(m.into()),
            );
        }
        if let Some(t) = projection.limiting_token_type.as_deref() {
            merged.insert(
                "code_assist_limiting_token_type".into(),
                serde_json::Value::String(t.into()),
            );
        }
        // Awaiting → real transition: clear the status marker.
        merged.remove("code_assist_status");
    }
    // Window kind is always present (we always know csq's mapping
    // semantics) so always-overwrite is correct here.
    merged.insert(
        "code_assist_window_kind".into(),
        serde_json::Value::String("daily".into()),
    );
    if !merged.is_empty() {
        entry.extras = Some(serde_json::Value::Object(merged));
    }

    quota_state::save_state(base_dir, &quota_file)?;
    Ok(())
}

/// Minimal RFC 3339 / ISO 8601 → Unix seconds parser. Avoids pulling
/// in chrono for one parse. Accepts `YYYY-MM-DDTHH:MM:SS[.fff]Z`;
/// returns None on any parse failure or out-of-range field.
fn parse_iso8601_to_unix_secs(s: &str) -> Option<u64> {
    // Drop trailing Z; reject anything else (timezone offsets aren't
    // emitted by the Code Assist endpoint per gemini-cli test fixtures).
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut date_iter = date.splitn(3, '-');
    let year: i64 = date_iter.next()?.parse().ok()?;
    let month: u32 = date_iter.next()?.parse().ok()?;
    let day: u32 = date_iter.next()?.parse().ok()?;

    let time = time.split('.').next().unwrap_or(time);
    let mut time_iter = time.splitn(3, ':');
    let hour: u32 = time_iter.next()?.parse().ok()?;
    let minute: u32 = time_iter.next()?.parse().ok()?;
    let second: u32 = time_iter.next()?.parse().ok()?;

    // Bounds check (mirrors the anthropic.rs parser). Reject obvious
    // schema-drift signals rather than silently rolling them into
    // adjacent days/months.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    // Days since Unix epoch using the standard "days from civil"
    // algorithm (Howard Hinnant). Avoids chrono.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch: i64 = era * 146_097 + doe as i64 - 719_468;

    let seconds =
        days_since_epoch * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    if seconds < 0 {
        return None;
    }
    Some(seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::gemini::provisioning::{write_binding, GeminiBinding};
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn enumerate_finds_only_oauth_mode_slots() {
        let dir = TempDir::new().unwrap();
        // Slot 1: ApiKey — should NOT be enumerated.
        let api_key_binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(1), &api_key_binding).unwrap();
        // Slot 2: CodeAssistOAuth — should be enumerated.
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(2), &oauth_binding).unwrap();
        // Slot 3: CodeAssistOAuth — should also be enumerated.
        write_binding(dir.path(), slot(3), &oauth_binding).unwrap();
        // Slot 5: VertexSa — should NOT be enumerated.
        let vertex_binding = GeminiBinding::new(
            AuthMode::VertexSa {
                path: dir.path().join("sa.json"),
            },
            "auto",
        );
        write_binding(dir.path(), slot(5), &vertex_binding).unwrap();

        let oauth_slots = enumerate_oauth_mode_slots(dir.path());
        let nums: Vec<u16> = oauth_slots.iter().map(|s| s.get()).collect();
        assert_eq!(nums, vec![2, 3]);
    }

    #[test]
    fn enumerate_returns_empty_when_creds_dir_missing() {
        let dir = TempDir::new().unwrap();
        // No credentials/ subdir at all.
        let oauth_slots = enumerate_oauth_mode_slots(dir.path());
        assert!(oauth_slots.is_empty());
    }

    #[test]
    fn enumerate_skips_malformed_marker_files() {
        let dir = TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("gemini-7.json"), "{ this is not json").unwrap();

        let oauth_slots = enumerate_oauth_mode_slots(dir.path());
        assert!(oauth_slots.is_empty());
    }

    #[test]
    fn parses_iso8601_to_unix_secs_known_dates() {
        // 2024-01-01T00:00:00Z = 1704067200 (verified `date -ud '2024-01-01' +%s`)
        assert_eq!(
            parse_iso8601_to_unix_secs("2024-01-01T00:00:00Z"),
            Some(1_704_067_200)
        );
        // With fractional seconds (dropped).
        assert_eq!(
            parse_iso8601_to_unix_secs("2024-01-01T00:00:00.123Z"),
            Some(1_704_067_200)
        );
        // 2099-12-31T23:59:59Z.
        assert_eq!(
            parse_iso8601_to_unix_secs("2099-12-31T23:59:59Z"),
            Some(4_102_444_799)
        );
    }

    #[test]
    fn parses_iso8601_rejects_out_of_range_components() {
        // Redteam round 1 MED: bounds-check parity with anthropic.rs.
        assert!(parse_iso8601_to_unix_secs("2024-13-01T00:00:00Z").is_none());
        assert!(parse_iso8601_to_unix_secs("2024-01-32T00:00:00Z").is_none());
        assert!(parse_iso8601_to_unix_secs("2024-01-01T25:00:00Z").is_none());
        assert!(parse_iso8601_to_unix_secs("2024-01-01T00:60:00Z").is_none());
        // Leap second (60) is allowed; 61+ is not.
        assert!(parse_iso8601_to_unix_secs("2024-01-01T00:00:60Z").is_some());
        assert!(parse_iso8601_to_unix_secs("2024-01-01T00:00:61Z").is_none());
    }

    #[test]
    fn parses_iso8601_rejects_non_z_timezone() {
        assert!(parse_iso8601_to_unix_secs("2024-01-01T00:00:00+05:00").is_none());
    }

    #[test]
    fn parses_iso8601_rejects_malformed() {
        assert!(parse_iso8601_to_unix_secs("not a date").is_none());
    }

    /// End-to-end tick test with a mock HTTP transport. Verifies the
    /// hardened poller calls loadCodeAssist + retrieveUserQuota once
    /// per tick (not per slot), parses the response, aggregates, and
    /// writes quota.json with surface=gemini, kind=utilization,
    /// counter fields cleared, and extras carrying the limiting
    /// model + window-kind diagnostic.
    ///
    /// `await_holding_lock` is suppressed: per `rules/testing.md`
    /// Rule 6, tests that mutate process env MUST hold
    /// `test_env::lock()` for the full duration of the env-sensitive
    /// work — including across `tick(...).await` because the poller
    /// reads HOME inside spawn_blocking. The single-threaded tokio
    /// test runtime bounds deadlock risk.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn tick_writes_to_every_oauth_slot_with_one_http_pair() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(2), &oauth_binding).unwrap();
        write_binding(dir.path(), slot(3), &oauth_binding).unwrap();
        // ApiKey-mode slot (must NOT be touched by this poller)
        let api_binding = GeminiBinding::new(AuthMode::ApiKey, "auto");
        write_binding(dir.path(), slot(1), &api_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.test_token"}"#,
        )
        .unwrap();
        // SAFETY: _guard MUST outlive `tick(...).await` because tick
        // spawns blocking workers that read HOME on the shared
        // blocking pool. Dropping early lets a sibling test's env
        // mutation race in.
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        // Mock counts how many times loadCodeAssist + retrieveUserQuota
        // are called. Dedup contract: ONE pair per tick, not per slot.
        let load_calls = Arc::new(Mutex::new(0u32));
        let quota_calls = Arc::new(Mutex::new(0u32));
        let load_calls_c = Arc::clone(&load_calls);
        let quota_calls_c = Arc::clone(&quota_calls);
        let mock: HttpPostProbeFn = Arc::new(move |url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                *load_calls_c.lock().unwrap() += 1;
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/test-csq-codeassist"}"#.to_string(),
                ))
            } else if url.contains(":retrieveUserQuota") {
                *quota_calls_c.lock().unwrap() += 1;
                Ok((
                    200,
                    Default::default(),
                    r#"{"buckets":[
                        {"modelId":"gemini-2.5-pro","tokenType":"REQUESTS","remainingFraction":0.6,"resetTime":"2099-10-22T16:01:15Z"},
                        {"modelId":"gemini-2.5-flash","tokenType":"REQUESTS","remainingFraction":0.2,"resetTime":"2099-10-22T16:01:15Z"}
                    ]}"#.to_string(),
                ))
            } else {
                Ok((404, Default::default(), String::new()))
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        // Dedup: ONE call to each endpoint per tick, regardless of N
        // OAuth slots.
        assert_eq!(
            *load_calls.lock().unwrap(),
            1,
            "loadCodeAssist must be called once per tick (dedup across N OAuth slots)"
        );
        assert_eq!(
            *quota_calls.lock().unwrap(),
            1,
            "retrieveUserQuota must be called once per tick (dedup across N OAuth slots)"
        );

        // Both OAuth slots got identical quota writes.
        let qf = quota_state::load_state(dir.path()).unwrap();
        for s in [2u16, 3u16] {
            let acct = qf
                .accounts
                .get(&s.to_string())
                .unwrap_or_else(|| panic!("slot {s} written"));
            assert_eq!(acct.surface, "gemini");
            assert_eq!(acct.kind, "utilization");
            assert!(
                acct.counter.is_none(),
                "Counter fields cleared on Utilization row"
            );
            let seven = acct.seven_day.as_ref().expect("seven_day populated");
            assert!((seven.used_percentage - 80.0).abs() < 0.001);
            // ISO8601 parsed correctly to a non-zero epoch.
            assert!(seven.resets_at > 0, "resets_at must be parsed, not 0");
            let extras = acct.extras.as_ref().unwrap();
            assert_eq!(extras["code_assist_limiting_model"], "gemini-2.5-flash");
            assert_eq!(extras["code_assist_window_kind"], "daily");
            // Round-3 redteam MED: the non-sentinel path MUST NOT
            // carry `code_assist_status="awaiting_quota"`.
            assert!(
                extras
                    .as_object()
                    .map(|m| !m.contains_key("code_assist_status"))
                    .unwrap_or(false),
                "non-sentinel write must not carry code_assist_status: {extras:?}"
            );
        }
        // ApiKey slot 1 was NOT touched by this poller.
        assert!(
            !qf.accounts.contains_key("1"),
            "ApiKey-mode slot must not be written by gemini_oauth poller"
        );
    }

    /// Project cache hit: second tick under the same identity does
    /// NOT call loadCodeAssist again.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn project_cache_hit_skips_load_code_assist_on_subsequent_tick() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(4), &oauth_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.cached_token"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let load_calls = Arc::new(Mutex::new(0u32));
        let load_calls_c = Arc::clone(&load_calls);
        let mock: HttpPostProbeFn = Arc::new(move |url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                *load_calls_c.lock().unwrap() += 1;
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/cached"}"#.to_string(),
                ))
            } else if url.contains(":retrieveUserQuota") {
                Ok((
                    200,
                    Default::default(),
                    r#"{"buckets":[{"modelId":"gemini-2.5-pro","tokenType":"REQUESTS","remainingFraction":0.5,"resetTime":"2099-10-22T16:01:15Z"}]}"#.to_string(),
                ))
            } else {
                Ok((404, Default::default(), String::new()))
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));

        // Tick 1 — populates cache.
        tick(dir.path(), &mock, &cache).await;
        // Tick 2 — same identity, should skip loadCodeAssist.
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(
            *load_calls.lock().unwrap(),
            1,
            "loadCodeAssist must be cached after first success — got {}",
            *load_calls.lock().unwrap()
        );
    }

    /// load_state failure (corrupt quota.json) MUST NOT clobber other
    /// accounts. The OAuth poller logs and skips its own write.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn corrupt_quota_json_does_not_clobber_other_accounts() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(6), &oauth_binding).unwrap();

        // Plant a corrupt quota.json with another account's data
        // that's "valuable" (must survive a corrupt-load → skip-write).
        std::fs::write(
            quota_state::quota_path(dir.path()),
            "{ this is not valid json",
        )
        .unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.t"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let mock: HttpPostProbeFn = Arc::new(|url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/x"}"#.to_string(),
                ))
            } else {
                Ok((
                    200,
                    Default::default(),
                    r#"{"buckets":[{"modelId":"gemini-2.5-pro","tokenType":"REQUESTS","remainingFraction":0.5,"resetTime":"2099-10-22T16:01:15Z"}]}"#.to_string(),
                ))
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        // The corrupt file should NOT have been replaced with a fresh
        // empty file containing only this slot.
        let on_disk = std::fs::read_to_string(quota_state::quota_path(dir.path())).unwrap();
        assert!(
            on_disk.contains("not valid json"),
            "corrupt quota.json must be preserved (skip-write semantics): on_disk={on_disk}"
        );
    }

    /// Round-3 redteam MED: full-token hash distinguishes tokens
    /// that share a long prefix. Earlier first-32-char truncation
    /// would collide on Google ya29.* tokens that share the
    /// deterministic-looking header (~30+ chars).
    #[test]
    fn fingerprint_token_distinguishes_long_shared_prefix_tokens() {
        // 64 shared chars + 16 differing chars.
        let shared = "ya29.a0Ae_FAKE_token_with_long_shared_prefix_aaaaaaaaaaaaaaaaaaaa";
        let token_a = format!("{shared}_DIFFER_AAAAAAA");
        let token_b = format!("{shared}_DIFFER_BBBBBBB");
        assert_eq!(token_a.len(), token_b.len());
        // Confirm the prefix length triggers what would have been the
        // old prefix-truncation collision.
        assert!(token_a
            .chars()
            .zip(token_b.chars())
            .take(32)
            .all(|(a, b)| a == b));
        let fp_a = fingerprint_token(&token_a);
        let fp_b = fingerprint_token(&token_b);
        assert_ne!(
            fp_a, fp_b,
            "fingerprint_token must distinguish long-shared-prefix tokens"
        );
    }

    /// Round-3 redteam HIGH: empty-buckets sentinel write path. A
    /// 200 + empty-buckets response synthesizes a sentinel projection
    /// and writes `code_assist_status="awaiting_quota"` to extras.
    /// Limiting fields are explicitly absent.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn tick_writes_sentinel_when_buckets_empty() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(7), &oauth_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.fresh_login_no_usage"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let mock: HttpPostProbeFn = Arc::new(|url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/fresh"}"#.to_string(),
                ))
            } else {
                // Empty buckets: connected but no usage recorded yet.
                Ok((200, Default::default(), r#"{"buckets":[]}"#.to_string()))
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        let qf = quota_state::load_state(dir.path()).unwrap();
        let acct = qf
            .accounts
            .get("7")
            .expect("slot 7 written even on empty buckets");
        let extras = acct.extras.as_ref().unwrap();
        assert_eq!(
            extras["code_assist_status"], "awaiting_quota",
            "sentinel write must mark code_assist_status"
        );
        assert_eq!(extras["code_assist_window_kind"], "daily");
        let extras_obj = extras.as_object().unwrap();
        assert!(
            !extras_obj.contains_key("code_assist_limiting_model"),
            "sentinel write must NOT carry stale limiting_model"
        );
        assert!(
            !extras_obj.contains_key("code_assist_limiting_token_type"),
            "sentinel write must NOT carry stale limiting_token_type"
        );
        // Round-4 redteam MED: sentinel rows MUST NOT populate
        // seven_day — the giant year-2100 epoch the previous fix
        // used would have leaked into AccountStatus.seven_day_resets_in
        // as a ~2.34B-second countdown, polluting the UI's reset-rank
        // pool and seven-day sort.
        assert!(
            acct.seven_day.is_none(),
            "sentinel rows must leave seven_day unset; status=awaiting_quota in extras is the sentinel signal"
        );
    }

    /// Round-3 redteam HIGH: real → awaiting transition clears
    /// stale limiting fields. A slot that previously had a real
    /// projection (limiting_model populated) and then transitions
    /// to a sentinel (empty buckets, e.g. user revoked subscription)
    /// MUST NOT carry the stale limiting fields under
    /// code_assist_status="awaiting_quota" (that combination is a
    /// direct contradiction the UI cannot render coherently).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn real_to_awaiting_transition_clears_stale_limiting_fields() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(8), &oauth_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.transitioning_user"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let phase = Arc::new(Mutex::new(0u32));
        let phase_c = Arc::clone(&phase);
        let mock: HttpPostProbeFn = Arc::new(move |url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/transit"}"#.to_string(),
                ))
            } else {
                let phase_now = *phase_c.lock().unwrap();
                if phase_now == 0 {
                    // Tick 1: real bucket with limiting_model.
                    Ok((
                        200,
                        Default::default(),
                        r#"{"buckets":[{"modelId":"gemini-2.5-pro","tokenType":"REQUESTS","remainingFraction":0.4,"resetTime":"2099-10-22T16:01:15Z"}]}"#.to_string(),
                    ))
                } else {
                    // Tick 2: empty buckets (user revoked).
                    Ok((200, Default::default(), r#"{"buckets":[]}"#.to_string()))
                }
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        // Tick 1: real → extras carries limiting_model.
        tick(dir.path(), &mock, &cache).await;
        let qf = quota_state::load_state(dir.path()).unwrap();
        let extras = qf.accounts["8"].extras.as_ref().unwrap();
        assert_eq!(extras["code_assist_limiting_model"], "gemini-2.5-pro");

        // Tick 2: empty buckets → sentinel. Must clear stale fields.
        *phase.lock().unwrap() = 1;
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        let qf = quota_state::load_state(dir.path()).unwrap();
        let acct = &qf.accounts["8"];
        let extras = acct.extras.as_ref().unwrap();
        let extras_obj = extras.as_object().unwrap();
        assert_eq!(extras["code_assist_status"], "awaiting_quota");
        assert!(
            !extras_obj.contains_key("code_assist_limiting_model"),
            "real → awaiting transition must clear stale limiting_model: {extras:?}"
        );
        assert!(
            !extras_obj.contains_key("code_assist_limiting_token_type"),
            "real → awaiting transition must clear stale limiting_token_type"
        );
        // Round-4 redteam MED: sentinel rows MUST NOT carry a
        // `seven_day` window. The transition must DROP the prior
        // tick's window when the new tick lands as sentinel — the
        // UI's reset-rank pool depends on this to exclude
        // awaiting-quota slots.
        assert!(
            acct.seven_day.is_none(),
            "real → awaiting transition must clear seven_day: {acct:?}"
        );
    }

    /// Round-4 redteam MED: awaiting → real transition. A slot that
    /// began as a sentinel (empty buckets, `code_assist_status=
    /// "awaiting_quota"`) must shed the marker AND populate
    /// `seven_day` once Google starts returning real bucket data.
    /// Symmetric to `real_to_awaiting_transition_clears_stale_limiting_fields`.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn awaiting_to_real_transition_clears_status_and_populates_seven_day() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(11), &oauth_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.fresh_to_active_user"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let phase = Arc::new(Mutex::new(0u32));
        let phase_c = Arc::clone(&phase);
        let mock: HttpPostProbeFn = Arc::new(move |url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/p"}"#.to_string(),
                ))
            } else {
                let phase_now = *phase_c.lock().unwrap();
                if phase_now == 0 {
                    // Tick 1: empty buckets → sentinel.
                    Ok((200, Default::default(), r#"{"buckets":[]}"#.to_string()))
                } else {
                    // Tick 2: real bucket → real projection.
                    Ok((
                        200,
                        Default::default(),
                        r#"{"buckets":[{"modelId":"gemini-2.5-pro","tokenType":"REQUESTS","remainingFraction":0.5,"resetTime":"2099-10-22T16:01:15Z"}]}"#.to_string(),
                    ))
                }
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        // Tick 1: sentinel.
        tick(dir.path(), &mock, &cache).await;
        let qf = quota_state::load_state(dir.path()).unwrap();
        let extras = qf.accounts["11"].extras.as_ref().unwrap();
        assert_eq!(extras["code_assist_status"], "awaiting_quota");
        assert!(qf.accounts["11"].seven_day.is_none());

        // Tick 2: real → must shed the sentinel marker AND populate seven_day.
        *phase.lock().unwrap() = 1;
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        let qf = quota_state::load_state(dir.path()).unwrap();
        let acct = &qf.accounts["11"];
        let extras = acct.extras.as_ref().unwrap();
        let extras_obj = extras.as_object().unwrap();
        assert!(
            !extras_obj.contains_key("code_assist_status"),
            "awaiting → real transition must shed code_assist_status marker: {extras:?}"
        );
        assert_eq!(extras["code_assist_limiting_model"], "gemini-2.5-pro");
        assert!(
            acct.seven_day.is_some(),
            "awaiting → real transition must populate seven_day: {acct:?}"
        );
        let seven = acct.seven_day.as_ref().unwrap();
        assert!((seven.used_percentage - 50.0).abs() < 0.001);
    }

    /// Round-4 redteam MED: InFlightGuard panic-safety. If
    /// `read_oauth_creds` panics inside `spawn_blocking`, the closure
    /// unwinds without clearing `oauth_creds_read_in_flight` directly.
    /// The RAII Drop on the outer `_in_flight_guard` MUST clear the
    /// flag so the next tick is not permanently stuck on
    /// "previous read_oauth_creds still in flight."
    ///
    /// We can't easily inject a panic into the real `read_oauth_creds`
    /// without wiring a test-only shim. Instead we exercise the
    /// `InFlightGuard` directly with a synthesized panic scope.
    #[test]
    fn in_flight_guard_releases_flag_on_panic() {
        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        // Acquire + immediately panic inside a catch_unwind. After
        // unwind, Drop must have fired and cleared the flag.
        let cache_for_thread = Arc::clone(&cache);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard =
                InFlightGuard::try_acquire(&cache_for_thread).expect("first try_acquire succeeds");
            panic!("simulated panic while in-flight guard is held");
        }));
        assert!(result.is_err(), "test must capture the panic");
        // Verify the flag is cleared (RAII Drop fired during unwind).
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            !guard.oauth_creds_read_in_flight,
            "InFlightGuard::Drop must clear the flag during panic unwind"
        );
        drop(guard);
        // And subsequent acquire must succeed (flag was actually cleared).
        let next = InFlightGuard::try_acquire(&cache);
        assert!(
            next.is_some(),
            "next try_acquire must succeed (flag was released by Drop)"
        );
    }

    /// Round-3 redteam HIGH: cache-miss + retrieveUserQuota non-200
    /// must NOT cache the invalid project. Earlier code wrote the
    /// project to cache as soon as loadCodeAssist returned 200,
    /// creating a 2-tick stuck state when retrieveUserQuota then
    /// returned 4xx.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn cache_miss_with_retrieve_quota_404_does_not_cache_invalid_project() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(9), &oauth_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.invalid_project_id_user"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let load_calls = Arc::new(Mutex::new(0u32));
        let load_calls_c = Arc::clone(&load_calls);
        let mock: HttpPostProbeFn = Arc::new(move |url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                *load_calls_c.lock().unwrap() += 1;
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/wrong-for-this-user"}"#.to_string(),
                ))
            } else {
                // 404: project not found for this caller.
                Ok((404, Default::default(), String::new()))
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        // Tick 1: cache miss → loadCodeAssist=200 → retrieveUserQuota=404.
        // Project must NOT be cached (round-3 fix).
        tick(dir.path(), &mock, &cache).await;
        // Tick 2: should be ANOTHER cache miss (loadCodeAssist
        // called again), not a cache hit.
        tick(dir.path(), &mock, &cache).await;

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(
            *load_calls.lock().unwrap(),
            2,
            "loadCodeAssist must be called BOTH ticks — cache must not retain an invalid project"
        );
    }

    /// Round-3 redteam HIGH: even when retrieveUserQuota returns
    /// e.g. 500 on cache hit, the cached project IS invalidated so
    /// the next tick re-discovers (broaden beyond 401/403).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn cache_hit_with_retrieve_quota_500_invalidates_cache() {
        let dir = TempDir::new().unwrap();
        let oauth_binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(dir.path(), slot(10), &oauth_binding).unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(
            home.join(".gemini/oauth_creds.json"),
            r#"{"access_token":"ya29.user_with_caching_then_500"}"#,
        )
        .unwrap();
        let _guard = crate::platform::test_env::lock();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let load_calls = Arc::new(Mutex::new(0u32));
        let phase = Arc::new(Mutex::new(0u32));
        let load_calls_c = Arc::clone(&load_calls);
        let phase_c = Arc::clone(&phase);
        let mock: HttpPostProbeFn = Arc::new(move |url: &str, _h, _b| {
            if url.contains(":loadCodeAssist") {
                *load_calls_c.lock().unwrap() += 1;
                Ok((
                    200,
                    Default::default(),
                    r#"{"cloudaicompanionProject":"projects/p"}"#.to_string(),
                ))
            } else {
                let phase_now = *phase_c.lock().unwrap();
                if phase_now == 0 {
                    // Tick 1: success → caches project.
                    Ok((
                        200,
                        Default::default(),
                        r#"{"buckets":[{"modelId":"gemini-2.5-pro","tokenType":"REQUESTS","remainingFraction":0.5,"resetTime":"2099-10-22T16:01:15Z"}]}"#.to_string(),
                    ))
                } else {
                    // Tick 2: 500 on a cache-hit path.
                    Ok((500, Default::default(), String::new()))
                }
            }
        });

        let cache: ProjectCache = Arc::new(Mutex::new(ProjectCacheState::default()));
        tick(dir.path(), &mock, &cache).await; // populates cache
        *phase.lock().unwrap() = 1;
        tick(dir.path(), &mock, &cache).await; // 500 invalidates
        tick(dir.path(), &mock, &cache).await; // re-discovers

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        // loadCodeAssist called twice: tick 1 (initial cache miss)
        // and tick 3 (cache was invalidated by tick 2's 500).
        assert_eq!(
            *load_calls.lock().unwrap(),
            2,
            "non-200 on cache hit must invalidate; round-2 broaden-invalidation contract"
        );
    }
}
