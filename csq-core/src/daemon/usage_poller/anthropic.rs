//! Anthropic account usage polling.
//!
//! Polls `GET /api/oauth/usage` for each Anthropic account, parses
//! the response, and writes quota data to `quota.json`.

use crate::accounts::{discovery, AccountSource};
use crate::credentials::{self, file as cred_file};
use crate::quota::{state as quota_state, AccountQuota, PollOutcome, PollerHealth, UsageWindow};
use crate::types::AccountNum;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, warn};

use super::{
    classify_transport_error, clear_backoff, clear_cooldown, in_cooldown, increase_backoff,
    set_cooldown, set_cooldown_with_backoff, set_cooldown_with_backoff_and_retry_after,
    HttpGetWithRetryAfterFn, PollError, CALL_TIMEOUT, MAX_ACCOUNTS_PER_TICK,
};

/// Anthropic base URL for OAuth usage.
pub(crate) const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

/// Beta header value required for the usage endpoint.
pub(crate) const ANTHROPIC_BETA_HEADER: &str = "oauth-2025-04-20";

/// Runs a single Anthropic usage poller tick.
///
/// Exposed `pub(crate)` for tests.
pub(crate) async fn tick(
    base_dir: &std::path::Path,
    http_get: &HttpGetWithRetryAfterFn,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
) {
    tick_filtered(base_dir, http_get, cooldowns, backoffs, None).await;
}

/// Targeted re-poll of ONE slot, used by the rebind wake path
/// (login-followup LOW-6). It runs the exact same per-account body as
/// [`tick`] — including the cooldown check, so a wake NEVER overrides an
/// active 429/failure cooldown — but touches no other slot.
pub(crate) async fn tick_slot(
    base_dir: &std::path::Path,
    http_get: &HttpGetWithRetryAfterFn,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    slot: u16,
) {
    tick_filtered(base_dir, http_get, cooldowns, backoffs, Some(slot)).await;
}

async fn tick_filtered(
    base_dir: &std::path::Path,
    http_get: &HttpGetWithRetryAfterFn,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    only_slot: Option<u16>,
) {
    debug!("usage poller tick starting");

    let mut accounts = discovery::discover_anthropic(base_dir);
    if let Some(slot) = only_slot {
        accounts.retain(|a| a.id == slot);
    }
    if accounts.len() > MAX_ACCOUNTS_PER_TICK {
        accounts.truncate(MAX_ACCOUNTS_PER_TICK);
    }

    let mut polled = 0usize;
    let mut skipped = 0usize;

    for info in accounts {
        if info.source != AccountSource::Anthropic || !info.has_credentials {
            continue;
        }

        let account = match AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => {
                // Discovery walks `config-*` directory names and parses the
                // suffix as a bare u16 (no AccountNum bound applied at that
                // layer) — a stray directory outside 1..=999 reaches here.
                // No `poller_health` row is written for it: every other
                // surface that could read one back (csq doctor, csq probe,
                // csq status) already refuses this same slot id via its own
                // `AccountNum::try_from`, so a health row here would be an
                // orphan no diagnostic can ever address by slot number.
                warn!(
                    slot = info.id,
                    error_kind = "anthropic_poller_invalid_slot",
                    "usage poller: discovered slot id is not a valid account \
                     number (1..=999); skipping"
                );
                continue;
            }
        };

        let origin = crate::quota::origin::capture(base_dir, account);
        if origin.stamp().is_none() {
            // Unreadable/foreign metadata is not an unbound legacy identity.
            warn!(
                account = account.get(),
                error_kind = "anthropic_poller_identity_authority_refused",
                "usage poller retained quota after unreadable identity custody"
            );
            continue;
        }
        if matches!(origin, crate::quota::origin::SlotOrigin::Known(_)) {
            let previous_origin = quota_state::load_state_or_skip(base_dir)
                .ok()
                .and_then(|q| q.get_health(account.get()).and_then(|h| h.origin));
            if previous_origin != origin.stamp() {
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
            }
        }

        // Cooldown check
        if in_cooldown(cooldowns, info.id) {
            skipped += 1;
            let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
            if let Err(e) = record_poll_failure_guarded(
                base_dir,
                account,
                origin,
                PollOutcome::SkippedCooldown,
                cooldown_until,
            ) {
                warn!(
                    account = info.id,
                    error_kind = "quota_health_write_failed",
                    reason = %crate::error::redact_tokens(&e.to_string()),
                    "usage poller: failed to persist poller health"
                );
            }
            continue;
        }

        // Read access token from canonical credential file.
        //
        // M4-4: route through identity-keyed credentials when
        // `profiles.json::by_slot` has a UUID for this slot. Slot-id
        // channel: per-slot poller state (channel (a) per
        // `account-terminal-separation.md` MUST Rule 1 — the poller's
        // own loop already knows which slot it is polling). UUID
        // resolution does NOT introduce a new slot-id channel — it
        // reads `by_slot[slot]` keyed on the slot-id we already have.
        // Legacy fallback to `credentials/<N>.json` only when no UUID
        // mapping exists; the M3-7/M4-5 gate guarantees identity
        // credentials are seeded in production once `by_slot` is
        // populated.
        let slot_uuid = crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get());
        let canonical = match slot_uuid {
            Some(uuid) => crate::accounts::identity_store::credentials_path_for(base_dir, uuid),
            None => cred_file::canonical_path(base_dir, account),
        };
        // ROOT ruling A (reader parity): adopt a pending post-commit rescue
        // record BEFORE concluding anything about credential absence. A
        // rescued pair is a durable credential the canonical file may not
        // hold yet (the refresh that rotated it lost the commit lock race).
        let creds = match read_canonical_with_rescue(base_dir, slot_uuid, &canonical) {
            PollerCredentialRead::Loaded(creds) => creds,
            PollerCredentialRead::RescuePending(error) => {
                // NOT `SkippedNoCredentials`: the slot is not credential-less.
                // The record stays pending and the next tick retries adoption,
                // so no cooldown and no failure row are recorded for a state
                // that heals itself. A fixed-vocabulary WARN keeps the wait
                // visible to the operator without claiming the slot is empty.
                warn!(
                    account = info.id,
                    error_kind = "anthropic_poller_rescue_pending",
                    reason = %crate::error::redact_tokens(&error.to_string()),
                    "usage poller: a rescued credential is pending adoption; \
                     skipping this tick without recording no-credentials"
                );
                skipped += 1;
                continue;
            }
            PollerCredentialRead::Unreadable(e) => {
                warn!(
                    account = info.id,
                    error_kind = "anthropic_poller_credentials_unreadable",
                    reason = %crate::error::redact_tokens(&e.to_string()),
                    "usage poller: could not load this slot's credentials; skipping"
                );
                // No cooldown to record: there is nothing to "wait out"
                // here (unlike a 401/429/timeout, which back off a live
                // upstream response). The daemon simply retries next tick
                // on the chance credentials appear (e.g. mid-login).
                if let Err(e) = record_poll_failure_guarded(
                    base_dir,
                    account,
                    origin,
                    PollOutcome::SkippedNoCredentials,
                    None,
                ) {
                    warn!(
                        account = info.id,
                        error_kind = "quota_health_write_failed",
                        reason = %crate::error::redact_tokens(&e.to_string()),
                        "usage poller: failed to persist poller health"
                    );
                }
                continue;
            }
        };
        if crate::quota::origin::capture(base_dir, account) != origin {
            continue;
        }
        // Short-lived heap String passed into spawn_blocking; dropped
        // when the blocking task completes. Never logged or stored in
        // long-lived collections. Acceptable per security.md rule 8.
        let token = creds
            .expect_anthropic()
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .to_string();

        // Poll usage in spawn_blocking with a timeout to prevent
        // the 2026-04-12 hang where a stuck HTTP call blocked the
        // entire poller indefinitely.
        let http = Arc::clone(http_get);
        let join_handle = tokio::task::spawn_blocking(move || poll_anthropic_usage(&token, &http));
        let poll_result = tokio::time::timeout(CALL_TIMEOUT, join_handle).await;

        if crate::quota::origin::capture(base_dir, account) != origin {
            clear_cooldown(cooldowns, info.id);
            clear_backoff(backoffs, info.id);
            continue;
        }

        // Flatten: timeout → join → poll result
        let poll_result = match poll_result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                // A TIMEOUT escalates the backoff exactly like an explicit 429.
                // A hung call and a server that has stopped answering
                // promptly under load are indistinguishable at this layer —
                // both present as "no response within CALL_TIMEOUT" — so
                // treating a timeout as strictly less serious than an
                // explicit 429 would mean the ONE failure mode most likely
                // to recur quickly is the one that backs off the least.
                //
                // The daemon's own log recorded 330 429s against this
                // account as of 2026-09-06 (grep of this host's log, not an
                // inference); a live unauthenticated probe against
                // `/api/oauth/usage` on 2026-09-10 separately returned `429`
                // with `retry-after: 2912`, but that probe carried no
                // credential, so it establishes nothing about how the
                // AUTHENTICATED poller path is treated — no throttle claim
                // follows from it (`instrument-discipline.md` MUST-1). What
                // is engineering-sound regardless of either number: with the
                // plain `set_cooldown` this arm used before this fix, a
                // repeated timeout retried on a flat 600s clock no matter
                // how many times it had already failed, exactly the same gap
                // the 429 arm below had.
                //
                // Over-backing-off on a genuine transient blip costs at most one
                // stale poll interval and self-corrects: the success arm calls
                // `clear_backoff`, so a single good poll resets the factor to 1.
                warn!(account = info.id, "usage poller: call timed out after 30s");
                increase_backoff(backoffs, info.id);
                set_cooldown_with_backoff(cooldowns, backoffs, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                if let Err(e) = record_poll_failure_guarded(
                    base_dir,
                    account,
                    origin,
                    PollOutcome::Timeout,
                    cooldown_until,
                ) {
                    warn!(
                        account = info.id,
                        error_kind = "quota_health_write_failed",
                        reason = %crate::error::redact_tokens(&e.to_string()),
                        "usage poller: failed to persist poller health"
                    );
                }
                continue;
            }
        };

        match poll_result {
            Ok(Ok(usage)) => {
                // Write to quota file
                let base = base_dir.to_path_buf();
                if let Err(e) = write_usage_to_quota_guarded(&base, account, &usage, origin) {
                    warn!(account = info.id, "usage poller: failed to write quota");
                    let _ = e;
                }
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
                polled += 1;
            }
            Ok(Err((PollError::RateLimited, retry_after))) => {
                // `retry_after` is `Some(n)` only when the response carried a
                // digits-only `retry-after` header (validated in the Node
                // script that emitted it — see
                // `http::get_bearer_node_with_retry_after`'s doc); anything
                // else, including no header at all, normalises to `None`
                // upstream and is handled identically to "absent" by
                // `set_cooldown_with_backoff_and_retry_after` below (it takes
                // the max of the backoff-scaled wait and the server's wait,
                // so an absent/unparseable/shorter server value never
                // shortens the existing backoff).
                warn!(
                    account = info.id,
                    retry_after_secs = retry_after,
                    "usage poller: 429 rate limited"
                );
                increase_backoff(backoffs, info.id);
                set_cooldown_with_backoff_and_retry_after(
                    cooldowns,
                    backoffs,
                    info.id,
                    retry_after,
                );
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::RateLimited,
                    cooldown_until,
                );
            }
            Ok(Err((PollError::Unauthorized, _))) => {
                warn!(account = info.id, "usage poller: 401 unauthorized");
                set_cooldown(cooldowns, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::Unauthorized,
                    cooldown_until,
                );
            }
            Ok(Err((PollError::Transport(_), _))) => {
                // Raised from `debug!` to `warn!` (2026-09-12): this arm
                // previously produced ZERO log output, which is how a
                // slot polling a genuinely dead endpoint went silent for
                // 70+ minutes with nothing in the daemon log to show it —
                // the daemon only emits WARN and above. Throttled to
                // "first occurrence, then on change of outcome" via
                // `record_poll_failure`'s returned `changed` flag, so a
                // sustained outage logs once per state transition rather
                // than once every 5-minute tick for its whole duration.
                set_cooldown(cooldowns, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                if record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::Transport,
                    cooldown_until,
                ) {
                    warn!(
                        account = info.id,
                        error_kind = "anthropic_poll_transport_error",
                        "usage poller: transport error — will not repeat this WARN \
                         every tick while the failure persists unchanged"
                    );
                } else {
                    debug!(account = info.id, "usage poller: transport error (repeat)");
                }
            }
            Ok(Err((PollError::BadUrl(_), _))) => {
                // Reachable for TWO distinct reasons (round-2 redteam
                // R6-rust corrected this comment — it previously claimed
                // "unreachable in practice"): (1) this poller's own URL is
                // the fixed `ANTHROPIC_BASE_URL` constant, so the outbound
                // char/https/userinfo/unparseable guards can never reject
                // it — that half of the original reasoning still holds;
                // but (2) the TOKEN guard (`ERR_TOKEN_UNSAFE_CHARS`) and
                // the process-wide `ERR_NO_JS_RUNTIME` /
                // `ERR_ENCODE_FAILED` pre-flight failures check the
                // credential and the runtime environment, NOT the URL —
                // now that this call site routes through
                // `classify_transport_error`, a corrupted stored access
                // token trips this arm too. WARN is correct for both: a
                // malformed fixed URL means the constant itself somehow
                // became corrupted; a malformed token means the account's
                // stored credential needs re-login — neither is a
                // transient network blip.
                warn!(
                    account = info.id,
                    error_kind = "anthropic_poll_bad_url",
                    "usage poller: outbound url or token rejected pre-flight — check the account's stored credentials"
                );
                set_cooldown(cooldowns, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::Transport,
                    cooldown_until,
                );
            }
            Ok(Err((PollError::Parse(_), _))) => {
                // Raised from `debug!` to `warn!` (2026-09-12) — same
                // rationale and same first-occurrence throttle as the
                // `Transport` arm above.
                set_cooldown(cooldowns, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                if record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::Parse,
                    cooldown_until,
                ) {
                    warn!(
                        account = info.id,
                        error_kind = "anthropic_poll_parse_error",
                        "usage poller: response body did not parse as the expected \
                         usage JSON shape — will not repeat this WARN every tick \
                         while the failure persists unchanged"
                    );
                } else {
                    debug!(account = info.id, "usage poller: parse error (repeat)");
                }
            }
            Ok(Err((PollError::HttpError(status), _))) => {
                // Raised from `debug!` to `warn!` (2026-09-12) — includes
                // every 5xx and any other unexpected status (429/401 are
                // handled by their own arms above). Same throttle.
                set_cooldown(cooldowns, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                if record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::ServerError,
                    cooldown_until,
                ) {
                    warn!(
                        account = info.id,
                        status,
                        error_kind = "anthropic_poll_http_error",
                        "usage poller: non-200 response — will not repeat this WARN \
                         every tick while the failure persists unchanged"
                    );
                } else {
                    debug!(
                        account = info.id,
                        status, "usage poller: non-200 response (repeat)"
                    );
                }
            }
            Err(_join_err) => {
                warn!(account = info.id, "usage poller: task panicked");
                set_cooldown(cooldowns, info.id);
                let cooldown_until = cooldown_remaining_epoch(cooldowns, info.id);
                record_and_warn_on_write_failure(
                    base_dir,
                    account,
                    origin,
                    info.id,
                    PollOutcome::Panic,
                    cooldown_until,
                );
            }
        }
    }

    debug!(polled, skipped, "usage poller tick complete");
}

/// Outcome of reading a slot's canonical credential for one poller tick,
/// after a pending post-commit rescue record has had its chance.
#[derive(Debug)]
enum PollerCredentialRead {
    /// The canonical credential is readable (possibly just adopted).
    /// Boxed: `CredentialFile` dwarfs the two error variants
    /// (`clippy::large_enum_variant`), and this value is moved straight into
    /// the poll body either way.
    Loaded(Box<credentials::CredentialFile>),
    /// The canonical is unreadable AND a rescue record is still PENDING: the
    /// slot is NOT credential-less, so `SkippedNoCredentials` would be a
    /// false verdict. The next tick retries adoption.
    RescuePending(crate::error::CredentialError),
    /// No usable credential and no rescue record — genuine absence.
    Unreadable(crate::error::CredentialError),
}

/// Reads `uuid`'s canonical credential, adopting a pending post-commit
/// rescue record first.
///
/// Mirrors `refresh/check.rs`'s `adopt_pending_rescue`: one record read on
/// the normal path; the commit lock is taken only when a record actually
/// exists. A refused adoption (live holder, unparseable record) is logged
/// and left PENDING, and the read then classifies as
/// [`PollerCredentialRead::RescuePending`] rather than a false "no
/// credentials" (`guard-reader-writer-parity.md`: the reader must recognise
/// the rescued form the writer produced).
///
/// Rescue records are UUID-keyed and live inside `identities/<uuid>/`, so
/// the legacy (no `by_slot` mapping) path structurally cannot have one.
fn read_canonical_with_rescue(
    base_dir: &std::path::Path,
    uuid: Option<crate::accounts::identity_store::IdentityId>,
    canonical: &std::path::Path,
) -> PollerCredentialRead {
    let identity_dir = uuid.and_then(|uuid| {
        crate::accounts::identity_store::credentials_path_for(base_dir, uuid)
            .parent()
            .map(std::path::Path::to_path_buf)
    });
    if let (Some(uuid), Some(identity_dir)) = (uuid, identity_dir.as_deref()) {
        if crate::credentials::rescue::rescue_record_pending(identity_dir).is_some() {
            // D237 round-2 security L3: the poller runs on the async runtime
            // and is not the tick that must land a rotated pair; a 30 s
            // canonical wait here would stall the poller and every sibling
            // task. Adopt with a NON-BLOCKING attempt and keep the record
            // PENDING on refusal (the refresher tick adopts with the full
            // commit budget).
            match crate::credentials::rescue::adopt_rescue_record_nonblocking(
                base_dir,
                &uuid.to_string(),
            ) {
                Ok(_) => {}
                Err(error) => warn!(
                    error_kind = "rescue_adopt_refused",
                    reason = error.error_kind_tag(),
                    "usage poller: pending rescue record could not be adopted; left pending"
                ),
            }
        }
    }
    match credentials::load(canonical) {
        Ok(creds) => PollerCredentialRead::Loaded(Box::new(creds)),
        Err(error) => {
            let still_pending = identity_dir.as_deref().is_some_and(|identity_dir| {
                crate::credentials::rescue::rescue_record_pending(identity_dir).is_some()
            });
            if still_pending {
                PollerCredentialRead::RescuePending(error)
            } else {
                PollerCredentialRead::Unreadable(error)
            }
        }
    }
}

/// Parsed usage data from `/api/oauth/usage`.
#[derive(Debug, Clone)]
pub(crate) struct UsageData {
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
}

/// Polls `/api/oauth/usage` for one Anthropic account.
///
/// Returns the classified [`PollError`] paired with the parsed
/// `retry-after` value as a `(PollError, Option<u64>)` tuple, rather than
/// widening [`PollError::RateLimited`] itself to carry the field: that
/// variant is constructed at 9+ other poller call sites (grok, kimi,
/// minimax, zai, deepseek, third_party, codex) that have no use for it
/// and would each need an unrelated update for a payload only this
/// module's caller reads. `retry_after` is `Some` only on the
/// `RateLimited` arm below (the one case the server's header is
/// meaningful for) and `None` on every other arm — including success,
/// where there is no error to pair it with.
pub(crate) fn poll_anthropic_usage(
    token: &str,
    http_get: &HttpGetWithRetryAfterFn,
) -> Result<UsageData, (PollError, Option<u64>)> {
    let url = format!("{ANTHROPIC_BASE_URL}/api/oauth/usage");
    let extra_headers = [("Anthropic-Beta", ANTHROPIC_BETA_HEADER)];

    let (status, retry_after, body) =
        http_get(&url, token, &extra_headers).map_err(|e| (classify_transport_error(e), None))?;

    match status {
        200 => {}
        429 => return Err((PollError::RateLimited, retry_after)),
        401 => return Err((PollError::Unauthorized, None)),
        other => return Err((PollError::HttpError(other), None)),
    }

    parse_usage_response(&body).map_err(|e| (e, None))
}

/// Parses the `/api/oauth/usage` JSON response into `UsageData`.
///
/// Handles the mapping from the API shape:
///   `{ "utilization": 0.42, "resets_at": "2099-01-01T00:00:00Z" }`
/// to the internal `UsageWindow`:
///   `{ used_percentage: 42.0, resets_at: epoch_u64 }`
pub(crate) fn parse_usage_response(body: &[u8]) -> Result<UsageData, PollError> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| PollError::Parse(e.to_string()))?;

    Ok(UsageData {
        five_hour: parse_window(&json, "five_hour"),
        seven_day: parse_window(&json, "seven_day"),
    })
}

fn parse_window(json: &serde_json::Value, key: &str) -> Option<UsageWindow> {
    let window = json.get(key)?;

    // `utilization` is already 0.0–100.0 (percentage).
    // Anthropic's `/api/oauth/usage` returns e.g. `58.0` for 58%.
    let used_percentage = window.get("utilization")?.as_f64()?;

    // `resets_at` is ISO-8601 string. Parse to epoch seconds.
    let resets_str = window.get("resets_at")?.as_str()?;
    let resets_at = parse_iso8601_to_epoch(resets_str)?;

    Some(UsageWindow {
        used_percentage,
        resets_at,
    })
}

/// Minimal RFC 3339 parser: `YYYY-MM-DDTHH:MM:SS` + timezone → epoch
/// seconds.
///
/// Accepts a trailing `Z` (UTC) or a numeric `±HH:MM` offset. The
/// Anthropic usage API always returns UTC (`Z`/`+00:00`); the Kimi
/// usages API is China-based, so a `+08:00` contract drift must not
/// make BOTH windows unparseable → perpetual cooldown (redteam R1).
/// No `chrono` or `time` dependency needed.
pub(crate) fn parse_iso8601_to_epoch(s: &str) -> Option<u64> {
    // RFC 3339 timestamps are pure ASCII. Reject anything else up front
    // so the fixed-offset slicing below can never land on a non-char
    // boundary — a 19-byte input containing a multi-byte char panicked
    // the byte-slicing parser (redteam R1 sec-NIT-1).
    if !s.is_ascii() {
        return None;
    }

    // Split the timezone designator: trailing `Z`, or `±HH:MM`.
    let (s, offset_secs): (&str, i64) = if let Some(r) = s.strip_suffix('Z') {
        (r, 0)
    } else if s.len() >= 6 {
        let (body, tz) = s.split_at(s.len() - 6);
        let tz_bytes = tz.as_bytes();
        let sign: i64 = match tz_bytes[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        if tz_bytes[3] != b':' {
            return None;
        }
        // RFC 3339 time-numoffset is `±2DIGIT:2DIGIT` — Rust's i64
        // FromStr accepts a sign, so "+-8:00" would otherwise parse as
        // −08:00 (a silently INVERTED offset) and "++8:00" as +08:00.
        // Fail closed on any non-digit (R4 NIT).
        if !tz_bytes[1].is_ascii_digit()
            || !tz_bytes[2].is_ascii_digit()
            || !tz_bytes[4].is_ascii_digit()
            || !tz_bytes[5].is_ascii_digit()
        {
            return None;
        }
        let off_hour: i64 = tz[1..3].parse().ok()?;
        let off_min: i64 = tz[4..6].parse().ok()?;
        if off_hour > 23 || off_min > 59 {
            return None;
        }
        (body, sign * (off_hour * 3600 + off_min * 60))
    } else {
        return None;
    };

    // Accept both "YYYY-MM-DDTHH:MM:SS" and "YYYY-MM-DDTHH:MM:SS.fff"
    let s = match s.find('.') {
        Some(dot) => &s[..dot],
        None => s,
    };

    // Parse YYYY-MM-DDTHH:MM:SS
    if s.len() != 19 {
        return None;
    }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let minute: u64 = s[14..16].parse().ok()?;
    let second: u64 = s[17..19].parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // `365 * (year - 1970)` below would underflow u64 for a pre-epoch
    // year — reject it rather than panic (same containment class as
    // the ASCII guard above; the parser runs inside spawn_blocking,
    // but a panic there still costs a cooldown cycle).
    if year < 1970 {
        return None;
    }

    // Days before each month (non-leap).
    const MONTH_DAYS: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    let mut days = 365 * (year - 1970);
    // Leap years between 1970 and year-1.
    if year > 1970 {
        days += (year - 1969) / 4;
        days -= (year - 1901) / 100;
        days += (year - 1601) / 400;
    }
    days += MONTH_DAYS[(month - 1) as usize];
    // Add leap day if after Feb in a leap year.
    if month > 2 && is_leap_year(year) {
        days += 1;
    }
    days += day - 1;

    let naive = days * 86400 + hour * 3600 + minute * 60 + second;
    // RFC 3339: local = UTC + offset → UTC = local − offset. Clamp at
    // 0: a pre-1970 local time at a positive offset has no u64 epoch.
    let epoch = (naive as i64 - offset_secs).max(0);
    Some(epoch as u64)
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Writes parsed usage data into the local `quota.json`.
///
/// Acquires `quota.json.lock` for mutual exclusion with any other
/// writer (see RT finding #1 — consistency with `state::update_quota`).
pub(crate) fn write_usage_to_quota_guarded(
    base_dir: &std::path::Path,
    account: AccountNum,
    usage: &UsageData,
    origin: crate::quota::origin::SlotOrigin,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    if origin.stamp().is_none() || crate::quota::origin::capture(base_dir, account) != origin {
        return Ok(());
    }
    // MED-1 (an internal ticket redteam): load_state_or_skip fails closed instead of
    // falling back to QuotaFile::empty() — a load failure here must SKIP
    // the write, not persist a one-row file that wipes every sibling
    // account's row (mirrors usage_poller::gemini_oauth::write_quota).
    let mut quota = match quota_state::load_state_or_skip(base_dir) {
        Ok(qf) => qf,
        Err(e) => {
            warn!(
                account = account.get(),
                error_kind = "quota_load_failed",
                reason = %crate::error::redact_tokens(&e.to_string()),
                "usage poller: quota.json unreadable, skipping write to avoid clobbering sibling rows"
            );
            return Ok(());
        }
    };

    let now = now_epoch();

    quota.set(
        account.get(),
        AccountQuota {
            five_hour: usage.five_hour.clone(),
            seven_day: usage.seven_day.clone(),
            updated_at: now,
            extras: Some(serde_json::json!({"csq_anthropic_origin": origin.stamp()})),
            ..Default::default()
        },
    );

    // Health is written in the SAME `save_state` call as the quota row
    // above (see `PollerHealth`'s doc) — a success can never leave a
    // stale failure record behind, and a failure can never be
    // misread against a since-refreshed quota row, because there is
    // exactly one load-mutate-save cycle per tick per slot.
    quota.set_health(
        account.get(),
        PollerHealth {
            origin: origin.stamp(),
            last_attempt_at: now,
            last_outcome: PollOutcome::Ok,
            consecutive_failures: 0,
            cooldown_until: None,
            next_retry_at: None,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account.get(), "usage poller: quota file updated");
    Ok(())
}

/// Current wall-clock time as epoch seconds, `0.0` on a clock error
/// (mirrors the existing tolerance in [`write_usage_to_quota_guarded`] and
/// [`AccountQuota::updated_at`]'s "never polled" sentinel).
fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Translates a slot's in-memory, monotonic-clock cooldown deadline into
/// a wall-clock epoch for persistence. `Instant` carries no epoch of its
/// own, so this is `now_epoch() + remaining_wait`, read from the SAME
/// cooldown map `tick`'s in-memory gating already consults — never a
/// second, independent computation of the wait duration.
fn cooldown_remaining_epoch(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    account: u16,
) -> Option<f64> {
    super::cooldown_remaining(cooldowns, account)
        .map(|remaining| now_epoch() + remaining.as_secs_f64())
}

/// Persists a non-success poll outcome for `account`, merging it into
/// `quota.json`'s `poller_health` map under the SAME lock and
/// [`quota_state::save_state`] call pattern as [`write_usage_to_quota_guarded`]'s
/// success path — never a second lock acquisition for the same tick.
///
/// Returns `Ok(true)` when `outcome` differs from the slot's previously
/// recorded outcome (including "no previous record" — first occurrence).
/// Callers use this to throttle a WARN to "first occurrence, then on
/// change of outcome" instead of firing on every tick a sustained outage
/// persists (see `tick`'s Transport/Parse/HttpError arms). A caller that
/// does not need the throttle (e.g. an outcome that already warns
/// unconditionally) may ignore the return value.
///
/// `PollOutcome::SkippedCooldown` carries `consecutive_failures` forward
/// unchanged rather than incrementing it — see that variant's doc.
/// Every other outcome (including `SkippedNoCredentials`, which is a
/// genuine failed attempt to reach a usable credential) increments it.
fn record_poll_failure_guarded(
    base_dir: &std::path::Path,
    account: AccountNum,
    origin: crate::quota::origin::SlotOrigin,
    outcome: PollOutcome,
    cooldown_until: Option<f64>,
) -> Result<bool, crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    if origin.stamp().is_none() || crate::quota::origin::capture(base_dir, account) != origin {
        return Ok(false);
    }

    let mut quota = match quota_state::load_state_or_skip(base_dir) {
        Ok(qf) => qf,
        Err(e) => {
            warn!(
                account = account.get(),
                error_kind = "quota_load_failed",
                reason = %crate::error::redact_tokens(&e.to_string()),
                "usage poller: quota.json unreadable, skipping poller-health \
                 write to avoid clobbering sibling rows"
            );
            return Ok(false);
        }
    };

    let previous = quota
        .get_health(account.get())
        .copied()
        .filter(|health| health.origin == origin.stamp());
    let changed = previous.map(|h| h.last_outcome != outcome).unwrap_or(true);
    let consecutive_failures = match outcome {
        PollOutcome::SkippedCooldown => previous.map(|h| h.consecutive_failures).unwrap_or(0),
        _ => previous
            .map(|h| h.consecutive_failures)
            .unwrap_or(0)
            .saturating_add(1),
    };

    quota.set_health(
        account.get(),
        PollerHealth {
            origin: origin.stamp(),
            last_attempt_at: now_epoch(),
            last_outcome: outcome,
            consecutive_failures,
            cooldown_until,
            next_retry_at: cooldown_until,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    Ok(changed)
}

/// Convenience wrapper around [`record_poll_failure_guarded`] for `tick`'s match
/// arms: logs (at `warn!`) if the health write itself fails, and returns
/// the `changed` flag (`false` on write failure, so a throttled caller
/// never suppresses its own WARN because persistence broke). Named
/// `info_id` rather than reusing `account.get()` at call sites purely to
/// match `tick`'s existing `info.id` log-field convention.
fn record_and_warn_on_write_failure(
    base_dir: &std::path::Path,
    account: AccountNum,
    origin: crate::quota::origin::SlotOrigin,
    info_id: u16,
    outcome: PollOutcome,
    cooldown_until: Option<f64>,
) -> bool {
    match record_poll_failure_guarded(base_dir, account, origin, outcome, cooldown_until) {
        Ok(changed) => changed,
        Err(e) => {
            warn!(
                account = info_id,
                error_kind = "quota_health_write_failed",
                reason = %crate::error::redact_tokens(&e.to_string()),
                "usage poller: failed to persist poller health"
            );
            false
        }
    }
}

#[cfg(test)]
fn write_usage_to_quota(
    base: &std::path::Path,
    account: AccountNum,
    usage: &UsageData,
) -> Result<(), crate::error::CsqError> {
    write_usage_to_quota_guarded(
        base,
        account,
        usage,
        crate::quota::origin::capture(base, account),
    )
}
#[cfg(test)]
fn record_poll_failure(
    base: &std::path::Path,
    account: AccountNum,
    outcome: PollOutcome,
    cooldown: Option<f64>,
) -> Result<bool, crate::error::CsqError> {
    record_poll_failure_guarded(
        base,
        account,
        crate::quota::origin::capture(base, account),
        outcome,
        cooldown,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        self, file as cred_file, AnthropicCredentialFile, CredentialFile, OAuthPayload,
    };
    use crate::quota::state as quota_state;
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn install_account(base: &std::path::Path, account: u16) {
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-test-token".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-test-refresh".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&cred_file::canonical_path(base, num), &creds).unwrap();
    }

    fn install_known_account(
        base: &std::path::Path,
        slot: u16,
        id: u128,
        org: u128,
        generation: u64,
    ) {
        let identity = uuid::Uuid::from_u128(id).into();
        crate::quota::origin::fixtures::known(
            base,
            slot,
            identity,
            uuid::Uuid::from_u128(org),
            generation,
        );
        install_account(base, slot);
        let legacy = credentials::load(&cred_file::canonical_path(
            base,
            AccountNum::try_from(slot).unwrap(),
        ))
        .unwrap();
        credentials::save(
            &crate::accounts::identity_store::credentials_path_for(base, identity),
            &legacy,
        )
        .unwrap();
        let config = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&config).unwrap();
        crate::accounts::markers::write_csq_account(&config, identity).unwrap();
    }

    #[tokio::test]
    async fn org_rebind_during_http_does_not_publish_foreign_usage_or_health() {
        let dir = TempDir::new().unwrap();
        install_known_account(dir.path(), 4, 41, 51, 1);
        let initial = quota_state::load_state_or_skip(dir.path()).unwrap();
        quota_state::save_state(dir.path(), &initial).unwrap();
        let before = std::fs::read(quota_state::quota_path(dir.path())).unwrap();
        let base = dir.path().to_path_buf();
        let http: HttpGetWithRetryAfterFn = Arc::new(move |_, _, _| {
            install_known_account(&base, 4, 42, 52, 2);
            Ok((
                200,
                None,
                br#"{"five_hour":{"utilization":42,"resets_at":"2099-01-01T00:00:00Z"}}"#.to_vec(),
            ))
        });
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));
        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(
            std::fs::read(quota_state::quota_path(dir.path())).unwrap(),
            before
        );
        assert!(quota_state::load_state(dir.path())
            .unwrap()
            .get(4)
            .is_none());
    }

    #[test]
    fn new_org_failed_attempt_does_not_relabel_old_successful_usage() {
        let dir = TempDir::new().unwrap();
        install_known_account(dir.path(), 4, 41, 51, 1);
        let account = AccountNum::try_from(4).unwrap();
        let first = crate::quota::origin::capture(dir.path(), account);
        let usage = UsageData {
            five_hour: Some(UsageWindow {
                used_percentage: 42.0,
                resets_at: 4_102_444_800,
            }),
            seven_day: None,
        };
        write_usage_to_quota_guarded(dir.path(), account, &usage, first).unwrap();
        let old = quota_state::load_state_or_skip(dir.path())
            .unwrap()
            .get(4)
            .unwrap()
            .clone();
        install_known_account(dir.path(), 4, 42, 52, 2);
        let second = crate::quota::origin::capture(dir.path(), account);
        record_poll_failure_guarded(dir.path(), account, second, PollOutcome::Transport, None)
            .unwrap();
        let raw = quota_state::load_state_or_skip(dir.path()).unwrap();
        assert_eq!(raw.get(4), Some(&old));
        assert_eq!(raw.get_health(4).unwrap().origin, second.stamp());
        let visible = quota_state::load_state(dir.path()).unwrap();
        assert!(visible.get(4).is_none());
        assert!(visible.get_health(4).is_some());
    }

    fn mock_usage_success(counter: Arc<AtomicU32>) -> HttpGetWithRetryAfterFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            // Anthropic returns utilization as 0-100 percentage directly
            let body = br#"{
                "five_hour": { "utilization": 42.0, "resets_at": "2099-01-01T00:00:00Z" },
                "seven_day": { "utilization": 15.0, "resets_at": "2099-01-14T00:00:00Z" }
            }"#;
            Ok((200, None, body.to_vec()))
        })
    }

    /// 429 with no `retry-after` header — the "server didn't say" case.
    fn mock_usage_429(counter: Arc<AtomicU32>) -> HttpGetWithRetryAfterFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((429, None, b"rate limited".to_vec()))
        })
    }

    /// 429 carrying a `retry-after` value, for the honoring tests below.
    fn mock_usage_429_with_retry_after(
        counter: Arc<AtomicU32>,
        retry_after_secs: u64,
    ) -> HttpGetWithRetryAfterFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((429, Some(retry_after_secs), b"rate limited".to_vec()))
        })
    }

    fn mock_usage_401(counter: Arc<AtomicU32>) -> HttpGetWithRetryAfterFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((401, None, b"unauthorized".to_vec()))
        })
    }

    /// A socket/DNS-level failure — `classify_transport_error` buckets any
    /// string that is not one of the shared `crate::http::ERR_*` pre-flight
    /// constants as `PollError::Transport`.
    fn mock_usage_transport_error(counter: Arc<AtomicU32>) -> HttpGetWithRetryAfterFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Err("connection refused".to_string())
        })
    }

    // ─── parse_usage_response tests ──────────────────────────

    #[test]
    fn parse_full_response() {
        // Anthropic returns utilization as 0-100 percentage directly
        let body = br#"{
            "five_hour": { "utilization": 42.0, "resets_at": "2026-04-10T20:00:00Z" },
            "seven_day": { "utilization": 15.0, "resets_at": "2026-04-17T00:00:00Z" }
        }"#;
        let data = parse_usage_response(body).unwrap();

        let fh = data.five_hour.unwrap();
        assert!((fh.used_percentage - 42.0).abs() < 0.01);
        assert!(fh.resets_at > 0);

        let sd = data.seven_day.unwrap();
        assert!((sd.used_percentage - 15.0).abs() < 0.01);
        assert!(sd.resets_at > 0);
    }

    #[test]
    fn parse_missing_seven_day() {
        let body = br#"{
            "five_hour": { "utilization": 0.85, "resets_at": "2026-04-10T20:00:00Z" }
        }"#;
        let data = parse_usage_response(body).unwrap();
        assert!(data.five_hour.is_some());
        assert!(data.seven_day.is_none());
    }

    #[test]
    fn parse_empty_response() {
        let body = b"{}";
        let data = parse_usage_response(body).unwrap();
        assert!(data.five_hour.is_none());
        assert!(data.seven_day.is_none());
    }

    #[test]
    fn parse_invalid_json() {
        let body = b"not json";
        let err = parse_usage_response(body);
        assert!(matches!(err, Err(PollError::Parse(_))));
    }

    #[test]
    fn parse_utilization_is_direct_percentage() {
        // Anthropic returns utilization as percentage (100.0 = 100%)
        let body = br#"{"five_hour":{"utilization":100.0,"resets_at":"2026-01-01T00:00:00Z"}}"#;
        let data = parse_usage_response(body).unwrap();
        assert!((data.five_hour.unwrap().used_percentage - 100.0).abs() < 0.01);
    }

    // ─── ISO-8601 parser tests ───────────────────────────────

    #[test]
    fn iso8601_basic_utc() {
        let epoch = parse_iso8601_to_epoch("2026-04-10T15:30:00Z").unwrap();
        // 2026-04-10T15:30:00Z should be a reasonable epoch value.
        assert!(epoch > 1_700_000_000);
        assert!(epoch < 2_000_000_000);
    }

    #[test]
    fn iso8601_with_plus_zero_offset() {
        let a = parse_iso8601_to_epoch("2026-04-10T15:30:00Z").unwrap();
        let b = parse_iso8601_to_epoch("2026-04-10T15:30:00+00:00").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn iso8601_with_fractional_seconds() {
        let a = parse_iso8601_to_epoch("2026-04-10T15:30:00Z").unwrap();
        let b = parse_iso8601_to_epoch("2026-04-10T15:30:00.123Z").unwrap();
        assert_eq!(a, b); // fractional seconds are truncated
    }

    #[test]
    fn iso8601_unix_epoch() {
        let epoch = parse_iso8601_to_epoch("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(epoch, 0);
    }

    #[test]
    fn iso8601_known_date() {
        // 2000-01-01T00:00:00Z = 946684800
        let epoch = parse_iso8601_to_epoch("2000-01-01T00:00:00Z").unwrap();
        assert_eq!(epoch, 946684800);
    }

    #[test]
    fn iso8601_leap_year() {
        // 2024-03-01T00:00:00Z (2024 is a leap year)
        let epoch = parse_iso8601_to_epoch("2024-03-01T00:00:00Z").unwrap();
        // Jan (31) + Feb (29 in 2024) = 60 days into 2024.
        // 2024-01-01 = 1704067200. 60 * 86400 = 5184000. → 1709251200
        assert_eq!(epoch, 1709251200);
    }

    #[test]
    fn iso8601_applies_positive_numeric_offset() {
        // 2000-01-01T08:00:00 at +08:00 == 2000-01-01T00:00:00Z.
        let epoch = parse_iso8601_to_epoch("2000-01-01T08:00:00+08:00").unwrap();
        assert_eq!(epoch, 946684800);
        // 2000-01-01T00:00:00 at +05:30 == 946684800 − 19800.
        let epoch = parse_iso8601_to_epoch("2000-01-01T00:00:00+05:30").unwrap();
        assert_eq!(epoch, 946684800 - 19800);
    }

    #[test]
    fn iso8601_applies_negative_numeric_offset() {
        // 1999-12-31T19:00:00 at −05:00 == 2000-01-01T00:00:00Z.
        let epoch = parse_iso8601_to_epoch("1999-12-31T19:00:00-05:00").unwrap();
        assert_eq!(epoch, 946684800);
    }

    #[test]
    fn iso8601_rejects_invalid_offsets_and_missing_timezone() {
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+24:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+05:60").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+0500").is_none());
        // Malformed signs must fail closed, never invert (R4 NIT):
        // "+-8:00" would otherwise parse as −08:00.
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+-8:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00++8:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+0a:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+08:b0").is_none());
    }

    #[test]
    fn iso8601_multibyte_input_returns_none_not_panic() {
        // 19 bytes after the Z-strip but containing a multi-byte char —
        // the byte-slicing parser panicked on this shape (R1 sec-NIT-1).
        assert!(parse_iso8601_to_epoch("202é-01-01T00:00:0Z").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00±08:00").is_none());
    }

    #[test]
    fn iso8601_pre_epoch_year_rejected_not_underflow() {
        assert!(parse_iso8601_to_epoch("1960-01-01T00:00:00Z").is_none());
    }

    #[test]
    fn iso8601_positive_offset_past_epoch_clamps_to_zero() {
        // naive 1800 − offset 3600 would go negative; the contract is
        // clamp-to-zero (an instantly-expired window), never a wrap or
        // panic (R3 NIT — pin the chosen behavior).
        let epoch = parse_iso8601_to_epoch("1970-01-01T00:30:00+01:00").unwrap();
        assert_eq!(epoch, 0);
    }

    #[test]
    fn iso8601_fractional_seconds_with_numeric_offset() {
        // The tz split happens BEFORE the dot truncation, so a
        // fractional+offset timestamp (plausible China-region drift —
        // the case the offset arm was added for) parses correctly.
        let epoch = parse_iso8601_to_epoch("2000-01-01T08:00:00.841665+08:00").unwrap();
        assert_eq!(epoch, 946684800);
    }

    #[test]
    fn iso8601_rejects_garbage() {
        assert!(parse_iso8601_to_epoch("not a date").is_none());
    }

    // ─── tick integration tests ──────────────────────────────

    #[tokio::test]
    async fn tick_polls_and_writes_quota() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1, "exactly one HTTP GET");

        // Verify quota was written
        let quota = quota_state::load_state(dir.path()).unwrap();
        let q = quota.get(1).expect("account 1 should have quota");
        assert!((q.five_hour_pct() - 42.0).abs() < 0.01);
    }

    /// M4-4 AC: when `profiles.json::by_slot` is populated, the Anthropic
    /// usage poller reads the bearer token from
    /// `identities/<UUID>/credentials.json`. Validated by seeding the
    /// identity-keyed file with a distinctive token and the legacy path
    /// with a DIFFERENT token; the mock HTTP closure captures the token
    /// it was given and we assert it matches the identity-keyed value.
    #[tokio::test]
    async fn anthropic_usage_poller_reads_identity_credentials() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot: u16 = 1;

        // Seed `profiles.json::by_slot` so the poller routes UUID-keyed.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot);
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot.to_string(), uuid);
        profiles.set_profile(
            slot,
            crate::accounts::profiles::AccountProfile {
                email: "m4-4-anthropic-poller@test.invalid".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        crate::accounts::profiles::save(&crate::accounts::profiles::profiles_path(base), &profiles)
            .unwrap();

        // Identity-keyed: distinctive token. This is what the poller MUST read.
        crate::quota::origin::fixtures::known(
            base,
            slot,
            uuid,
            uuid::Uuid::from_u128(0x2000 + u128::from(slot)),
            0,
        );
        let identity_dir = crate::accounts::identity_store::identity_path(base, uuid);
        crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
        crate::platform::fs::secure_dir(&identity_dir).unwrap();
        let identity_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        let identity_creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-IDENTITY-KEYED-TOKEN".into()),
                refresh_token: RefreshToken::new("rt-identity".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&identity_path, &identity_creds).unwrap();

        // Legacy path: DIFFERENT token. The poller must NOT read this.
        let num = AccountNum::try_from(slot).unwrap();
        let legacy_creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-LEGACY-TOKEN-DO-NOT-READ".into()),
                refresh_token: RefreshToken::new("rt-legacy".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&cred_file::canonical_path(base, num), &legacy_creds).unwrap();

        // Mock HTTP that captures the bearer token.
        let captured_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_token_clone = Arc::clone(&captured_token);
        let http: HttpGetWithRetryAfterFn =
            Arc::new(move |_url: &str, token: &str, _headers: &[(&str, &str)]| {
                *captured_token_clone.lock().unwrap() = Some(token.to_string());
                let body = br#"{
                "five_hour": { "utilization": 42.0, "resets_at": "2099-01-01T00:00:00Z" },
                "seven_day": { "utilization": 15.0, "resets_at": "2099-01-14T00:00:00Z" }
            }"#;
                Ok((200, None, body.to_vec()))
            });

        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(base, &http, &cooldowns, &backoffs).await;

        let captured = captured_token.lock().unwrap().clone();
        assert_eq!(
            captured.as_deref(),
            Some("sk-ant-oat01-IDENTITY-KEYED-TOKEN"),
            "poller MUST read the bearer token from identities/<UUID>/credentials.json, \
             not from credentials/<N>.json"
        );

        // Quota was written for the slot.
        let quota = quota_state::load_state(base).unwrap();
        let q = quota.get(slot).expect("quota for slot 1");
        assert!((q.five_hour_pct() - 42.0).abs() < 0.01);
    }

    /// ROOT ruling A reader parity: a pending rescued pair outranks the stale
    /// canonical — `tick` adopts it BEFORE reading, so the usage call carries
    /// the rescued token and the record is removed.
    ///
    /// RED: remove the adoption inside `read_canonical_with_rescue` (call
    /// `credentials::load` directly) -> the poller sends the STALE token and
    /// the rescue record survives.
    #[tokio::test]
    async fn tick_adopts_pending_rescue_before_polling() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        const SLOT: u16 = 1;
        const ID: u128 = 41;
        install_known_account(base, SLOT, ID, 51, 1);

        let identity: crate::accounts::identity_store::IdentityId =
            uuid::Uuid::from_u128(ID).into();
        let identity_path = crate::accounts::identity_store::credentials_path_for(base, identity);
        let identity_dir = identity_path.parent().unwrap().to_path_buf();

        // Canonical: STALE pair (older expiry, so adoption's freshness guard
        // installs the rescued pair rather than treating it as superseded).
        let stale = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-STALE-TOKEN".into()),
                refresh_token: RefreshToken::new("rt-stale".into()),
                expires_at: 100,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&identity_path, &stale).unwrap();

        // Rescued: the fresher pair the provider actually issued.
        let rescued = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-RESCUED-TOKEN".into()),
                refresh_token: RefreshToken::new("rt-rescued".into()),
                expires_at: 200,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        // D237 round-2 H-c: the record carries the SOURCE witness
        // (`fixture@example.invalid` / account 17 / organization 51 is the
        // `install_known_account` identity.json context), so adoption re-runs
        // the writer's gate instead of an expiry comparison.
        let witness = crate::credentials::rescue::RescueWitness::Anthropic(
            crate::accounts::anthropic_identity::RescueLineageWitness {
                kind: crate::accounts::anthropic_identity::RescueWitnessKind::Refresh,
                source_version:
                    crate::accounts::anthropic_identity::CredentialVersion::for_credentials(
                        stale.anthropic().unwrap(),
                    )
                    .unwrap(),
                result_version:
                    crate::accounts::anthropic_identity::CredentialVersion::for_credentials(
                        rescued.anthropic().unwrap(),
                    )
                    .unwrap(),
                context: Some(crate::accounts::anthropic_identity::RescueKnownContext {
                    email: "fixture@example.invalid".into(),
                    account_uuid: uuid::Uuid::from_u128(17),
                    organization_uuid: uuid::Uuid::from_u128(51),
                }),
                legacy_email: None,
            },
        );
        crate::credentials::rescue::write_rescue_record(
            &identity_dir,
            "anthropic",
            &identity.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&rescued).unwrap(),
            &witness,
        )
        .unwrap();

        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);
        let http: HttpGetWithRetryAfterFn =
            Arc::new(move |_url: &str, token: &str, _headers: &[(&str, &str)]| {
                *captured_clone.lock().unwrap() = Some(token.to_string());
                Ok((
                    200,
                    None,
                    br#"{"five_hour":{"utilization":42,"resets_at":"2099-01-01T00:00:00Z"}}"#
                        .to_vec(),
                ))
            });
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(base, &http, &cooldowns, &backoffs).await;

        assert_eq!(
            captured.lock().unwrap().as_deref(),
            Some("sk-ant-oat01-RESCUED-TOKEN"),
            "the poller must adopt the rescued pair before polling, not send the stale token"
        );
        assert!(
            crate::credentials::rescue::rescue_record_pending(&identity_dir).is_none(),
            "a successful adoption removes the rescue record"
        );
        assert!(
            quota_state::load_state(base).unwrap().get(SLOT).is_some(),
            "the adopted credential's usage must be recorded"
        );
    }

    /// Ruling 3(a): an UNPARSEABLE rescue record can never install, so the
    /// reader's adoption QUARANTINES it (bytes kept for forensics, never
    /// deleted) and the genuinely absent canonical is classified
    /// `Unreadable` — the record must not block every tick forever.
    ///
    /// RED: make adoption skip the unparseable quarantine -> the record
    /// stays pending and the read classifies as `RescuePending` instead.
    #[test]
    fn unparseable_rescue_record_is_quarantined_not_left_pending() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(3);
        let canonical = crate::accounts::identity_store::credentials_path_for(base, uuid);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();
        let record_path = crate::credentials::rescue::rescue_record_path(&identity_dir);
        std::fs::write(&record_path, b"not json").unwrap();

        // No canonical credential at all: adoption quarantines the
        // unparseable record, leaving a genuine absence.
        assert!(
            matches!(
                read_canonical_with_rescue(base, Some(uuid), &canonical),
                PollerCredentialRead::Unreadable(_)
            ),
            "a quarantined unparseable record leaves a genuine absence"
        );
        assert!(
            crate::credentials::rescue::rescue_record_pending(&identity_dir).is_none(),
            "a quarantined record leaves the pending set"
        );
        assert!(
            identity_dir
                .join("quarantine")
                .join(record_path.file_name().unwrap())
                .is_file(),
            "the unparseable record is QUARANTINED, never deleted"
        );

        // Control: the identical on-disk state with no record is also absence.
        assert!(
            matches!(
                read_canonical_with_rescue(base, Some(uuid), &canonical),
                PollerCredentialRead::Unreadable(_)
            ),
            "without a rescue record the same state is a genuine absence"
        );
    }

    /// Fail-closed reader parity: a PROVABLE rescue record against an
    /// UNREADABLE canonical cannot be re-gated by adoption (it cannot prove
    /// the source), so the record stays PENDING and the read must classify
    /// it as `RescuePending` — which the tick turns into a skip WITHOUT a
    /// `SkippedNoCredentials` row.
    ///
    /// RED: remove the `still_pending` check -> the read classifies as
    /// `Unreadable`, and the tick records a false no-credentials verdict
    /// while a durable pair is pending.
    #[test]
    fn pending_rescue_against_unreadable_canonical_classifies_as_rescue_pending() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(3);
        let canonical = crate::accounts::identity_store::credentials_path_for(base, uuid);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&identity_dir).unwrap();
        // Corrupt, not absent: adoption refuses to install over a canonical
        // it cannot read, so the record stays pending and the read is
        // classified `RescuePending` rather than a no-credentials verdict.
        std::fs::write(&canonical, b"not json").unwrap();

        let stale = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-STALE-TOKEN".into()),
                refresh_token: RefreshToken::new("rt-stale".into()),
                expires_at: 100,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        let rescued = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-RESCUED-TOKEN".into()),
                refresh_token: RefreshToken::new("rt-rescued".into()),
                expires_at: 200,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        let witness = crate::credentials::rescue::RescueWitness::Anthropic(
            crate::accounts::anthropic_identity::RescueLineageWitness {
                kind: crate::accounts::anthropic_identity::RescueWitnessKind::Refresh,
                source_version:
                    crate::accounts::anthropic_identity::CredentialVersion::for_credentials(
                        stale.anthropic().unwrap(),
                    )
                    .unwrap(),
                result_version:
                    crate::accounts::anthropic_identity::CredentialVersion::for_credentials(
                        rescued.anthropic().unwrap(),
                    )
                    .unwrap(),
                context: None,
                legacy_email: None,
            },
        );
        crate::credentials::rescue::write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&rescued).unwrap(),
            &witness,
        )
        .unwrap();

        assert!(
            matches!(
                read_canonical_with_rescue(base, Some(uuid), &canonical),
                PollerCredentialRead::RescuePending(_)
            ),
            "a provable record against an unreadable canonical is PENDING, not absence"
        );
        assert!(
            crate::credentials::rescue::rescue_record_pending(&identity_dir).is_some(),
            "an adoption refusal leaves the record pending"
        );
    }

    #[tokio::test]
    async fn tick_429_enters_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_429(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(in_cooldown(&cooldowns, 1));

        // Second tick: cooldown blocks the poll.
        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "cooldown should suppress"
        );
    }

    /// End-to-end wiring check (the isolated `set_cooldown_with_backoff_and_retry_after`
    /// unit tests in `mod.rs::cooldown_backoff_tests` cover the arithmetic;
    /// this covers that `tick` actually threads the parsed `retry-after`
    /// value through `poll_anthropic_usage` into that function). An
    /// arbitrarily large retry-after (2000s -- a round test constant, not
    /// tied to any specific measured value) on a factor-1 account (600s
    /// backoff wait) must produce a cooldown far longer than 600s.
    #[tokio::test]
    async fn tick_429_with_retry_after_honors_server_wait() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);
        const SERVER_WAIT_SECS: u64 = 2000;

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_429_with_retry_after(Arc::clone(&counter), SERVER_WAIT_SECS);
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let wait = cooldowns
            .lock()
            .unwrap()
            .get(&1)
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .expect("slot 1 should be in cooldown");
        assert!(
            wait.as_secs_f64() > super::super::FAILURE_COOLDOWN.as_secs_f64() * 3.0,
            "tick must thread the server's {SERVER_WAIT_SECS}s retry-after              through to the cooldown, not the flat 600s (factor-1) backoff              wait; got {wait:?}"
        );
    }

    #[tokio::test]
    async fn tick_401_enters_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_401(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(in_cooldown(&cooldowns, 1));
    }

    #[tokio::test]
    async fn tick_no_accounts_does_nothing() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tick_success_clears_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // Prime an expired cooldown. On fresh CI runners Instant::now() may
        // be less than FAILURE_COOLDOWN since boot, so checked_sub returns
        // None — skip the test rather than panic. See refresher.rs for the
        // same pattern and a full explanation of the trade-off.
        let past = match Instant::now()
            .checked_sub(super::super::FAILURE_COOLDOWN + Duration::from_secs(1))
        {
            Some(p) => p,
            None => {
                eprintln!(
                    "SKIP tick_success_clears_cooldown: Instant::now() too close \
                     to boot to simulate an expired cooldown"
                );
                return;
            }
        };
        cooldowns.lock().unwrap().insert(1, past);

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!in_cooldown(&cooldowns, 1));
    }

    /// MED-1 (an internal ticket redteam): a schema-drifted `quota.json` (from a
    /// newer csq build) must NOT be clobbered by this write leg. Before
    /// the fix, `load_state_or_warn`'s `QuotaFile::empty()` fallback let
    /// `write_usage_to_quota` persist a ONE-row file for slot 3, wiping
    /// slots 1 and 2. The fixed `load_state_or_skip` path returns `Ok(())`
    /// without touching the file at all.
    #[test]
    fn write_usage_to_quota_skips_on_poisoned_file_preserving_siblings() {
        let dir = TempDir::new().unwrap();
        let poisoned = r#"{
            "schema_version": 99,
            "accounts": {
                "1": {"five_hour": {"used_percentage": 50.0, "resets_at": 4102444800}, "updated_at": 1.0},
                "2": {"five_hour": {"used_percentage": 80.0, "resets_at": 4102444800}, "updated_at": 1.0}
            }
        }"#;
        std::fs::write(quota_state::quota_path(dir.path()), poisoned).unwrap();

        let account = AccountNum::try_from(3u16).unwrap();
        let usage = UsageData {
            five_hour: Some(crate::quota::UsageWindow {
                used_percentage: 12.0,
                resets_at: 4_102_444_800,
            }),
            seven_day: None,
        };
        let result = write_usage_to_quota(dir.path(), account, &usage);
        assert!(result.is_ok(), "skip must be Ok(()), not an error");

        let raw = std::fs::read_to_string(quota_state::quota_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            v["accounts"]["1"]["five_hour"]["used_percentage"].as_f64(),
            Some(50.0),
            "slot 1 must survive untouched"
        );
        assert_eq!(
            v["accounts"]["2"]["five_hour"]["used_percentage"].as_f64(),
            Some(80.0),
            "slot 2 must survive untouched"
        );
        assert!(
            v["accounts"].get("3").is_none(),
            "slot 3 write must have been skipped entirely, not persisted"
        );
        assert!(
            v.get("poller_health").and_then(|h| h.get("3")).is_none(),
            "a skipped write must not leave a poller_health row behind either \
             — the two are written in the same save_state call"
        );
    }

    // ─── poller health persistence (live production-incident fix) ───
    //
    // Slot 9 stopped updating for 70+ minutes with ZERO log output: the
    // failure classes below (`debug!`-only) and the two `Err(_) =>
    // continue` discards left no operator-visible trace of what the
    // poller was doing. These tests pin the health record each outcome
    // now leaves behind, and the throttle that keeps a sustained outage
    // from flooding the log.

    /// A slot inside an already-set cooldown is skipped without an HTTP
    /// call, and that skip is itself recorded — with a `cooldown_until` in
    /// the future, not a bare "we don't know" state.
    #[tokio::test]
    async fn tick_cooldown_skip_persists_skipped_cooldown_health_with_future_deadline() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // Prime an active cooldown directly, bypassing a real failure —
        // `tick` must skip purely because of this, never call upstream.
        cooldowns
            .lock()
            .unwrap()
            .insert(1, Instant::now() + Duration::from_secs(120));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "an active cooldown must suppress the HTTP call entirely"
        );

        let quota = quota_state::load_state(dir.path()).unwrap();
        let health = quota.get_health(1).expect("health record for slot 1");
        assert_eq!(health.last_outcome, PollOutcome::SkippedCooldown);
        let cooldown_until = health
            .cooldown_until
            .expect("cooldown_until must be set for a cooldown skip");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(
            cooldown_until > now,
            "cooldown_until ({cooldown_until}) must be in the future (now={now})"
        );
    }

    /// A 429 must be distinguishable from a 401 in the persisted health —
    /// they have entirely different operator remedies (wait vs re-login).
    #[tokio::test]
    async fn tick_429_persists_rate_limited_not_unauthorized() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_429(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;

        let quota = quota_state::load_state(dir.path()).unwrap();
        let health = quota.get_health(1).expect("health record for slot 1");
        assert_eq!(health.last_outcome, PollOutcome::RateLimited);
        assert_ne!(health.last_outcome, PollOutcome::Unauthorized);
        assert_eq!(health.consecutive_failures, 1);
    }

    /// A transport (connect/DNS) failure — this outcome was `debug!`-only
    /// and silently discarded before this fix (the slot-9 incident: zero
    /// log lines for 70+ minutes). It must now be visible in the
    /// persisted health.
    #[tokio::test]
    async fn tick_transport_error_persists_transport_health() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_transport_error(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;

        let quota = quota_state::load_state(dir.path()).unwrap();
        let health = quota.get_health(1).expect("health record for slot 1");
        assert_eq!(health.last_outcome, PollOutcome::Transport);
        assert_eq!(health.consecutive_failures, 1);
    }

    /// `record_poll_failure`'s returned `changed` flag is the exact
    /// boolean `tick`'s Transport/Parse/HttpError arms use to decide
    /// whether to fire `warn!` this tick (see those arms). This pins the
    /// throttle directly: first occurrence fires, an identical repeat is
    /// suppressed, and a change of outcome fires again. (This codebase
    /// has no tracing-capture test harness to assert the `warn!` macro
    /// call itself fired; this is the direct unit-level test of the gate
    /// that call is conditioned on — see the session report for why that
    /// substitution was made.)
    #[test]
    fn record_poll_failure_changed_flag_gates_the_warn_throttle() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();

        let first = record_poll_failure(dir.path(), account, PollOutcome::Transport, None)
            .expect("record must succeed against a fresh empty quota.json");
        assert!(
            first,
            "first occurrence must report changed=true (warn fires)"
        );

        let second = record_poll_failure(dir.path(), account, PollOutcome::Transport, None)
            .expect("record must succeed");
        assert!(
            !second,
            "an identical repeated outcome must report changed=false (warn suppressed)"
        );

        let third = record_poll_failure(dir.path(), account, PollOutcome::Parse, None)
            .expect("record must succeed");
        assert!(
            third,
            "a change of outcome must report changed=true again (warn fires)"
        );
    }

    /// The health row and the quota row for a successful poll are written
    /// by the SAME `save_state` call inside `write_usage_to_quota` — they
    /// share the one `now` computed in that function, so their timestamps
    /// are not merely close, they are identical. A regression that split
    /// this into two separate lock/load/save cycles (the shape this rule
    /// exists to forbid) would make this equality flaky-to-failing.
    #[tokio::test]
    async fn tick_success_writes_quota_row_and_health_row_from_the_same_save() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;

        let quota = quota_state::load_state(dir.path()).unwrap();
        let q = quota.get(1).expect("quota row for slot 1");
        let health = quota.get_health(1).expect("health row for slot 1");
        assert_eq!(health.last_outcome, PollOutcome::Ok);
        assert_eq!(health.consecutive_failures, 0);
        assert!(health.cooldown_until.is_none());
        assert_eq!(
            q.updated_at, health.last_attempt_at,
            "the quota row and the health row must share the exact same \
             timestamp — they come from one `now` in one save_state call"
        );
    }

    /// `consecutive_failures` climbs across repeated failures and resets
    /// to 0 the moment a poll succeeds.
    #[test]
    fn consecutive_failures_increments_and_resets_to_zero_on_success() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);
        let account = AccountNum::try_from(1u16).unwrap();

        record_poll_failure(dir.path(), account, PollOutcome::Transport, None).unwrap();
        let h1 = quota_state::load_state(dir.path())
            .unwrap()
            .get_health(1)
            .unwrap()
            .consecutive_failures;
        assert_eq!(h1, 1);

        record_poll_failure(dir.path(), account, PollOutcome::ServerError, None).unwrap();
        let h2 = quota_state::load_state(dir.path())
            .unwrap()
            .get_health(1)
            .unwrap()
            .consecutive_failures;
        assert_eq!(h2, 2);

        let usage = UsageData {
            five_hour: None,
            seven_day: None,
        };
        write_usage_to_quota(dir.path(), account, &usage).unwrap();
        let after_success = quota_state::load_state(dir.path()).unwrap();
        let h3 = after_success.get_health(1).unwrap();
        assert_eq!(h3.consecutive_failures, 0, "success must reset the counter");
        assert_eq!(h3.last_outcome, PollOutcome::Ok);
    }

    /// A `SkippedCooldown` re-observation of an already-failing slot must
    /// NOT inflate `consecutive_failures` — it is the same failure still
    /// being waited out, not a new attempt. See `PollerHealth::
    /// consecutive_failures`'s doc for the full rationale.
    #[test]
    fn skipped_cooldown_carries_consecutive_failures_forward_unchanged() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();

        record_poll_failure(dir.path(), account, PollOutcome::Unauthorized, None).unwrap();
        record_poll_failure(dir.path(), account, PollOutcome::Unauthorized, None).unwrap();
        let before = quota_state::load_state(dir.path())
            .unwrap()
            .get_health(1)
            .unwrap()
            .consecutive_failures;
        assert_eq!(before, 2);

        record_poll_failure(
            dir.path(),
            account,
            PollOutcome::SkippedCooldown,
            Some(123.0),
        )
        .unwrap();
        let after = quota_state::load_state(dir.path())
            .unwrap()
            .get_health(1)
            .unwrap()
            .consecutive_failures;
        assert_eq!(
            after, before,
            "a cooldown-skip re-observation must not inflate the failure count"
        );
    }
}
