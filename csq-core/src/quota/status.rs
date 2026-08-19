//! Multi-account status display for `csq status` command.

use super::format::{account_label, fmt_reset, fmt_time};
use super::state;
use crate::accounts::{discovery, AccountInfo, AccountSource, Backend};
use crate::providers::catalog::Surface;
use crate::quota::{AccountQuota, BalanceInfo};
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Column widths for the `csq status` table. The 5h and 7d blocks share the
/// same `BAR(4) PCT(4) RESET(6)` shape so the header and data rows align by
/// construction.
const BAR_W: usize = 4;
const PCT_W: usize = 4; // "  2%" .. "100%"
const RST_W: usize = 6; // "now" .. "23h59m"

/// Renders a proportional usage bar `width` cells wide, with eighth-block
/// sub-cell resolution (`█` full, `▏▎▍▌▋▊▉` partial, `░` empty). A non-zero
/// percentage always shows at least one eighth so "tiny but used" is visually
/// distinct from "idle". Every glyph is display-width 1.
fn usage_bar(pct: f64, width: usize) -> String {
    const PARTIALS: [char; 7] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let p = pct.clamp(0.0, 100.0);
    let mut eighths = (p / 100.0 * width as f64 * 8.0).round() as usize;
    if p > 0.0 {
        eighths = eighths.max(1);
    }
    let full = (eighths / 8).min(width);
    let rem = eighths % 8;
    let mut s = String::with_capacity(width * 3);
    let mut used = 0;
    for _ in 0..full {
        s.push('█');
        used += 1;
    }
    if used < width && rem > 0 {
        s.push(PARTIALS[rem - 1]);
        used += 1;
    }
    for _ in used..width {
        s.push('░');
    }
    s
}

/// Healthy/stale boundary for a slot's quota-poll age. Input to
/// [`poll_freshness`]; drives [`AccountStatus::stale_secs`].
///
/// **Derivation (`tooling-self-verification.md` Rule 3 — the constant is
/// re-derived from the two outcomes it separates, not adopted because a
/// test passed with it). Re-derived 2026-08-02 after two successive
/// arithmetic errors in this comment (see "Corrected" note below) — this
/// revision states explicitly which parts are STRUCTURALLY GUARANTEED
/// versus ASSUMED for the common case.**
///
/// Multiple poller cadences run concurrently and this is ONE global
/// threshold, so it is anchored on the SLOWEST live cadence — every
/// faster-cadence surface inherits extra margin for free:
///
/// - Anthropic / Codex / Gemini Code-Assist OAuth ride the main tick —
///   `daemon::usage_poller::POLL_INTERVAL` = 300s (5 min).
/// - 3P bearer providers (DeepSeek, MiniMax, Z.AI) and native-CLI billing
///   (Grok, Kimi) ride the slower tick —
///   `daemon::usage_poller::POLL_INTERVAL_3P` = 900s (15 min).
///
/// **The realised 3P period `p` — lower bound is STRUCTURALLY
/// GUARANTEED, upper bound is ASSUMED.** The 3P branch is not on its own
/// timer: the run loop's `last_3p_tick.elapsed() >= POLL_INTERVAL_3P`
/// check (`daemon::usage_poller::run_loop`) cannot trip before 900s have
/// elapsed, so `p >= POLL_INTERVAL_3P` (900s) always holds — this half is
/// structural. The commonly-assumed upper bound `p < POLL_INTERVAL_3P +
/// POLL_INTERVAL` (< 1200s) additionally assumes the SAME loop
/// iteration's `anthropic::tick` + `codex::tick` + `gemini::drain_all` +
/// `gemini_oauth::tick` calls — which all run BEFORE the 3P-elapsed check
/// on every iteration — complete well within `POLL_INTERVAL` (300s).
/// **This is NOT proven.** Each of those calls processes up to
/// `MAX_ACCOUNTS_PER_TICK` (64) accounts SEQUENTIALLY (confirmed:
/// `anthropic::tick`'s account loop has no `spawn`/concurrency), each
/// account bounded by `CALL_TIMEOUT` (30s) — so a tick where many
/// accounts simultaneously time out can push the iteration well past
/// 300s, and `p` grows with it. **Direction of error if this assumption
/// breaks:** a longer `p` means a HEALTHY, still-ticking slot's row ages
/// FURTHER before its next successful poll — the same direction as this
/// whole feature's design bias (age is reported honestly rather than
/// hidden), not a new failure mode, but the "always clears N failures"
/// claims below hold only under the assumed bound, not unconditionally.
/// A full fix would require bounding per-tick worst-case latency (e.g.
/// concurrent per-account polling with a hard tick budget) — out of
/// scope for this constant; a named, non-silent limitation rather than a
/// `zero-tolerance.md` Rule 5 residual risk, because no code path here
/// makes a false SAFETY claim — the worst case still ages TOWARD Stale,
/// never away from it.
///
/// **A cooldown never costs an extra period.** `FAILURE_COOLDOWN` (600s)
/// is SHORTER than `POLL_INTERVAL_3P` (900s), so it has always expired by
/// the next 3P firing and cannot suppress an attempt. (This is
/// load-bearing and is pinned by
/// `stale_threshold_is_derived_from_the_live_poller_cadence` below —
/// raising `FAILURE_COOLDOWN` past the 3P interval invalidates every
/// number here and breaks that test.)
///
/// **The classifier is STRICT (`age_secs > STALE_THRESHOLD_SECS`), so
/// `age_secs == STALE_THRESHOLD_SECS` reads Fresh** — every bound below
/// accounts for that, unlike the two prior revisions of this comment.
///
/// **Healthy side — measured from the last SUCCESS, which is what this
/// threshold actually compares, under the ASSUMED upper bound on `p`
/// above.** `updated_at` only advances on a SUCCESSFUL poll, so `N`
/// consecutive failed attempts leave the row untouched and its age at the
/// next successful attempt is `(N+1) * p`, with `p` ranging over
/// `[900, 1200)` — a STRICT upper bound, per the derivation above:
///
/// | consecutive failures (N) | row-age range  | vs strict `> 3600`   |
/// | ------------------------- | --------------- | ----------------------- |
/// | 0 (steady state)          | `[900, 1200)`   | always clears           |
/// | 1 (one glitch)             | `[1800, 2400)`  | always clears           |
/// | 2                          | `[2700, 3600)`  | always clears — the range's own upper bound is STRICTLY below 3600, this is not "at the bound" |
/// | 3                          | `[3600, 4800)`  | clears ONLY at the exact minimum `p = 900` (age == 3600 reads Fresh); trips for every `p > 900` |
/// | 4+                         | `[4500, inf)`   | always trips            |
///
/// This is the SECOND correction to this table. The first revision (which
/// itself replaced an earlier off-by-one-period error) claimed N=2 was
/// "at the bound" and N=3 "always trips" — both wrong, because it compared
/// against the range's fixed upper value (1200) as if achievable, when
/// `p < 1200` is itself a strict inequality. The corrected picture is ONE
/// full failure more tolerant: N=2 ALWAYS clears (not merely "at the
/// bound"), and N=3 clears only in the single minimum-period edge case
/// rather than never. Corrected 2026-08-02
/// (`tooling-self-verification.md` Rule 3: the highest-value findings are
/// arithmetic, not structural).
///
/// **Broken side:** the incident this threshold exists to catch
/// (2026-08-02, a native Grok slot with an expired vendor token) sat
/// stale for 15.6h = 56,160s, and an expired vendor token does not
/// self-heal — the age grows without bound until an operator re-logs in.
/// N=4+ always trips regardless of drift, so this incident is caught with
/// enormous margin (56,160s vs a 4,500s trip point).
///
/// **What 3600 therefore separates, stated honestly:** under the assumed
/// per-tick-latency bound, it clears steady state and ANY TWO consecutive
/// transient failures unconditionally, and trips on three-or-more
/// consecutive failures except in the single edge case where every
/// realised period hit the structural minimum exactly. That edge case
/// reading Fresh is a coin-flip at one specific row age, not a systematic
/// false negative — the marker still fires for every worse (more
/// realistic) drift pattern.
///
/// **The fast cadence (Anthropic / Gemini Code-Assist OAuth,
/// `POLL_INTERVAL`=300s) is a DIFFERENT regime from the 3P cadence above
/// — not a scaled-down copy of it.**
///
/// **Codex is NOT in this group** — see the separate Codex paragraph
/// below. An earlier revision of this comment listed it here, which was
/// wrong twice over: Codex is not gated by `FAILURE_COOLDOWN` at all
/// (`codex::tick` takes `cfg.codex_breakers`, and `codex.rs` contains no
/// reference to `FAILURE_COOLDOWN`), so neither the lower bound nor the
/// upper bound derived below applies to it. Found by a third redteam
/// lens 2026-08-02; the numbers happened to stay inside this envelope by
/// coincidence, and nothing asserted it until Premise 4 of
/// `stale_threshold_is_derived_from_the_live_poller_cadence` did.
///
/// An earlier revision of this comment
/// claimed these surfaces "clear the same bound with 3x the margin, since
/// their `p < 600s`" — FALSE on both halves, found by a second redteam
/// lens 2026-08-02. `FAILURE_COOLDOWN` (600s) EXCEEDS `POLL_INTERVAL`
/// (300s) here (the reverse of the 3P relationship, where
/// `FAILURE_COOLDOWN < POLL_INTERVAL_3P`), so `anthropic::tick`'s
/// `in_cooldown` gate (`anthropic.rs`) genuinely SUPPRESSES the tick
/// immediately after a failure — the realised retry period is NOT under
/// 600s, it is AT LEAST 600s.
///
/// The first post-success failure always lands exactly one tick later
/// (300s — no cooldown gates the FIRST attempt). Every SUBSEQUENT retry
/// is spaced by the realised fast-cadence period `p_fast`, STRUCTURALLY
/// bounded below by `FAILURE_COOLDOWN` (600s — the account cannot be
/// retried before its own cooldown expires) and ASSUMED bounded above by
/// `FAILURE_COOLDOWN + POLL_INTERVAL` (900s, the same one-tick
/// iteration-slop assumption as the 3P derivation above — and subject to
/// the same NOT-PROVEN caveat). `set_cooldown_with_backoff` can grow
/// `p_fast` further on repeated failures, always in the tolerant
/// direction (longer period → more failures needed to trip), never the
/// other way.
///
/// Age after `N` consecutive fast-cadence failures is `tick + N *
/// p_fast`:
///
/// | consecutive failures (N) | row-age                         | vs strict `> 3600` |
/// | ------------------------- | -------------------------------- | --------------------- |
/// | 3                          | `< 300 + 3*900 = 3000` (assumed upper bound) | always clears |
/// | 5 (illustrative, `p_fast`=600 exactly) | `= 300 + 5*600 = 3300` | clears at the structural minimum |
/// | 6                          | `>= 300 + 6*600 = 3900` (structural minimum) | always trips |
///
/// So the fast cadence ALWAYS clears 3 consecutive failures (using the
/// assumed worst-case period) and ALWAYS trips by 6 (using the
/// structural-minimum period) — a materially LARGER failure budget than
/// the 3P cadence's 2-clears/3-trips, not the "3x the margin" the prior
/// text claimed. Pinned by `stale_threshold_is_derived_from_the_live_poller_cadence`
/// below (Premise 3 + the two fast-cadence assertions) — raising
/// `FAILURE_COOLDOWN` above `POLL_INTERVAL` on some FUTURE fast-cadence
/// surface, or dropping it below, changes this regime and breaks the
/// test. Corrected 2026-08-02.
///
/// **Codex is its own THIRD regime — an ungated prefix, then a doubling
/// circuit breaker.** It polls on `POLL_INTERVAL` (300s) like the fast
/// cadence, but `FAILURE_COOLDOWN` never touches it: retries are gated
/// by `codex::BreakerState`. The first `CODEX_BREAKER_FAIL_THRESHOLD`
/// (5) consecutive failures are NOT gated at all — they retry on the
/// bare 300s tick. Only the 5th trips the breaker, applying
/// `CODEX_BREAKER_BASE_COOLDOWN` (900s) and doubling it per subsequent
/// consecutive failure, capped at `CODEX_BREAKER_MAX_COOLDOWN` (4800s).
///
/// | consecutive failures (N) | row-age at recovery              | vs strict `> 3600` |
/// | ------------------------- | -------------------------------- | --------------------- |
/// | 5 (the trip itself)        | `5*300 + 900 = 2400`             | clears (1200s margin) |
/// | 6                          | `2400 + 2*900 = 4200`            | trips (600s margin)   |
///
/// So Codex clears a 5-failure transient episode and trips on the 6th —
/// close in shape to the fast cadence's 3-clears/6-trips, but arrived at
/// through entirely different constants. Pinned by Premise 4 of
/// `stale_threshold_is_derived_from_the_live_poller_cadence`; any change
/// to a `CODEX_BREAKER_*` constant that breaks the separation fails
/// there. Added 2026-08-02.
pub const STALE_THRESHOLD_SECS: u64 = 3600;

/// Tolerance for a quota row's `updated_at` reading AHEAD of `now_secs` —
/// i.e. clock skew between the process that wrote the row and the moment
/// it is read. Set to the slowest live poll interval (900s,
/// `POLL_INTERVAL_3P`) as a generous allowance for ordinary NTP drift and
/// daemon-restart jitter — comfortably larger than any realistic clock
/// disagreement between processes on the same host, comfortably smaller
/// than the corrupted-clock scenario [`poll_freshness`] guards against
/// (a stale write from a since-corrected future-dated clock, which would
/// otherwise read Fresh for as long as `now_secs` has not yet caught up
/// to the bad `updated_at` — days, in the incident this constant exists
/// to bound).
const FUTURE_SKEW_TOLERANCE_SECS: u64 = 900;

/// Poll-staleness classification for a slot's quota row. See
/// [`poll_freshness`] for the pure classifier and [`STALE_THRESHOLD_SECS`]
/// for the threshold derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollFreshness {
    /// No quota row exists for the slot, the row's `updated_at` is the v2
    /// default sentinel (`0.0` — `AccountQuota::default()`, including a
    /// rebind-cleared row that has not yet seen its first successful
    /// poll), OR `updated_at` is implausibly far AHEAD of `now_secs`
    /// (beyond `FUTURE_SKEW_TOLERANCE_SECS` — corrupt data from a
    /// since-corrected bad clock, not a genuinely fresh write). Distinct
    /// from `Stale`: there is no age to report, so no marker renders — a
    /// freshly created slot, or a surface csq does not poll at all
    /// (manual, most bare API-key 3P surfaces), must not be mislabelled
    /// as "stale". This function alone does NOT know whether a row's
    /// surface is EVENT-DRIVEN (updated only when user traffic produces
    /// an event, e.g. Gemini ApiKey/VertexSa) versus poll-cadence — that
    /// classification is the CALLER's responsibility
    /// (`compose_status`'s `is_event_driven_row` gate, which skips
    /// calling this function entirely for such rows) because it depends
    /// on the row's `surface`/`kind`, which this function does not take.
    NeverPolled,
    /// `now - updated_at` is within [`STALE_THRESHOLD_SECS`], OR
    /// `updated_at` is ahead of `now` by no more than
    /// `FUTURE_SKEW_TOLERANCE_SECS` (ordinary clock skew — floors to
    /// age 0 via `saturating_sub`). No marker.
    Fresh,
    /// `now - updated_at` exceeds [`STALE_THRESHOLD_SECS`] — the poller
    /// has missed several consecutive ticks on every currently-live
    /// cadence. `age_secs` is `now - updated_at`.
    Stale { age_secs: u64 },
}

/// Classifies a slot's poll freshness from its quota row's `updated_at`
/// (epoch seconds, or `None` when the slot has no quota row at all)
/// against the caller-supplied `now_secs`.
///
/// Pure and clock-injected — `csq-core` has no ambient clock helper, so
/// this takes `now_secs` as a parameter rather than reading
/// `SystemTime::now()` itself, keeping it unit-testable without time
/// bombs. Callers (the CLI, the desktop IPC layer) pass the real wall
/// clock; tests pass a literal `now_secs`.
pub fn poll_freshness(updated_at: Option<f64>, now_secs: u64) -> PollFreshness {
    let updated_at = match updated_at {
        Some(u) if u > 0.0 => u,
        _ => return PollFreshness::NeverPolled,
    };
    // updated_at is an epoch-seconds f64 written by `save_state` callers,
    // which always pass a real wall-clock value — but this function must
    // not panic on adversarial/corrupted input, so saturate at u64::MAX
    // before the cast rather than trust the range. No lower-bound clamp
    // is needed here: the `Some(u) if u > 0.0` guard above has already
    // excluded every `u <= 0.0` AND every NaN (NaN comparisons are always
    // false, so `NaN > 0.0` routes to `NeverPolled`) — `updated_at` is
    // always a positive, non-NaN f64 by the time this line runs.
    let updated_secs = updated_at.min(u64::MAX as f64) as u64;
    // A row whose `updated_at` is implausibly far AHEAD of `now_secs` is
    // corrupt data (a bad clock at write time, since corrected), not a
    // healthy recent write. Classify it as NeverPolled — honest about
    // having no confident age — rather than let `saturating_sub` floor
    // it to age 0 and render Fresh for as long as `now_secs` has not yet
    // caught up to the bad timestamp, which can be days (see
    // `FUTURE_SKEW_TOLERANCE_SECS`'s doc comment for the bound).
    if updated_secs > now_secs.saturating_add(FUTURE_SKEW_TOLERANCE_SECS) {
        return PollFreshness::NeverPolled;
    }
    let age_secs = now_secs.saturating_sub(updated_secs);
    if age_secs > STALE_THRESHOLD_SECS {
        PollFreshness::Stale { age_secs }
    } else {
        PollFreshness::Fresh
    }
}

/// Status entry for a single account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub id: u16,
    pub label: String,
    pub is_active: bool,
    pub five_hour_pct: Option<f64>,
    pub five_hour_resets_in: Option<u64>,
    pub seven_day_pct: Option<f64>,
    pub seven_day_resets_in: Option<u64>,
    /// Account source (Anthropic OAuth, Codex OAuth, third-party API
    /// key, manual). Older JSON without this field deserialises to
    /// `AccountSource::Anthropic` via the default.
    #[serde(default = "default_source")]
    pub source: AccountSource,
    /// Upstream surface (`claude-code` or `codex`). Defaults to
    /// `ClaudeCode` for backwards compatibility with snapshots that
    /// predate this field.
    #[serde(default)]
    pub surface: Surface,
    /// Auth method tag from `AccountInfo.method` —
    /// `oauth` / `api_key` / `code_assist_oauth` / `vertex_sa`.
    /// Used by [`AccountStatus::format_line`] to render the trailing
    /// `(api-key)` / `(oauth)` / `(vertex-sa)` suffix on non-polled
    /// rows. Defaults to empty for snapshots that predate this field.
    #[serde(default)]
    pub method: String,
    /// Remaining account balance for pay-per-token providers (e.g. DeepSeek).
    /// `None` for subscription-based or rate-limited providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<BalanceInfo>,
    /// Cloud-Claude routing backend (an internal ticket), DERIVED from the slot's
    /// `settings.json` env block by
    /// [`crate::providers::settings::backend_for_slot`] at compose time — NOT
    /// stored on `AccountInfo`. `Direct` for every ordinary slot; `Vertex` /
    /// `Bedrock` for a `ClaudeCode` slot routed through Google Vertex AI / AWS
    /// Bedrock. Older JSON without this field deserialises to `Backend::Direct`.
    #[serde(default)]
    pub backend: Backend,
    /// Age (seconds) of a stale quota poll — `Some(age)` only when
    /// [`poll_freshness`] classifies the row as [`PollFreshness::Stale`].
    /// `None` covers BOTH "fresh" and "never polled" (see that enum's
    /// doc) — the renderer shows no marker for either, so the two
    /// states collapse to the same wire value by design. Additive
    /// field: absent on JSON written by older csq builds, defaulting to
    /// `None` (no marker) rather than failing to deserialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_secs: Option<u64>,
}

fn default_source() -> AccountSource {
    AccountSource::Anthropic
}

impl AccountStatus {
    /// Returns the icon for 5-hour usage:
    /// - `●` (bullet) for <80%
    /// - `◐` (half) for 80-99%
    /// - `○` (circle) for 100%
    /// - `·` (middle dot) for no data
    pub fn five_hour_icon(&self) -> &'static str {
        match self.five_hour_pct {
            None => "·",
            Some(p) if p < 80.0 => "●",
            Some(p) if p < 100.0 => "◐",
            Some(_) => "○",
        }
    }

    /// Surface tag shown after the label, e.g. ` [codex]`,
    /// ` [gemini]`, or ` [minimax]`. Empty for vanilla Anthropic
    /// OAuth rows so existing output is byte-identical for
    /// Anthropic-only setups.
    ///
    /// C5 (an internal journal entry, issue 4): native Kimi/Grok session surfaces render
    /// UPPERCASE tags (` [KIMI]` / ` [GROK]`) — deliberately distinct from
    /// the lowercase OAuth/API-key tags (`[codex]`, `[gemini]`,
    /// `[minimax]`) so a native self-authenticating vendor-CLI slot reads
    /// visually distinct from a csq-managed credential slot at a glance.
    fn surface_tag(&self) -> String {
        // Cloud-Claude routing (an internal ticket) takes precedence: it applies only
        // to the ClaudeCode surface and is mutually exclusive with the
        // codex/gemini/native surfaces and the 3P base-URL providers below, so
        // an early return is safe. Renders ` [vertex]` / ` [bedrock]`.
        if self.backend.is_cloud() {
            return format!(" [{}]", self.backend.as_str());
        }
        match (&self.surface, &self.source) {
            (Surface::Codex, _) => " [codex]".to_string(),
            (Surface::Gemini, _) => " [gemini]".to_string(),
            (Surface::Kimi, _) => " [KIMI]".to_string(),
            (Surface::Grok, _) => " [GROK]".to_string(),
            (_, AccountSource::ThirdParty { provider }) => {
                format!(" [{}]", provider.to_ascii_lowercase())
            }
            (_, AccountSource::Manual) => " [manual]".to_string(),
            _ => String::new(),
        }
    }

    /// Formats the status line for this account.
    ///
    /// Anthropic OAuth and Codex rows include 5h/7d quota fields when
    /// the poller has data (Codex quota lands alongside Anthropic per
    /// spec 07 §7.4). Third-party and manual rows omit the quota
    /// suffix — csq does not poll those providers' quotas today.
    pub fn format_line(&self) -> String {
        let marker = if self.is_active { "*" } else { " " };
        let icon = self.five_hour_icon();
        let tag = self.surface_tag();
        let stale = self.stale_marker();

        // Third-party / manual slots: no quota polling, render a
        // bound-state suffix instead of "5h:— 7d:—" so the user can
        // tell "no data yet" from "no polling".
        let polled = matches!(self.source, AccountSource::Anthropic | AccountSource::Codex);
        if !polled {
            let suffix = if self.has_any_quota_data() {
                self.quota_suffix()
            } else {
                self.bound_state_suffix().to_string()
            };
            return format!(
                "{} #{} {} {}{}  {}{}",
                marker, self.id, icon, self.label, tag, suffix, stale
            );
        }

        let suffix = self.quota_suffix();
        format!(
            "{} #{} {} {}{}  {}{}",
            marker, self.id, icon, self.label, tag, suffix, stale
        )
    }

    /// Trailing `  stale <age>` marker used by the `csq status` table
    /// renderer ([`render_status_table`]). [`format_line`](Self::format_line)
    /// also calls this — the two are kept in sync — but `format_line`
    /// itself has NO production caller today (only its own tests); the
    /// table renderer is the sole live path. Empty string when
    /// `stale_secs` is `None` (fresh or never-polled; see
    /// [`PollFreshness`]). Fixed vocabulary, no file paths or
    /// credentials — an operator diagnostic, not prose.
    fn stale_marker(&self) -> String {
        match self.stale_secs {
            // Native-CLI slots are VENDOR-authed: csq deliberately never
            // refreshes their tokens (an internal journal entry design lock — "native
            // surfaces self-refresh"). Measured 2026-08-06, that premise
            // holds only while the vendor CLI is actually RUNNING: a Kimi
            // vendor token lives 900 s and IS refreshed on a real call
            // (verified — a `csq run 14 --prompt` moved `expires_at`
            // forward), but nothing refreshes it while the slot is idle.
            // So csq's periodic poll 401s almost always, and the row goes
            // stale by design.
            //
            // That staleness is EXPECTED and self-correcting on next use.
            // Rendering it identically to a wedged-daemon staleness is the
            // same conflation this file has already been fixed for twice —
            // a balance masking a live window, and an absent window shown
            // as a measured 0%. Two opposite states, one indicator.
            //
            // Annotate rather than SUPPRESS: the age is real and worth
            // showing (if the daemon genuinely wedges, every row goes stale
            // and that is still visible). What was wrong was implying this
            // particular row needs operator action.
            Some(age) if matches!(self.source, AccountSource::Native { .. }) => {
                format!("  stale {} · re-auths on use", fmt_time(age))
            }
            Some(age) => format!("  stale {}", fmt_time(age)),
            None => String::new(),
        }
    }

    fn has_any_quota_data(&self) -> bool {
        self.five_hour_pct.is_some() || self.seven_day_pct.is_some() || self.balance.is_some()
    }

    /// True when the row carries at least one real usage WINDOW.
    ///
    /// Deliberately excludes `balance`: this is the predicate that decides
    /// whether a slot is subscription-shaped (render the window) or
    /// pay-per-token-shaped (render the balance). Folding `balance` in here
    /// would make it always true for grok-17 and reinstate the bug.
    fn shows_window(&self) -> bool {
        self.five_hour_pct.is_some() || self.seven_day_pct.is_some()
    }

    /// True when this row is genuinely rendering the pay-per-token BALANCE
    /// suffix — mirrors the exact predicate `render_status_table`'s body
    /// branch uses (`if let (false, Some(b)) = (a.shows_window(),
    /// a.balance.as_ref())`) to decide between the balance display and
    /// everything else.
    ///
    /// Deliberately a POSITIVE assertion (no window AND a balance IS
    /// present), not `!shows_window()` alone. `!shows_window()` is ALSO
    /// true for a subscription account whose poller has gone stale — no
    /// window AND no balance, i.e. no data at all — and conflating that
    /// with "genuinely balance-based" wrongly demotes a healthy provider
    /// group to the trailing bucket in [`compose_status`]'s sort.
    ///
    /// Found live: two real Kimi accounts (subscription, `stale
    /// 2h`/`stale 2d` — expired vendor tokens) sorted to the bottom of
    /// `csq status` instead of directly after Codex, because the
    /// display-order fix's first cut keyed the trailing bucket on
    /// `!shows_window()` alone.
    fn is_balance_only(&self) -> bool {
        !self.shows_window() && self.balance.is_some()
    }

    /// Provider group rank for `csq status` display ordering.
    ///
    /// Mirrors the desktop dashboard's `providerGroupRank` in
    /// `csq/ui/src/lib/components/AccountList.svelte` (an internal ticket) — the two
    /// surfaces MUST NOT drift. Order: Claude native -> Codex -> Kimi (both
    /// account shapes) -> Grok -> Z.AI -> MiniMax -> everything else.
    /// Derived from `source` / `surface` — NEVER from slot id, which the
    /// maintainer actively renumbers.
    ///
    /// Applied ONLY as the secondary sort key in [`compose_status`], after
    /// the [`AccountStatus::is_balance_only`] split — a genuinely
    /// balance-only account (e.g. DeepSeek) sorts last regardless of its
    /// provider group, because billing mode is per-PLAN, not per-provider
    /// (an internal ticket). A subscription account with no data yet (never polled,
    /// or a stale/dead poller) is NOT balance-only and keeps its provider
    /// rank — see `is_balance_only`'s doc comment for why the split cannot
    /// key on absent window data alone.
    fn provider_group_rank(&self) -> u8 {
        if matches!(self.source, AccountSource::Anthropic) {
            return 1; // Claude native (Anthropic OAuth)
        }
        if matches!(self.surface, Surface::Codex) {
            return 2;
        }
        // Kimi has two account shapes: a native self-authenticating CLI
        // slot (`surface == Surface::Kimi`) and a 3P Bearer-key slot that
        // runs the `claude` CLI against Kimi's base URL (`source ==
        // ThirdParty { provider: "Kimi" }`, `surface == ClaudeCode`). Both
        // belong in the same group even though their `surface`/`method`
        // differ — mirrors the Svelte `surface === 'kimi' || provider_id
        // === 'kimi'` disjunction.
        if matches!(self.surface, Surface::Kimi) {
            return 3;
        }
        if let AccountSource::ThirdParty { provider } = &self.source {
            if provider.eq_ignore_ascii_case("kimi") {
                return 3;
            }
        }
        if matches!(self.surface, Surface::Grok) {
            return 4;
        }
        if let AccountSource::ThirdParty { provider } = &self.source {
            if provider.eq_ignore_ascii_case("z.ai") {
                return 5;
            }
            if provider.eq_ignore_ascii_case("minimax") {
                return 6;
            }
        }
        7 // everything else (Gemini, Ollama, DeepSeek, cloud-Claude, manual, ...)
    }

    /// Suffix shown on non-polled rows when no quota is recorded yet.
    /// Distinguishes the auth method so OAuth-mode Gemini (token-bearing)
    /// is not mislabelled as `(api-key)` (a real material misread —
    /// users with both API-key and OAuth slots cannot tell them apart
    /// from the dashboard otherwise).
    ///
    /// C4/C5 (an internal journal entry): `bound_state_line` (the table renderer, below)
    /// already carried the `native_cli` arm from the W3 fix — this sibling
    /// function (the `format_line` non-table renderer) had NOT, so a native
    /// Kimi/Grok slot with no quota data fell through to the `_ => "(api-key)"`
    /// default and was mislabelled exactly like the bug the W3 fix closed
    /// for the table path. Found by `format_line_native_{kimi,grok}_*` tests.
    fn bound_state_suffix(&self) -> &'static str {
        match self.method.as_str() {
            "code_assist_oauth" | "oauth" | "oauth-personal" => "(oauth)",
            "vertex_sa" => "(vertex-sa)",
            // Wave 3 native-CLI slots (Kimi/Grok) self-authenticate — neither
            // api-key nor csq-held OAuth. See `bound_state_line`'s identical
            // arm for the original W3 fix this mirrors.
            "native_cli" => "(native-cli)",
            // `api_key` and the empty-string default both render
            // `(api-key)` — preserves byte-for-byte output for the
            // 3P bearer slots (DeepSeek/MiniMax/Z.AI/Ollama) that
            // existed before this field landed.
            _ => "(api-key)",
        }
    }

    fn quota_suffix(&self) -> String {
        // Usage windows WIN over a balance whenever both are present.
        //
        // A populated `balance` does NOT imply a pay-per-token plan — billing
        // mode is per-PLAN, not per-provider, and the same vendor ships both.
        // A subscription slot can carry a meaningless `$0.00` alongside the
        // real quota window: measured on grok-17, which reported
        // `seven_day_pct: 7.0` AND `balance: {USD, 0.0}` and rendered the
        // useless one. Windows are the subscription signal, so they take
        // precedence; the balance is the FALLBACK for a slot that has no
        // window data at all (the genuine pay-per-token shape — DeepSeek
        // carries `USD 165.32` with both windows `None`).
        if !self.shows_window() {
            if let Some(ref b) = self.balance {
                return format_balance(b);
            }
        }
        let usage = match self.five_hour_pct {
            Some(p) => {
                let resets = self
                    .five_hour_resets_in
                    .map(fmt_time)
                    .unwrap_or_else(|| "?".into());
                format!("5h:{:.0}% ({}) ", p, resets)
            }
            None => "5h:— ".to_string(),
        };
        let weekly = match self.seven_day_pct {
            Some(p) => format!("7d:{:.0}%", p),
            None => "7d:—".to_string(),
        };
        format!("{}{}", usage, weekly)
    }

    // ── Table renderer (csq status) ──────────────────────────────────

    /// True when this row carries quota data csq can render — a polled
    /// surface (Anthropic / Codex), a third-party slot that reports usage
    /// (e.g. Z.AI 7-day window), or a balance-carrying pay-per-token slot.
    fn shows_quota(&self) -> bool {
        matches!(self.source, AccountSource::Anthropic | AccountSource::Codex)
            || self.has_any_quota_data()
    }

    /// Surface tag without the leading space [`surface_tag`] adds, e.g.
    /// `[codex]`. Empty for vanilla Anthropic.
    fn tag_bare(&self) -> String {
        self.surface_tag().trim_start().to_string()
    }

    /// The non-polled bound-state line shown in place of the quota columns,
    /// e.g. `oauth — not quota-polled`. Distinguishes auth method so an
    /// OAuth Gemini slot is not mislabelled as an api-key slot.
    fn bound_state_line(&self) -> String {
        let word = match self.method.as_str() {
            "code_assist_oauth" | "oauth" | "oauth-personal" => "oauth",
            "vertex_sa" => "vertex-sa",
            // Wave 3 native-CLI slots self-authenticate — neither api-key nor
            // csq-held OAuth (found mislabeled "api-key" by the W3 user-path smoke).
            "native_cli" => "native-cli",
            _ => "api-key",
        };
        format!("{word} — not quota-polled")
    }

    /// Weekly-cap flag: `⛔` at 100%, `⚠` above 80%, empty otherwise. The
    /// single signal that tells an operator "this account is weekly-limited"
    /// at a glance.
    fn weekly_flag(&self) -> &'static str {
        match self.seven_day_pct {
            Some(p) if p >= 100.0 => "⛔",
            Some(p) if p >= 80.0 => "⚠",
            _ => "",
        }
    }

    /// Renders one quota block — `bar pct reset` — to a fixed 16-column width
    /// so the 5h and 7d columns align. `empty_label` (`idle` / `—`) fills the
    /// block when the window has no data.
    fn quota_block(pct: Option<f64>, resets_in: Option<u64>, empty_label: &str) -> String {
        let block_w = BAR_W + 1 + PCT_W + 1 + RST_W; // 16
        match pct {
            Some(p) => {
                let bar = usage_bar(p, BAR_W);
                let reset = resets_in.map(fmt_reset).unwrap_or_else(|| "?".into());
                format!("{bar} {p:>3.0}% {reset:<RST_W$}")
            }
            None => format!("{empty_label:<block_w$}"),
        }
    }
}

/// Formats a balance for display.
///
/// USD renders as `$197.15`; other currencies render as `197.15 EUR`.
fn format_balance(b: &BalanceInfo) -> String {
    if b.currency == "USD" {
        format!("${:.2}", b.remaining)
    } else {
        format!("{:.2} {}", b.remaining, b.currency)
    }
}

/// Renders the full `csq status` table: header summary, aligned account rows
/// with per-window usage bars + reset countdowns + weekly-cap flags, and a
/// legend footer when any account is capped.
///
/// Pure (takes a pre-formatted `clock` string) so the layout is golden-tested
/// without a wall-clock dependency. The CLI passes `chrono::Local::now()`.
pub fn render_status_table(
    accounts: &[AccountStatus],
    active: Option<AccountNum>,
    clock: &str,
) -> String {
    let active_id = active.map(|a| a.get());

    // Column widths derived from the data so labels + tags align.
    let id_w = accounts
        .iter()
        .map(|a| a.id.to_string().len())
        .max()
        .unwrap_or(1)
        .max(1);
    let acct_w = accounts
        .iter()
        .map(|a| {
            let label = a.label.chars().count();
            let tag = a.tag_bare().chars().count();
            if tag == 0 {
                label
            } else {
                label + 1 + tag
            }
        })
        .max()
        .unwrap_or(7)
        .max("ACCOUNT".len());

    let mut out = String::new();

    // Header summary.
    let n = accounts.len();
    let active_str = active_id
        .map(|id| format!("#{id} active"))
        .unwrap_or_else(|| "no active slot".to_string());
    out.push_str(&format!("\n  csq · {n} slots · {active_str} · {clock}\n\n"));

    // Column header (each window block shares the BAR/PCT/RESET widths used by
    // the data rows, so they align by construction).
    let head5 = format!("{:<BAR_W$} {:>PCT_W$} {:<RST_W$}", "5H", "USED", "RESET");
    let head7 = format!("{:<BAR_W$} {:>PCT_W$} {:<RST_W$}", "7D", "USED", "RESET");
    let header = format!(
        "  {marker} {hash:>id_w$}  {acct:<acct_w$}  {head5}  {head7}",
        marker = " ",
        hash = "#",
        acct = "ACCOUNT",
    );
    out.push_str(header.trim_end());
    out.push('\n');

    let mut any_flag = false;
    for a in accounts {
        let marker = if active_id == Some(a.id) { "▸" } else { " " };

        // Account field: label left, tag right-aligned to the column edge.
        let tag = a.tag_bare();
        let label_w = a.label.chars().count();
        let acct_field = if tag.is_empty() {
            format!("{:<acct_w$}", a.label)
        } else {
            let pad = acct_w.saturating_sub(label_w + tag.chars().count());
            format!("{}{}{}", a.label, " ".repeat(pad), tag)
        };

        let body = if let (false, Some(b)) = (a.shows_window(), a.balance.as_ref()) {
            // Genuine pay-per-token slot: a balance and NO usage window.
            // Render the credit in place of the bars.
            //
            // The `!shows_window()` guard is load-bearing — see `quota_suffix`.
            // Keying on `balance.is_some()` alone rendered grok-17's
            // meaningless `$0.00` and HID its real 7% weekly window, because a
            // subscription plan can carry both. DeepSeek (balance, no windows)
            // is the shape this branch actually exists for.
            format!("{} balance", format_balance(b))
        } else if a.shows_quota() {
            let five = AccountStatus::quota_block(a.five_hour_pct, a.five_hour_resets_in, "idle");
            let seven = AccountStatus::quota_block(a.seven_day_pct, a.seven_day_resets_in, "—");
            let flag = a.weekly_flag();
            if !flag.is_empty() {
                any_flag = true;
            }
            let flag_part = if flag.is_empty() {
                String::new()
            } else {
                format!(" {flag}")
            };
            format!("{five}  {seven}{flag_part}")
        } else {
            a.bound_state_line()
        };

        let stale = a.stale_marker();
        let line = format!(
            "  {marker} {id:>id_w$}  {acct_field}  {body}{stale}",
            id = a.id
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }

    if any_flag {
        out.push_str("\n  ⛔ weekly cap reached    ⚠ weekly >80%\n");
    }

    out
}

/// True when `q`'s row is written by an EVENT-DRIVEN consumer rather than
/// a periodic poller tick — i.e. `updated_at` only advances when the
/// user's own traffic produces an event, not on a fixed cadence.
/// [`poll_freshness`]'s age-based classification is meaningless for such
/// a row: an idle-but-healthy slot ages forever with no poller tick to
/// "miss", so [`compose_status`] MUST skip staleness classification
/// entirely for these rows rather than pass their (possibly very old)
/// `updated_at` through [`poll_freshness`].
///
/// Derived from data the writers themselves stamp on the row (`surface`
/// and `kind`) rather than a hardcoded provider/method list, so a future
/// event-driven surface is caught automatically as long as it follows the
/// same stamping convention its writer already uses.
///
/// The ONLY event-driven writer in the codebase today is
/// `daemon::usage_poller::gemini::apply_event_with_source` (NDJSON drain
/// and live IPC), used exclusively for Gemini `ApiKey` / `VertexSa` slots.
/// It stamps `surface = "gemini"` and `kind` in `{"counter", "unknown"}`
/// (the latter after the 5-strike schema-drift breaker trips) — NEVER
/// `"utilization"`. The sibling Gemini writer,
/// `daemon::usage_poller::gemini_oauth::tick` (Code Assist OAuth, polled
/// on the daemon's main 300s loop tick), stamps the SAME `surface =
/// "gemini"` but ALWAYS `kind = "utilization"`. So for the Gemini surface
/// specifically, `kind != "utilization"` is the discriminator between
/// the two writers.
///
/// Every OTHER surface (Anthropic, Codex, 3P bearer providers, native
/// Grok/Kimi) is poll-cadence regardless of `kind` — Codex's own degraded
/// state ALSO writes `kind = "unknown"`
/// (`daemon::usage_poller::codex::write_unknown_to_quota`), but that
/// write happens FROM INSIDE Codex's 300s poll tick, so a bare `kind ==
/// "unknown"` check (without the surface qualifier) would misclassify a
/// degraded-but-still-polled Codex row as event-driven and wrongly
/// suppress its staleness marker — the exact bug this function's
/// `surface == "gemini"` qualifier exists to avoid.
fn is_event_driven_row(q: &AccountQuota) -> bool {
    q.surface == "gemini" && q.kind != "utilization"
}

/// Returns the status of all discovered accounts.
///
/// Convenience wrapper for the direct (non-daemon) path: runs
/// [`discovery::discover_all`] and hands the result to
/// [`compose_status`]. The daemon-delegated path calls
/// [`compose_status`] directly with accounts parsed from
/// `/api/accounts`.
///
/// Before alpha.N this function called `discover_anthropic`, which
/// silently dropped Codex + third-party (MiniMax/Z.AI/Ollama) + manual
/// slots. `discover_all` composes every source in priority order so
/// `csq status` now renders the full configured set.
pub fn show_status(base_dir: &Path, active: Option<AccountNum>) -> Vec<AccountStatus> {
    let accounts = discovery::discover_all(base_dir);
    compose_status(base_dir, accounts, active)
}

/// Composes status entries from a pre-discovered account list.
///
/// Joins the account list with the local quota file and produces
/// the filtered, sorted [`AccountStatus`] entries the CLI displays.
/// The quota file is a local read in both paths — the daemon does
/// not currently expose quota over HTTP.
///
/// Used by both the direct path (via [`show_status`]) and the
/// daemon-delegated path (`csq status` after parsing
/// `/api/accounts`), so the two paths are guaranteed to produce
/// identical output for the same `(accounts, quota)` pair.
///
/// Sort is applied HERE (the single junction both paths share) rather than
/// in [`discovery::discover_all`] — that function composes accounts for
/// the daemon, refresher, usage pollers, auto-rotation, and `csq probe`,
/// none of which have a display-order concern, so widening its contract
/// with a display-only sort would be a much wider blast radius than this
/// display-order fix needs. The sort key is a 3-tuple: a genuinely
/// balance-only account ([`AccountStatus::is_balance_only`] — a positive
/// assertion, NOT the absence of window data; see that method's doc
/// comment for why the distinction is load-bearing) sorts after every
/// other account, since billing mode is per-PLAN, not per-provider (PR
/// an internal ticket); then by [`AccountStatus::provider_group_rank`] (mirrors the
/// desktop dashboard's `providerGroupRank`, an internal ticket); then by slot id
/// ascending. The id tiebreak is explicit rather than relying on
/// `discover_all`'s composition order being stable-sort-preserved: that
/// order interleaves native-CLI slots (Kimi/Grok) ahead of per-slot 3P
/// bindings within the SAME provider group (e.g. a native Kimi slot and a
/// Bearer-key Kimi slot), so composition order alone would NOT put the two
/// Kimi accounts in slot-ascending order relative to each other.
pub fn compose_status(
    base_dir: &Path,
    accounts: Vec<AccountInfo>,
    active: Option<AccountNum>,
) -> Vec<AccountStatus> {
    // an internal ticket: salvage per-row. This is a read-only display path, so one corrupt
    // row must cost one row — not every sibling account's quota.
    let quota = state::load_state_salvage(base_dir);

    // `unwrap_or(0)` is a deliberate fail-open, not an oversight: this
    // branch is reachable ONLY if the host clock reports a time before
    // the Unix epoch (1970), which no real OS clock does. If it ever
    // happened, `now_secs = 0` would make every row read Fresh via
    // `poll_freshness`'s `saturating_sub` — but a pre-epoch host clock
    // breaks every other timestamp-dependent behaviour in the process
    // (credential expiry, reset-window countdowns, audit timestamps) at
    // the same moment, so a locally "more correct" fallback here would
    // not make the surrounding system trustworthy. Not fixable at this
    // single call site; documented per `zero-tolerance.md` Rule 5's
    // named-blocker exception rather than left as a silent default.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut result: Vec<AccountStatus> = accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .map(|a| {
            let q = quota.get(a.id);
            let account_num = AccountNum::try_from(a.id).ok();
            let label = if a.label == "unknown" {
                account_num
                    .map(|n| account_label(base_dir, n))
                    .unwrap_or_else(|| a.label.clone())
            } else {
                a.label.clone()
            };

            AccountStatus {
                id: a.id,
                label,
                is_active: active.map(|c| c.get() == a.id).unwrap_or(false),
                five_hour_pct: q
                    .map(|q| q.five_hour_pct())
                    .filter(|p| *p > 0.0 || q.is_some_and(|q| q.five_hour.is_some())),
                five_hour_resets_in: q.and_then(|q| {
                    q.five_hour
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                seven_day_pct: q
                    .map(|q| q.seven_day_pct())
                    .filter(|p| *p > 0.0 || q.is_some_and(|q| q.seven_day.is_some())),
                seven_day_resets_in: q.and_then(|q| {
                    q.seven_day
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                source: a.source,
                surface: a.surface,
                method: a.method,
                balance: q.and_then(|q| q.balance.clone()),
                // Derived from the slot's settings.json env block — the sole
                // source of truth for the spawned `claude`'s cloud routing
                // (an internal ticket). Never stored on AccountInfo.
                backend: crate::providers::settings::backend_for_slot(base_dir, a.id),
                // `q.and_then` short-circuits to `None` when the slot has no
                // quota row at all — the `PollFreshness::NeverPolled` case
                // for "row absent" collapses to the same `None` here as the
                // "row present but never successfully polled" case that
                // `poll_freshness` itself detects from `updated_at <= 0.0`.
                // `is_event_driven_row` gates OUT event-driven Gemini rows
                // BEFORE `poll_freshness` ever sees their `updated_at` — see
                // that function's doc comment for why age-based staleness
                // is meaningless for them.
                stale_secs: q.and_then(|q| {
                    if is_event_driven_row(q) {
                        return None;
                    }
                    match poll_freshness(Some(q.updated_at), now_secs) {
                        PollFreshness::Stale { age_secs } => Some(age_secs),
                        PollFreshness::Fresh | PollFreshness::NeverPolled => None,
                    }
                }),
            }
        })
        .collect();

    // See the doc comment above for the 3-key rationale.
    result.sort_by_key(|a| (a.is_balance_only(), a.provider_group_rank(), a.id));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::BillingMode;
    use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::quota::{AccountQuota, UsageWindow};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn setup(base: &Path, account: u16, pct: f64) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(format!("at-{account}")),
                refresh_token: RefreshToken::new(format!("rt-{account}")),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(&credentials::file::canonical_path(base, target), &creds).unwrap();

        let mut quota = state::load_state_salvage(base);
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: pct,
                    resets_at: 9999999999,
                }),
                ..Default::default()
            },
        );
        state::save_state(base, &quota).unwrap();
    }

    #[test]
    fn show_status_returns_all_accounts() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0);
        setup(dir.path(), 2, 85.0);
        setup(dir.path(), 3, 100.0);

        let active = AccountNum::try_from(2u16).unwrap();
        let status = show_status(dir.path(), Some(active));

        assert_eq!(status.len(), 3);
        assert!(status.iter().find(|s| s.id == 2).unwrap().is_active);
        assert!(!status.iter().find(|s| s.id == 1).unwrap().is_active);
    }

    fn anthropic_status(id: u16) -> AccountStatus {
        AccountStatus {
            id,
            label: "x".into(),
            is_active: false,
            five_hour_pct: Some(20.0),
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        }
    }

    // ── window-vs-balance precedence ─────────────────────────────
    //
    // Billing mode is per-PLAN, not per-provider, so a subscription slot can
    // carry a meaningless balance alongside its real window. Both directions
    // are pinned: over-correcting would hide DeepSeek's credit.

    #[test]
    fn subscription_slot_renders_its_window_not_a_zero_balance() {
        // grok-17's REAL measured shape, 2026-08-03: a 7% weekly window AND
        // a $0.00 balance. It rendered "$0.00 balance" and hid the window.
        let s = AccountStatus {
            label: "grok-17".into(),
            five_hour_pct: None,
            seven_day_pct: Some(7.0),
            seven_day_resets_in: Some(338_821),
            balance: Some(BalanceInfo {
                currency: "USD".into(),
                remaining: 0.0,
            }),
            ..anthropic_status(17)
        };

        // Non-vacuity: the fixture really does carry both signals.
        assert!(s.balance.is_some(), "fixture lost its balance");
        assert!(s.shows_window(), "fixture lost its window");

        let suffix = s.quota_suffix();
        assert!(
            !suffix.contains("0.00") && !suffix.contains("balance"),
            "the meaningless $0.00 balance won over the real 7% window: {suffix}"
        );
        assert!(
            suffix.contains('7'),
            "the 7% weekly window is not rendered: {suffix}"
        );
    }

    #[test]
    fn pay_per_token_slot_still_renders_its_balance() {
        // DeepSeek's REAL measured shape: a balance and NO windows at all.
        // This is the branch the balance render exists for — the fix must not
        // take it away while fixing the subscription case.
        let s = AccountStatus {
            label: "DeepSeek".into(),
            five_hour_pct: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            balance: Some(BalanceInfo {
                currency: "USD".into(),
                remaining: 165.32,
            }),
            ..anthropic_status(12)
        };

        assert!(!s.shows_window(), "fixture should have no window");
        let suffix = s.quota_suffix();
        assert!(
            suffix.contains("165.32"),
            "pay-per-token balance was suppressed: {suffix}"
        );
    }

    #[test]
    fn status_icons_by_usage() {
        let s_low = anthropic_status(1);
        assert_eq!(s_low.five_hour_icon(), "●");

        let s_high = AccountStatus {
            five_hour_pct: Some(90.0),
            ..s_low.clone()
        };
        assert_eq!(s_high.five_hour_icon(), "◐");

        let s_full = AccountStatus {
            five_hour_pct: Some(100.0),
            ..s_low.clone()
        };
        assert_eq!(s_full.five_hour_icon(), "○");

        let s_none = AccountStatus {
            five_hour_pct: None,
            ..s_low
        };
        assert_eq!(s_none.five_hour_icon(), "·");
    }

    /// an internal ticket: a cloud-Claude backend renders ` [vertex]` / ` [bedrock]`; a
    /// `Direct` backend renders no backend tag (byte-identical to pre-an internal ticket
    /// output for every ordinary slot).
    #[test]
    fn surface_tag_cloud_backend_renders_vertex_and_bedrock() {
        let mut s = anthropic_status(1);
        s.backend = Backend::Vertex;
        assert!(
            s.format_line().contains("[vertex]"),
            "missing vertex tag: {}",
            s.format_line()
        );
        s.backend = Backend::Bedrock;
        assert!(
            s.format_line().contains("[bedrock]"),
            "missing bedrock tag: {}",
            s.format_line()
        );
        s.backend = Backend::Direct;
        let line = s.format_line();
        assert!(
            !line.contains("[vertex]") && !line.contains("[bedrock]"),
            "{line}"
        );
    }

    #[test]
    fn format_line_active_marker() {
        let s = AccountStatus {
            id: 3,
            label: "test@example.com".into(),
            is_active: true,
            five_hour_pct: Some(42.0),
            five_hour_resets_in: Some(3600),
            seven_day_pct: Some(15.0),
            seven_day_resets_in: Some(86400),
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(line.starts_with("* #3"));
        assert!(line.contains("test@example.com"));
        assert!(line.contains("42%"));
        assert!(line.contains("15%"));
        // Anthropic rows carry no surface tag — keeps existing output byte-identical.
        assert!(!line.contains("["));
    }

    #[test]
    fn format_line_third_party_minimax_shows_tag_and_api_key_suffix() {
        let s = AccountStatus {
            id: 9,
            label: "MiniMax".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "MiniMax".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(line.contains("#9"), "missing id: {line}");
        assert!(line.contains("[minimax]"), "missing provider tag: {line}");
        assert!(line.contains("(api-key)"), "missing api-key suffix: {line}");
        // 3P rows must NOT render quota placeholders — quota isn't
        // polled for MiniMax/Z.AI/Ollama today, so `5h:—` would imply
        // "no data yet" which is misleading.
        assert!(!line.contains("5h:"), "unexpected quota suffix: {line}");
        assert!(!line.contains("7d:"), "unexpected quota suffix: {line}");
    }

    #[test]
    fn format_line_gemini_oauth_shows_gemini_tag_and_oauth_suffix() {
        let s = AccountStatus {
            id: 13,
            label: "gemini-13".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "code_assist_oauth".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(line.contains("[gemini]"), "missing gemini tag: {line}");
        assert!(line.contains("#13"), "missing slot id: {line}");
        assert!(
            line.contains("(oauth)"),
            "OAuth slot rendered as api-key: {line}"
        );
        assert!(
            !line.contains("(api-key)"),
            "OAuth slot mislabelled: {line}"
        );
    }

    #[test]
    fn format_line_gemini_api_key_keeps_api_key_suffix() {
        let s = AccountStatus {
            id: 13,
            label: "gemini-13".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "api_key".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(
            line.contains("(api-key)"),
            "api-key slot mislabelled: {line}"
        );
    }

    #[test]
    fn format_line_gemini_vertex_sa_shows_vertex_sa_suffix() {
        let s = AccountStatus {
            id: 13,
            label: "gemini-13".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "vertex_sa".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(
            line.contains("(vertex-sa)"),
            "vertex-sa slot mislabelled: {line}"
        );
    }

    // ── Native Kimi/Grok (C4 billing + C5 core badge, an internal journal entry) ────

    fn native_status(id: u16, surface: Surface, label: &str) -> AccountStatus {
        AccountStatus {
            id,
            label: label.into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Native { surface },
            surface,
            method: "native_cli".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        }
    }

    /// C5 (issue 4): the native Kimi surface renders the UPPERCASE ` [KIMI]`
    /// tag — distinct from the lowercase `[codex]`/`[gemini]`/`[minimax]`
    /// tags used by csq-managed-credential surfaces.
    #[test]
    fn surface_tag_native_kimi_renders_uppercase_tag() {
        let s = native_status(7, Surface::Kimi, "kimi-7");
        assert_eq!(s.surface_tag(), " [KIMI]");
        assert_eq!(s.tag_bare(), "[KIMI]");
    }

    /// C5 (issue 4): the native Grok surface renders the UPPERCASE
    /// ` [GROK]` tag.
    #[test]
    fn surface_tag_native_grok_renders_uppercase_tag() {
        let s = native_status(8, Surface::Grok, "grok-8");
        assert_eq!(s.surface_tag(), " [GROK]");
        assert_eq!(s.tag_bare(), "[GROK]");
    }

    /// C4 (issue 3) + C5 (issue 4): the composed status line for a native
    /// Kimi slot carries the ` [KIMI]` tag AND the `(native-cli)`
    /// bound-state suffix (reusing the EXISTING non-polled
    /// subscription-surface code path that Anthropic/Codex quota rendering
    /// does NOT apply to third-party/native rows — see `format_line`'s
    /// `polled` gate) — never a per-token `$`/cost figure, and never the
    /// "unrecognized model" vocabulary. `quota/status.rs` has no cost/
    /// rate-lookup code path at all (confirmed: `rate_for_model_at` is never
    /// called from this module), so this is a structural regression guard
    /// against ever reintroducing one here for a subscription-billed native
    /// surface.
    #[test]
    fn format_line_native_kimi_shows_tag_and_native_cli_suffix_no_cost_warning() {
        let s = native_status(7, Surface::Kimi, "kimi-7");
        let line = s.format_line();
        assert!(line.contains("[KIMI]"), "missing native Kimi tag: {line}");
        assert!(
            line.contains("(native-cli)"),
            "missing native-cli bound-state suffix: {line}"
        );
        assert!(
            !line.contains("(api-key)"),
            "native slot must not be mislabelled api-key: {line}"
        );
        assert!(
            !line.to_lowercase().contains("unrecognized"),
            "native subscription slot must never surface the unrecognized-model warning: {line}"
        );
        assert!(
            !line.contains('$'),
            "native subscription slot must never render a per-token cost figure: {line}"
        );
    }

    /// Same as above for Grok — both native surfaces MUST behave
    /// identically since both classify `BillingMode::Subscription`.
    #[test]
    fn format_line_native_grok_shows_tag_and_native_cli_suffix_no_cost_warning() {
        let s = native_status(8, Surface::Grok, "grok-8");
        let line = s.format_line();
        assert!(line.contains("[GROK]"), "missing native Grok tag: {line}");
        assert!(
            line.contains("(native-cli)"),
            "missing native-cli bound-state suffix: {line}"
        );
        assert!(
            !line.contains("(api-key)"),
            "native slot must not be mislabelled api-key: {line}"
        );
        assert!(
            !line.to_lowercase().contains("unrecognized"),
            "native subscription slot must never surface the unrecognized-model warning: {line}"
        );
        assert!(
            !line.contains('$'),
            "native subscription slot must never render a per-token cost figure: {line}"
        );
    }

    /// C4 (issue 3): `compose_status` carries a native `AccountInfo` (whose
    /// `billing_mode` is `BillingMode::Subscription` per
    /// `discovery::discover_native`) through to `AccountStatus` and renders
    /// it via the SAME non-polled code path as the other non-quota-polled
    /// surfaces — end-to-end proof that the daemon-delegated `/api/accounts`
    /// path and the direct path produce identical native-slot output.
    #[test]
    fn compose_status_native_kimi_slot_renders_kimi_tag() {
        let dir = TempDir::new().unwrap();
        let accounts = vec![AccountInfo {
            id: 7,
            label: "kimi-7".into(),
            oauth_email: None,
            source: AccountSource::Native {
                surface: Surface::Kimi,
            },
            surface: Surface::Kimi,
            method: "native_cli".into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        }];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);
        let line = status[0].format_line();
        assert!(line.contains("[KIMI]"), "missing native Kimi tag: {line}");
    }

    #[test]
    fn format_line_codex_shows_codex_tag_and_quota() {
        let s = AccountStatus {
            id: 4,
            label: "user@openai.test".into(),
            is_active: true,
            five_hour_pct: Some(12.0),
            five_hour_resets_in: Some(1800),
            seven_day_pct: Some(3.0),
            seven_day_resets_in: Some(86400),
            source: AccountSource::Codex,
            surface: Surface::Codex,
            method: "oauth".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(line.starts_with("* #4"), "line: {line}");
        assert!(line.contains("[codex]"), "missing codex tag: {line}");
        // Codex is a polled surface (spec 07 §7.4) so quota suffix
        // must render like Anthropic.
        assert!(line.contains("5h:12%"), "missing 5h quota: {line}");
        assert!(line.contains("7d:3%"), "missing 7d quota: {line}");
    }

    #[test]
    fn show_status_no_accounts() {
        let dir = TempDir::new().unwrap();
        let status = show_status(dir.path(), None);
        assert!(status.is_empty());
    }

    /// `compose_status` is the composition step used by both the
    /// direct path (via [`show_status`]) and the daemon-delegated
    /// path (via `csq status` after parsing `/api/accounts`).
    /// This test feeds it a synthetic account list mirroring the
    /// shape the daemon route returns — validating that the CLI's
    /// daemon path produces identical output to the direct path
    /// for the same `(accounts, quota)` pair.
    #[test]
    fn compose_status_with_daemon_shaped_accounts() {
        let dir = TempDir::new().unwrap();
        // Populate quota file + credentials so compose_status has
        // something to join against.
        setup(dir.path(), 1, 20.0);
        setup(dir.path(), 2, 85.0);

        // Synthetic AccountInfo list as if returned from
        // `GET /api/accounts`. Label is already resolved (daemon
        // hits profiles.json server-side), has_credentials=true.
        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "alice@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: crate::providers::catalog::Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 2,
                label: "bob@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: crate::providers::catalog::Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
        ];

        let active = AccountNum::try_from(2u16).unwrap();
        let status = compose_status(dir.path(), accounts, Some(active));

        assert_eq!(status.len(), 2);
        let first = status.iter().find(|s| s.id == 1).unwrap();
        assert_eq!(first.label, "alice@example.com");
        assert!(!first.is_active);
        let second = status.iter().find(|s| s.id == 2).unwrap();
        assert_eq!(second.label, "bob@example.com");
        assert!(second.is_active);
    }

    /// `compose_status` must filter out accounts with
    /// `has_credentials == false` — these are placeholders the
    /// daemon may list (e.g., after a failed credential parse).
    #[test]
    fn compose_status_filters_accounts_without_credentials() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0);

        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "real@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 7,
                label: "broken@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: false,
                billing_mode: BillingMode::Subscription,
            },
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].id, 1);
    }

    /// Multi-surface coverage: the same mix a real user sees —
    /// Anthropic OAuth on slot 1, Codex OAuth on slot 4, per-slot
    /// MiniMax binding on slot 9, and Ollama (local) on slot 10.
    /// `compose_status` must carry the surface/source through so
    /// `format_line` can render each correctly.
    #[test]
    fn compose_status_multi_surface_mix() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 25.0); // Anthropic quota only
        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "anthro@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 4,
                label: "openai-user".into(),
                oauth_email: None,
                source: AccountSource::Codex,
                surface: Surface::Codex,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 9,
                label: "MiniMax".into(),
                oauth_email: None,
                source: AccountSource::ThirdParty {
                    provider: "MiniMax".into(),
                },
                surface: Surface::ClaudeCode,
                method: "api_key".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 10,
                label: "Ollama".into(),
                oauth_email: None,
                source: AccountSource::ThirdParty {
                    provider: "Ollama".into(),
                },
                surface: Surface::ClaudeCode,
                method: "api_key".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 4, "all four slots must be composed");

        let anth = status.iter().find(|s| s.id == 1).unwrap();
        assert!(matches!(anth.source, AccountSource::Anthropic));
        assert_eq!(anth.surface, Surface::ClaudeCode);

        let codex = status.iter().find(|s| s.id == 4).unwrap();
        assert!(matches!(codex.source, AccountSource::Codex));
        assert_eq!(codex.surface, Surface::Codex);
        assert!(codex.format_line().contains("[codex]"));

        let mm = status.iter().find(|s| s.id == 9).unwrap();
        match &mm.source {
            AccountSource::ThirdParty { provider } => assert_eq!(provider, "MiniMax"),
            other => panic!("expected ThirdParty MiniMax, got {:?}", other),
        }
        assert!(mm.format_line().contains("[minimax]"));

        let ol = status.iter().find(|s| s.id == 10).unwrap();
        match &ol.source {
            AccountSource::ThirdParty { provider } => assert_eq!(provider, "Ollama"),
            other => panic!("expected ThirdParty Ollama, got {:?}", other),
        }
        assert!(ol.format_line().contains("[ollama]"));
    }

    /// Back-compat regression: an AccountStatus JSON written by an
    /// older csq (no `source`/`surface` fields) must deserialise.
    #[test]
    fn account_status_deserializes_without_new_fields() {
        let legacy = r#"{
            "id": 1,
            "label": "alice@example.com",
            "is_active": true,
            "five_hour_pct": 12.0,
            "five_hour_resets_in": 3600,
            "seven_day_pct": 3.0,
            "seven_day_resets_in": 86400
        }"#;
        let parsed: AccountStatus = serde_json::from_str(legacy).expect("legacy JSON parses");
        assert_eq!(parsed.id, 1);
        assert!(matches!(parsed.source, AccountSource::Anthropic));
        assert_eq!(parsed.surface, Surface::ClaudeCode);
    }

    // ── Table renderer ───────────────────────────────────────────────

    #[test]
    fn usage_bar_resolution() {
        assert_eq!(usage_bar(0.0, 4), "░░░░"); // idle
        assert_eq!(usage_bar(2.0, 4), "▏░░░"); // nonzero shows ≥1 eighth
        assert_eq!(usage_bar(50.0, 4), "██░░"); // round(0.5*32)=16 → 2 full
        assert_eq!(usage_bar(100.0, 4), "████");
        assert_eq!(usage_bar(150.0, 4), "████"); // clamps over 100
    }

    #[allow(clippy::too_many_arguments)]
    fn tbl_row(
        id: u16,
        label: &str,
        active: bool,
        fh: Option<f64>,
        fh_r: Option<u64>,
        sd: Option<f64>,
        sd_r: Option<u64>,
        source: AccountSource,
        surface: Surface,
        method: &str,
    ) -> AccountStatus {
        AccountStatus {
            id,
            label: label.into(),
            is_active: active,
            five_hour_pct: fh,
            five_hour_resets_in: fh_r,
            seven_day_pct: sd,
            seven_day_resets_in: sd_r,
            source,
            surface,
            method: method.into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        }
    }

    #[test]
    fn render_table_shows_both_resets_aligns_and_flags() {
        let accts = vec![
            tbl_row(
                1,
                "a@x.com",
                false,
                Some(2.0),
                Some(11_520), // 3h12m
                Some(2.0),
                Some(446_400), // 5d4h
                AccountSource::Anthropic,
                Surface::ClaudeCode,
                "oauth",
            ),
            tbl_row(
                2,
                "bob@example.com",
                true,
                None, // idle 5h
                None,
                Some(100.0),
                Some(194_400), // 2d6h
                AccountSource::Anthropic,
                Surface::ClaudeCode,
                "oauth",
            ),
            tbl_row(
                10,
                "gemini-10",
                false,
                None,
                None,
                None,
                None,
                AccountSource::Gemini,
                Surface::Gemini,
                "oauth",
            ),
        ];
        let active = AccountNum::try_from(2u16).unwrap();
        let out = render_status_table(&accts, Some(active), "Mon 09:00");

        // Header summary.
        assert!(
            out.contains("csq · 3 slots · #2 active · Mon 09:00"),
            "{out}"
        );
        // BOTH windows now show a reset countdown — the gap this redesign closes
        // (the old format printed a 7d percentage with no reset time).
        assert!(out.contains("3h12m"), "5h reset missing: {out}");
        assert!(out.contains("5d4h"), "7d reset missing (the bug): {out}");
        assert!(out.contains("2d6h"), "capped row 7d reset: {out}");
        // Weekly-cap flag + idle 5h on the exhausted account.
        assert!(out.contains("⛔"), "cap flag: {out}");
        assert!(out.contains("idle"), "idle 5h cell: {out}");
        // Non-polled Gemini row renders bound state, not quota placeholders.
        assert!(out.contains("oauth — not quota-polled"), "{out}");
        // Footer legend appears because a row is capped.
        assert!(out.contains("⛔ weekly cap reached"), "{out}");

        // Active marker on slot 2 only.
        let active_line = out.lines().find(|l| l.contains("bob@example.com")).unwrap();
        assert!(
            active_line.trim_start().starts_with("▸"),
            "missing active marker: {active_line:?}"
        );
        let inactive_line = out.lines().find(|l| l.contains("a@x.com")).unwrap();
        assert!(
            !inactive_line.trim_start().starts_with("▸"),
            "unexpected active marker: {inactive_line:?}"
        );

        // Alignment: the "5H" column-header label and each polled row's usage
        // bar begin at the same character column.
        let header = out.lines().find(|l| l.contains("ACCOUNT")).unwrap();
        let col5 = header.chars().collect::<Vec<_>>();
        let h5 = col5
            .windows(2)
            .position(|w| w == ['5', 'H'])
            .expect("5H header");
        let row1 = out.lines().find(|l| l.contains("a@x.com")).unwrap();
        assert_eq!(
            row1.chars().nth(h5),
            Some('▏'),
            "5h bar misaligned with header: {row1:?}"
        );
    }

    #[test]
    fn render_table_no_flag_no_legend() {
        // No account above 80% weekly → no legend footer.
        let accts = vec![tbl_row(
            1,
            "a@x.com",
            true,
            Some(10.0),
            Some(3600),
            Some(20.0),
            Some(86_400),
            AccountSource::Anthropic,
            Surface::ClaudeCode,
            "oauth",
        )];
        let active = AccountNum::try_from(1u16).unwrap();
        let out = render_status_table(&accts, Some(active), "Tue 12:00");
        assert!(!out.contains("weekly cap reached"), "{out}");
        assert!(!out.contains("⛔"), "{out}");
        assert!(!out.contains('⚠'), "{out}");
    }

    // ── Native Grok billing display tests ────────────────────────────

    /// A native Grok slot whose billing poller has written a credit
    /// balance renders the real figure instead of the
    /// `native-cli — not quota-polled` placeholder. This is the
    /// end-to-end proof for the renderer half of Grok quota polling:
    /// `usage_poller::grok` writes `AccountQuota.balance`, `compose_status`
    /// copies it onto `AccountStatus`, and both render paths pick the
    /// balance branch ahead of the bound-state fallback.
    #[test]
    fn format_line_native_grok_with_balance_renders_amount_not_placeholder() {
        let mut s = native_status(17, Surface::Grok, "grok-17");
        s.balance = Some(BalanceInfo {
            currency: "USD".into(),
            remaining: 187.5,
        });
        let line = s.format_line();
        assert!(
            line.contains("$187.50"),
            "balance missing from line: {line}"
        );
        assert!(line.contains("[GROK]"), "missing native Grok tag: {line}");
        assert!(
            !line.contains("not quota-polled"),
            "polled Grok slot must not show the not-polled text: {line}"
        );
        assert!(
            !line.contains("(native-cli)"),
            "polled Grok slot must not fall back to the bound-state suffix: {line}"
        );
    }

    /// The table path (`csq status`) renders the same balance — the
    /// `balance` branch is checked before `shows_quota()`, so a Grok row
    /// never degrades into empty `idle`/`—` 5h/7d blocks it has no data
    /// for. Grok has no 5h/7d windows at all (monthly credit cycle).
    #[test]
    fn status_table_native_grok_balance_renders_and_omits_window_blocks() {
        let mut s = native_status(17, Surface::Grok, "grok-17");
        s.balance = Some(BalanceInfo {
            currency: "USD".into(),
            remaining: 187.5,
        });
        let out = render_status_table(&[s], None, "12:00");
        assert!(
            out.contains("$187.50 balance"),
            "table missing balance: {out}"
        );
        assert!(
            !out.contains("not quota-polled"),
            "table must not show the not-polled text for a polled slot: {out}"
        );
        assert!(
            !out.contains("idle"),
            "Grok has no 5h window — must not render an idle block: {out}"
        );
    }

    /// Honest-absence guard: a native Grok slot with NO polled balance
    /// keeps the `native-cli` bound-state text. The poller writes no
    /// balance when the response carries no `prepaidBalance`, so this is
    /// the rendered result of "no data" — never a fabricated `$0.00`.
    #[test]
    fn format_line_native_grok_without_balance_keeps_bound_state() {
        let s = native_status(17, Surface::Grok, "grok-17");
        let line = s.format_line();
        assert!(
            line.contains("(native-cli)"),
            "unpolled Grok slot must keep the native-cli suffix: {line}"
        );
        assert!(
            !line.contains('$'),
            "absent balance must never render as a dollar figure: {line}"
        );
    }

    // ── DeepSeek balance display tests ───────────────────────────────

    /// (c) A DeepSeek slot with a polled balance renders `$197.15` in the
    /// statusline suffix — not `(api-key)` or `not quota-polled`.
    #[test]
    fn format_line_deepseek_balance_renders_dollar_amount() {
        let s = AccountStatus {
            id: 7,
            label: "DeepSeek".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "DeepSeek".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: Some(BalanceInfo {
                currency: "USD".into(),
                remaining: 197.15,
            }),
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        assert!(
            line.contains("$197.15"),
            "balance missing from line: {line}"
        );
        // Must NOT fall back to the unpolled bound-state suffix.
        assert!(
            !line.contains("(api-key)"),
            "unexpected api-key suffix on balanced row: {line}"
        );
        assert!(
            !line.contains("not quota-polled"),
            "unexpected not-polled text: {line}"
        );
    }

    /// (c) A DeepSeek slot with NO balance yet renders the bound-state suffix.
    #[test]
    fn format_line_deepseek_no_balance_renders_bound_state() {
        let s = AccountStatus {
            id: 7,
            label: "DeepSeek".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "DeepSeek".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        };
        let line = s.format_line();
        // No balance → fallback to bound-state.
        assert!(
            line.contains("(api-key)"),
            "expected api-key suffix: {line}"
        );
        assert!(
            !line.contains('$'),
            "unexpected dollar sign on unpolled row: {line}"
        );
    }

    /// (c) Table renderer renders `$197.15 balance` in the body column.
    #[test]
    fn render_table_deepseek_balance_in_body() {
        let s = AccountStatus {
            id: 7,
            label: "DeepSeek".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "DeepSeek".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: Some(BalanceInfo {
                currency: "USD".into(),
                remaining: 197.15,
            }),
            backend: Backend::Direct,
            stale_secs: None,
        };
        let out = render_status_table(&[s], None, "Mon 09:00");
        assert!(out.contains("$197.15 balance"), "table body: {out}");
        // Must not contain the unpolled text.
        assert!(
            !out.contains("not quota-polled"),
            "unexpected not-polled text: {out}"
        );
    }

    /// C4 (issue 3) + C5 (issue 4): `csq status` table rendering for a
    /// native Kimi slot with no quota data — `render_status_table` uses
    /// `bound_state_line` (distinct from `format_line`'s `bound_state_suffix`,
    /// both fixed in this shard), and the `[KIMI]` tag renders in the
    /// ACCOUNT column via `tag_bare`. Never a cost/`$`/"unrecognized" artifact.
    #[test]
    fn render_table_native_kimi_shows_tag_and_native_cli_bound_state() {
        let s = native_status(7, Surface::Kimi, "kimi-7");
        let out = render_status_table(&[s], None, "Mon 09:00");
        assert!(out.contains("[KIMI]"), "table body missing tag: {out}");
        assert!(
            out.contains("native-cli — not quota-polled"),
            "table body missing native-cli bound-state line: {out}"
        );
        assert!(
            !out.contains("(api-key)"),
            "native slot must not be mislabelled api-key in table: {out}"
        );
        assert!(
            !out.to_lowercase().contains("unrecognized"),
            "native subscription slot must never surface the unrecognized-model warning: {out}"
        );
    }

    // ── poll_freshness / stale-row diagnostic (2026-08-02 Grok slot-17 incident) ──

    #[test]
    fn poll_freshness_no_row_is_never_polled() {
        assert_eq!(poll_freshness(None, 1_000_000), PollFreshness::NeverPolled);
    }

    /// `AccountQuota::default().updated_at == 0.0` — a row that PHYSICALLY
    /// exists on disk (e.g. a rebind-cleared row, `bind_provider_to_slot`)
    /// but has never seen a successful poll must classify identically to
    /// "row absent", not as an implausible multi-decade age.
    #[test]
    fn poll_freshness_default_sentinel_zero_is_never_polled() {
        assert_eq!(
            poll_freshness(Some(0.0), 4_102_444_800),
            PollFreshness::NeverPolled
        );
    }

    #[test]
    fn poll_freshness_fresh_within_threshold() {
        let now = 10_000u64;
        let updated_at = (now - 300) as f64; // 5 minutes ago
        assert_eq!(poll_freshness(Some(updated_at), now), PollFreshness::Fresh);
    }

    /// Pins [`STALE_THRESHOLD_SECS`] to the poller constants it was
    /// derived FROM, so the derivation cannot silently rot when the
    /// cadence changes.
    ///
    /// A threshold is not correct because a test passes with it
    /// (`tooling-self-verification.md` Rule 3) — it is correct only while
    /// the two outcomes it separates stay where the derivation put them.
    /// Both of those positions are functions of the poller's constants, so
    /// this test asserts the RELATIONSHIPS rather than re-stating 3600,
    /// matching the classifier's STRICT `>` comparison (an earlier version
    /// of this test used `<=` where the classifier uses `>`, which pinned
    /// a boundary claim that was actually false — see the doc comment's
    /// "Corrected 2026-08-02" note). Changing `POLL_INTERVAL_3P` or
    /// `FAILURE_COOLDOWN` breaks this test and forces the doc comment to
    /// be re-derived.
    #[test]
    fn stale_threshold_is_derived_from_the_live_poller_cadence() {
        use crate::daemon::usage_poller::{FAILURE_COOLDOWN, POLL_INTERVAL, POLL_INTERVAL_3P};

        let tick = POLL_INTERVAL.as_secs();
        let tick_3p = POLL_INTERVAL_3P.as_secs();
        let cooldown = FAILURE_COOLDOWN.as_secs();

        // Premise 1: a failure cooldown must never suppress the next 3P
        // attempt. If it could, every row-age bound below gains an extra
        // period and the derivation is wrong, not merely tight.
        assert!(
            cooldown < tick_3p,
            "FAILURE_COOLDOWN ({cooldown}s) must stay below POLL_INTERVAL_3P ({tick_3p}s), \
             or a cooldown suppresses a 3P attempt and every bound in \
             STALE_THRESHOLD_SECS's derivation shifts by one period"
        );

        // Premise 2: the 3P branch is gated inside the main loop, so the
        // ASSUMED (not structurally proven — see the doc comment) realised
        // period is bounded above by tick_3p + tick, and structurally
        // bounded below by tick_3p itself.
        let max_period = tick_3p + tick;

        // Two consecutive failures (N=2): row age at the next success is
        // `3 * p` with `p < max_period` STRICTLY (Premise 2's bound is
        // itself an exclusive upper bound on the realised period), so the
        // age is STRICTLY below `3 * max_period` — not merely "at" it.
        // The threshold MUST sit at-or-above that exclusive bound so this
        // case ALWAYS reads Fresh under the classifier's strict `>`.
        let two_glitch_exclusive_bound = 3 * max_period;
        assert!(
            STALE_THRESHOLD_SECS >= two_glitch_exclusive_bound,
            "STALE_THRESHOLD_SECS ({STALE_THRESHOLD_SECS}s) must be >= the two-glitch \
             exclusive upper bound ({two_glitch_exclusive_bound}s = 3 x ({tick_3p} + {tick})), \
             or two consecutive transient poll failures can render a stale marker on a \
             healthy slot"
        );

        // Three consecutive failures (N=3): row age at the next success is
        // `4 * p` with `p >= tick_3p` (Premise 2's STRUCTURAL lower
        // bound). The MINIMUM possible age in that range is `4 * tick_3p`
        // — the one case that still reads Fresh under a strict `>`
        // classifier. The threshold MUST sit at-or-below that minimum, or
        // even the FASTEST possible 3-glitch drift pattern would be
        // silently forgiven as Fresh.
        let three_glitch_minimum = 4 * tick_3p;
        assert!(
            STALE_THRESHOLD_SECS <= three_glitch_minimum,
            "STALE_THRESHOLD_SECS ({STALE_THRESHOLD_SECS}s) must be <= the three-glitch \
             minimum age ({three_glitch_minimum}s = 4 x {tick_3p}), or three consecutive \
             poll failures at the fastest realised cadence would never trip Stale"
        );

        // Today's constants make these two bounds coincide exactly at
        // 3600s (900 * 4 == 1200 * 3, because POLL_INTERVAL_3P is exactly
        // 3x POLL_INTERVAL) — pin that coincidence explicitly so a change
        // to either constant that breaks it is caught here, not silently
        // by a widened (or emptied) valid range.
        assert_eq!(
            two_glitch_exclusive_bound, three_glitch_minimum,
            "the two derived bounds no longer coincide — STALE_THRESHOLD_SECS's single \
             pinned value ({STALE_THRESHOLD_SECS}s) may no longer sit exactly at both; \
             re-derive the doc comment's table for the (now nonzero) valid range \
             [{two_glitch_exclusive_bound}s, {three_glitch_minimum}s]"
        );

        // Premise 3 (fast cadence — Anthropic/Codex/Gemini Code-Assist
        // OAuth): the OPPOSITE relationship from Premise 1. On the 3P
        // cadence a cooldown can never suppress a tick; on the fast
        // cadence it ALWAYS does, because FAILURE_COOLDOWN exceeds
        // POLL_INTERVAL. This is a genuinely different regime, not a
        // scaled-down copy of the 3P derivation, and it MUST be asserted
        // explicitly — a constant change that flips this relationship
        // (e.g. FAILURE_COOLDOWN dropped to <= POLL_INTERVAL) silently
        // invalidates the whole fast-cadence section of the doc comment
        // without tripping any assertion above.
        assert!(
            cooldown > tick,
            "FAILURE_COOLDOWN ({cooldown}s) must stay ABOVE POLL_INTERVAL ({tick}s) for the \
             fast-cadence derivation to hold — if this flips, the fast cadence behaves like \
             the 3P cadence instead (cooldown never suppresses a tick) and the doc comment's \
             fast-cadence section must be rewritten, not just re-numbered"
        );

        // Realised period between fast-cadence retry attempts once a
        // cooldown is active: structurally >= cooldown (cannot retry
        // before the account's own cooldown expires), assumed < cooldown
        // + tick (one extra tick of iteration slop, same assumption as
        // Premise 2 — NOT structurally proven, see the doc comment).
        let fast_period_max = cooldown + tick;

        // N=3 consecutive fast-cadence failures ALWAYS clears: age is
        // `tick + 3 * p_fast` with `p_fast < fast_period_max` strictly,
        // so age is strictly below `tick + 3 * fast_period_max`.
        let fast_three_glitch_worst_case = tick + 3 * fast_period_max;
        assert!(
            STALE_THRESHOLD_SECS > fast_three_glitch_worst_case,
            "STALE_THRESHOLD_SECS ({STALE_THRESHOLD_SECS}s) must exceed the fast-cadence \
             three-glitch worst case ({fast_three_glitch_worst_case}s = {tick} + 3 x \
             ({cooldown} + {tick})), or three consecutive fast-cadence poll failures can \
             render a stale marker on a healthy slot"
        );

        // N=6 consecutive fast-cadence failures ALWAYS trips: age is
        // `tick + 6 * p_fast` with `p_fast >= cooldown` (structural
        // minimum, achievable), so the MINIMUM possible age at N=6 is
        // `tick + 6 * cooldown`.
        let fast_six_glitch_minimum = tick + 6 * cooldown;
        assert!(
            STALE_THRESHOLD_SECS < fast_six_glitch_minimum,
            "STALE_THRESHOLD_SECS ({STALE_THRESHOLD_SECS}s) must be less than the \
             fast-cadence six-glitch minimum age ({fast_six_glitch_minimum}s = {tick} + 6 x \
             {cooldown}), or six consecutive fast-cadence poll failures at the fastest \
             realised cadence would never trip Stale"
        );

        // Premise 4 (Codex — a THIRD regime, NOT the fast-cadence one).
        //
        // Codex polls on POLL_INTERVAL like Anthropic, but its retries are
        // gated by its OWN circuit breaker, not by FAILURE_COOLDOWN:
        // `codex::tick` takes `cfg.codex_breakers` and the module contains
        // no reference to FAILURE_COOLDOWN at all. So Premise 3's
        // derivation — which assumes a cooldown gates EVERY retry — does
        // not describe Codex, and every constant it pins is irrelevant to
        // this surface.
        //
        // Until this block existed, Codex's numbers happened to land
        // inside the fast-cadence envelope by coincidence and NOTHING
        // asserted it: a change to any CODEX_BREAKER_* constant would have
        // silently invalidated the claim with every test still green.
        // That is exactly the shape `tooling-self-verification.md` Rule 3
        // names — a constant is correct only if it separates the two
        // outcomes it exists to separate, never because a test passed
        // with it.
        use crate::daemon::usage_poller::codex::{
            CODEX_BREAKER_BASE_COOLDOWN, CODEX_BREAKER_FAIL_THRESHOLD, CODEX_BREAKER_MAX_COOLDOWN,
        };
        let breaker_trips_at = u64::from(CODEX_BREAKER_FAIL_THRESHOLD);
        let breaker_base = CODEX_BREAKER_BASE_COOLDOWN.as_secs();
        let breaker_max = CODEX_BREAKER_MAX_COOLDOWN.as_secs();

        // 4a: the first `breaker_trips_at` failures are UNGATED — they
        // retry on the bare tick. If this dropped to 1 the surface would
        // collapse into Premise 3's regime and the ages below are wrong.
        assert!(
            breaker_trips_at > 1,
            "CODEX_BREAKER_FAIL_THRESHOLD ({breaker_trips_at}) must exceed 1, or Codex \
             retries are gated from the FIRST failure and its derivation becomes the \
             fast-cadence one (Premise 3) rather than the ungated-prefix one below"
        );

        // 4b: once tripped, the cooldown must actually suppress ticks —
        // otherwise the breaker is decorative and Codex never slows down.
        assert!(
            breaker_base > tick,
            "CODEX_BREAKER_BASE_COOLDOWN ({breaker_base}s) must exceed POLL_INTERVAL \
             ({tick}s), or a tripped breaker suppresses no tick and the post-trip ages \
             below collapse back to the bare cadence"
        );

        // 4c: the cooldown doubles per failure past the trip, capped at
        // MAX. The two ages below use `base` then `2 * base`, so the cap
        // must not bind that early or the arithmetic is wrong.
        assert!(
            2 * breaker_base <= breaker_max,
            "CODEX_BREAKER_MAX_COOLDOWN ({breaker_max}s) must admit at least one doubling \
             of CODEX_BREAKER_BASE_COOLDOWN ({breaker_base}s), or the cap binds before the \
             second trip and the six-glitch age below is not base + 2 x base"
        );

        // Row age when a glitch episode of exactly `breaker_trips_at`
        // failures recovers: that many ungated ticks, then the base
        // cooldown before the next (successful) attempt. This case MUST
        // still read Fresh.
        let codex_trip_glitch_age = breaker_trips_at * tick + breaker_base;
        assert!(
            STALE_THRESHOLD_SECS > codex_trip_glitch_age,
            "STALE_THRESHOLD_SECS ({STALE_THRESHOLD_SECS}s) must exceed the Codex \
             {breaker_trips_at}-glitch recovery age ({codex_trip_glitch_age}s = \
             {breaker_trips_at} x {tick} + {breaker_base}), or a transient Codex episode \
             that recovers renders a stale marker on a healthy slot"
        );

        // One failure further doubles the cooldown, so the next attempt
        // lands a full `2 * base` later. That case MUST trip Stale.
        let codex_one_past_trip_age = codex_trip_glitch_age + 2 * breaker_base;
        assert!(
            STALE_THRESHOLD_SECS < codex_one_past_trip_age,
            "STALE_THRESHOLD_SECS ({STALE_THRESHOLD_SECS}s) must be below the Codex \
             one-past-trip age ({codex_one_past_trip_age}s = {codex_trip_glitch_age} + 2 x \
             {breaker_base}), or a genuinely dead Codex token never trips Stale"
        );
    }

    /// Boundary, healthy side: `age_secs == STALE_THRESHOLD_SECS` is NOT
    /// `> threshold` — still `Fresh`. This is the exact edge the
    /// healthy/broken derivation on [`STALE_THRESHOLD_SECS`] separates.
    #[test]
    fn poll_freshness_boundary_exactly_at_threshold_is_fresh() {
        let now = 100_000u64;
        let updated_at = (now - STALE_THRESHOLD_SECS) as f64;
        assert_eq!(poll_freshness(Some(updated_at), now), PollFreshness::Fresh);
    }

    /// Boundary, broken side: one second past the threshold flips to
    /// `Stale`. Paired with the test above, this pins the exact edge on
    /// both sides.
    #[test]
    fn poll_freshness_boundary_one_second_past_threshold_is_stale() {
        let now = 100_000u64;
        let updated_at = (now - STALE_THRESHOLD_SECS - 1) as f64;
        match poll_freshness(Some(updated_at), now) {
            PollFreshness::Stale { age_secs } => assert_eq!(age_secs, STALE_THRESHOLD_SECS + 1),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// The 2026-08-02 Grok slot-17 incident this rule exists to catch:
    /// 15.6h stale, rendering $0.00 with no indication the row was dead.
    #[test]
    fn poll_freshness_stale_at_observed_incident_magnitude() {
        let now = 1_000_000_000u64;
        let age = 56_160u64; // 15.6h
        let updated_at = (now - age) as f64;
        match poll_freshness(Some(updated_at), now) {
            PollFreshness::Stale { age_secs } => assert_eq!(age_secs, age),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// Clock skew WITHIN [`FUTURE_SKEW_TOLERANCE_SECS`]: `updated_at`
    /// modestly ahead of `now_secs` must not panic or underflow —
    /// `saturating_sub` floors the age at 0, reading as Fresh. This is
    /// the ordinary-NTP-jitter case the tolerance exists to absorb.
    #[test]
    fn poll_freshness_future_updated_at_within_tolerance_does_not_panic_and_reads_fresh() {
        let now = 1_000u64;
        let updated_at = (now + FUTURE_SKEW_TOLERANCE_SECS) as f64; // exactly at the tolerance edge
        assert_eq!(poll_freshness(Some(updated_at), now), PollFreshness::Fresh);
    }

    /// Clock skew BEYOND [`FUTURE_SKEW_TOLERANCE_SECS`] is corrupt data
    /// (a bad-clock write, since corrected), not a healthy fresh row —
    /// classifies `NeverPolled` (no marker, no fabricated age) rather
    /// than reading Fresh for as long as `now_secs` has not caught up to
    /// the bad timestamp. Non-vacuity: this is the guard Fix 3 adds;
    /// deleting the `updated_secs > now_secs.saturating_add(...)` check
    /// in `poll_freshness` makes this test fail (see the PR's
    /// non-vacuity transcript — confirmed by hand, restored immediately).
    #[test]
    fn poll_freshness_future_updated_at_beyond_tolerance_is_never_polled_not_fresh_forever() {
        let now = 1_000u64;
        // 30 days ahead — the corrupted-clock magnitude named in
        // FUTURE_SKEW_TOLERANCE_SECS's doc comment.
        let updated_at = (now + 30 * 24 * 3600) as f64;
        assert_eq!(
            poll_freshness(Some(updated_at), now),
            PollFreshness::NeverPolled,
            "a row whose updated_at is implausibly far in the future must not silently \
             read Fresh — that would mask a genuinely dead poller for as long as now_secs \
             has not caught up to the bad timestamp"
        );
    }

    /// Writes a quota row with an explicit `updated_at` (unlike `setup`,
    /// which always leaves it at the `AccountQuota::default()` sentinel
    /// `0.0`) so staleness tests can control the row's age directly.
    fn setup_with_updated_at(base: &Path, account: u16, updated_at: f64) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(format!("at-{account}")),
                refresh_token: RefreshToken::new(format!("rt-{account}")),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(&credentials::file::canonical_path(base, target), &creds).unwrap();

        let mut quota = state::load_state_salvage(base);
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: 5.0,
                    resets_at: 9_999_999_999,
                }),
                updated_at,
                ..Default::default()
            },
        );
        state::save_state(base, &quota).unwrap();
    }

    fn now_secs_f64() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    fn single_anthropic_account(id: u16, label: &str) -> AccountInfo {
        AccountInfo {
            id,
            label: label.into(),
            oauth_email: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        }
    }

    /// End-to-end: a slot whose last successful poll is 2h old (comfortably
    /// past `STALE_THRESHOLD_SECS` = 1h) renders `stale 2h` in BOTH the
    /// `format_line` statusline shape and the `csq status` table body —
    /// the exact operator signal the 2026-08-02 Grok-17 incident lacked.
    #[test]
    fn compose_status_marks_stale_row_when_poll_stopped() {
        let dir = TempDir::new().unwrap();
        setup_with_updated_at(dir.path(), 1, now_secs_f64() - 7_200.0);

        let accounts = vec![single_anthropic_account(1, "grok-1")];
        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);

        let stale_secs = status[0]
            .stale_secs
            .expect("row 2h past last poll must be classified stale");
        assert!(
            (7_100..=7_300).contains(&stale_secs),
            "unexpected staleness age: {stale_secs}"
        );

        let line = status[0].format_line();
        assert!(line.contains("stale 2h"), "missing stale marker: {line}");

        let table = render_status_table(&status, None, "Mon 09:00");
        assert!(
            table.contains("stale 2h"),
            "table missing stale marker: {table}"
        );
    }

    /// A row updated 1 minute ago is comfortably `Fresh` — no marker on
    /// either renderer.
    ///
    /// FIX 10 (2026-08-02, second redteam lens): carries a SIBLING slot
    /// with a genuinely 2h-stale row in the SAME `compose_status` call.
    /// A bare `assert!(stale_secs.is_none())` on a lone fresh row has no
    /// independent killing power — a mutant that hardcodes
    /// `stale_secs: None` for every row (ignoring `poll_freshness`
    /// entirely) also passes it. The sibling assertion (`Some(_)` on the
    /// stale slot, in the SAME call) fails under that exact mutant, so
    /// this test now exercises both branches of the classifier, not just
    /// the one that happens to agree with a stub.
    #[test]
    fn compose_status_fresh_row_has_no_stale_marker() {
        let dir = TempDir::new().unwrap();
        setup_with_updated_at(dir.path(), 1, now_secs_f64() - 60.0);
        setup_with_updated_at(dir.path(), 2, now_secs_f64() - 7_200.0); // sibling: genuinely stale

        let accounts = vec![
            single_anthropic_account(1, "fresh-1"),
            single_anthropic_account(2, "stale-2"),
        ];
        let status = compose_status(dir.path(), accounts, None);
        let fresh = status.iter().find(|s| s.id == 1).unwrap();
        let stale = status.iter().find(|s| s.id == 2).unwrap();

        assert!(fresh.stale_secs.is_none(), "{:?}", fresh.stale_secs);
        assert!(!fresh.format_line().contains("stale"));
        assert!(
            stale.stale_secs.is_some(),
            "sibling stale row must classify Some(_) — a stub hardcoding None for \
             every row would pass the fresh-row assertion above but fail here"
        );
        assert!(stale.format_line().contains("stale"));

        let table = render_status_table(&status, None, "Mon 09:00");
        assert!(
            !table
                .lines()
                .any(|l| l.contains("fresh-1") && l.contains("stale")),
            "{table}"
        );
        assert!(
            table
                .lines()
                .any(|l| l.contains("stale-2") && l.contains("stale")),
            "{table}"
        );
    }

    /// A slot with credentials but NO quota.json row at all (never polled
    /// — e.g. a freshly created slot) must render with NO stale marker,
    /// not be mislabelled as stale-since-epoch.
    ///
    /// FIX 10 (2026-08-02, second redteam lens): same independent-killing-
    /// power fix as the test above — a sibling slot with a real quota row
    /// gets polled and left stale, in the SAME `compose_status` call, so
    /// an "always None" stub fails on the sibling even though it would
    /// pass the never-polled assertion alone.
    #[test]
    fn compose_status_never_polled_row_has_no_stale_marker() {
        let dir = TempDir::new().unwrap();
        let target = AccountNum::try_from(1u16).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at-1".to_string()),
                refresh_token: RefreshToken::new("rt-1".to_string()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(
            &credentials::file::canonical_path(dir.path(), target),
            &creds,
        )
        .unwrap();
        // No state::save_state call for slot 1 — quota.json absent for it.
        // Sibling slot 2 DOES have a quota row, genuinely stale.
        setup_with_updated_at(dir.path(), 2, now_secs_f64() - 7_200.0);

        let accounts = vec![
            single_anthropic_account(1, "never-polled-1"),
            single_anthropic_account(2, "stale-2"),
        ];
        let status = compose_status(dir.path(), accounts, None);
        let never_polled = status.iter().find(|s| s.id == 1).unwrap();
        let stale = status.iter().find(|s| s.id == 2).unwrap();

        assert!(
            never_polled.stale_secs.is_none(),
            "never-polled row must not be marked stale: {:?}",
            never_polled.stale_secs
        );
        assert!(!never_polled.format_line().contains("stale"));
        assert!(
            stale.stale_secs.is_some(),
            "sibling stale row must classify Some(_) — a stub hardcoding None for \
             every row would pass the never-polled assertion above but fail here"
        );
        assert!(stale.format_line().contains("stale"));
    }

    /// Writes an arbitrary `AccountQuota` row directly — for shapes
    /// `setup`/`setup_with_updated_at` don't cover (event-driven Gemini
    /// counter rows, native-CLI balance rows).
    fn setup_quota_row(base: &Path, account: u16, quota_row: AccountQuota) {
        let mut quota = state::load_state_salvage(base);
        quota.set(account, quota_row);
        state::save_state(base, &quota).unwrap();
    }

    /// FIX 1 (2026-08-02 redteam, HIGH): an event-driven Gemini
    /// ApiKey/VertexSa row (`kind = "counter"`) must NEVER be marked
    /// stale by age, no matter how old `updated_at` is — its
    /// `updated_at` only advances when the user's OWN traffic produces
    /// an event; an idle-but-healthy slot has no poller tick to "miss".
    /// Before this fix, `compose_status` applied `poll_freshness`
    /// uniformly to every row, so a healthy Gemini API-key slot used
    /// once at 09:00 would render `stale 5h` by 14:00 — self-
    /// contradictory alongside the `api-key — not quota-polled`
    /// bound-state text it renders in the SAME line, and a false
    /// daily-recurring marker that trains the operator to ignore it.
    #[test]
    fn compose_status_gemini_counter_row_never_marked_stale_when_idle() {
        let dir = TempDir::new().unwrap();
        // 10 hours old — comfortably past STALE_THRESHOLD_SECS, which
        // WOULD trip if this row were poll-cadence.
        setup_quota_row(
            dir.path(),
            13,
            AccountQuota {
                surface: "gemini".into(),
                kind: "counter".into(),
                updated_at: now_secs_f64() - 36_000.0,
                counter: Some(crate::quota::CounterState {
                    requests_today: 4,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let accounts = vec![AccountInfo {
            id: 13,
            label: "gemini-13".into(),
            oauth_email: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "api_key".into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        }];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);
        assert!(
            status[0].stale_secs.is_none(),
            "event-driven Gemini counter row must never be marked stale by age: {:?}",
            status[0].stale_secs
        );
        assert!(!status[0].format_line().contains("stale"));
        let table = render_status_table(&status, None, "Mon 09:00");
        assert!(!table.contains("stale"), "{table}");
    }

    /// FIX 5 (2026-08-02 redteam): regression test for the ACTUAL
    /// incident shape. Every other end-to-end staleness test in this
    /// module uses `AccountSource::Anthropic` — but the incident that
    /// motivated this whole feature was a native/3P Grok slot (balance
    /// row, no 5h/7d window) sitting stale for 15.6h. This pins that
    /// exact shape end-to-end: a native Grok slot's balance row, once
    /// its poller stops updating, renders `stale <age>` on both
    /// renderers — the diagnostic the incident lacked.
    #[test]
    fn compose_status_marks_stale_row_for_native_grok_balance_slot() {
        let dir = TempDir::new().unwrap();
        setup_quota_row(
            dir.path(),
            17,
            AccountQuota {
                surface: "grok".into(),
                kind: "balance".into(),
                updated_at: now_secs_f64() - 56_160.0, // 15.6h, the incident magnitude
                balance: Some(BalanceInfo {
                    currency: "USD".into(),
                    remaining: 187.5,
                }),
                ..Default::default()
            },
        );

        let accounts = vec![AccountInfo {
            id: 17,
            label: "grok-17".into(),
            oauth_email: None,
            source: AccountSource::Native {
                surface: Surface::Grok,
            },
            surface: Surface::Grok,
            method: "native_cli".into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        }];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);
        let stale_secs = status[0]
            .stale_secs
            .expect("15.6h-stale native Grok balance row must be classified stale");
        assert!(
            (56_000..=56_300).contains(&stale_secs),
            "unexpected staleness age: {stale_secs}"
        );

        let line = status[0].format_line();
        assert!(line.contains("$187.50"), "missing balance: {line}");
        assert!(line.contains("stale"), "missing stale marker: {line}");

        let table = render_status_table(&status, None, "Mon 09:00");
        assert!(
            table.contains("stale"),
            "table missing stale marker: {table}"
        );
        // A native slot's staleness is EXPECTED (see `stale_marker`), so it
        // must be annotated rather than read as a fault.
        assert!(
            line.contains("re-auths on use"),
            "native staleness must say it self-corrects: {line}"
        );
    }

    /// A native-CLI slot goes stale BY DESIGN: csq never refreshes vendor
    /// tokens, the vendor token lives ~15 min, and nothing refreshes it while
    /// the slot is idle. That is not a fault and must not read like one — but
    /// a NON-native slot's staleness still does mean something is wrong, and
    /// must NOT pick up the reassurance.
    ///
    /// Non-vacuity: drop the `AccountSource::Native` arm from `stale_marker`
    /// and the first assertion fails; apply the annotation unconditionally
    /// and the second fails.
    #[test]
    fn only_native_slots_get_the_re_auths_on_use_annotation() {
        let mut native = native_status(1, Surface::Grok, "grok-1");
        native.stale_secs = Some(6 * 3600);
        let native_line = native.format_line();
        assert!(
            native_line.contains("stale 6h") && native_line.contains("re-auths on use"),
            "native slot must show the age AND that it self-corrects: {native_line}"
        );

        let mut anthropic = anthropic_status(2);
        anthropic.stale_secs = Some(6 * 3600);
        let anthropic_line = anthropic.format_line();
        assert!(
            anthropic_line.contains("stale 6h"),
            "non-native staleness must still render: {anthropic_line}"
        );
        assert!(
            !anthropic_line.contains("re-auths on use"),
            "a non-native slot's staleness is NOT self-correcting — it must \
             not be reassured away: {anthropic_line}"
        );
    }

    // ── Provider-group display order (csq status) ──────────────────────

    /// Minimal `AccountInfo` builder for the provider-group ordering tests
    /// below — every field except id/label/source/surface/method is a
    /// fixed, irrelevant-to-sort default.
    fn account_info(
        id: u16,
        label: &str,
        source: AccountSource,
        surface: Surface,
        method: &str,
    ) -> AccountInfo {
        AccountInfo {
            id,
            label: label.into(),
            oauth_email: None,
            source,
            surface,
            method: method.into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        }
    }

    /// Writes a minimal windowed `AccountQuota` row (5h window only, a
    /// far-future reset so it never reads stale) — the shape
    /// `AccountStatus::shows_window` gates on. Used for non-Anthropic
    /// providers that DO carry a real usage window (Grok/Kimi/Z.AI/MiniMax
    /// can all be polled subscriptions, per an internal ticket — billing mode is
    /// per-PLAN, not per-provider).
    fn setup_window_quota(base: &Path, account: u16, five_hour_pct: f64) {
        setup_quota_row(
            base,
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: five_hour_pct,
                    resets_at: 9_999_999_999,
                }),
                ..Default::default()
            },
        );
    }

    /// Full required order (team-lead spec, matching the live-observed
    /// defect): Claude native -> Codex -> Kimi (both account shapes,
    /// together, slot-ascending) -> Grok -> Z.AI -> MiniMax -> balance-only
    /// pay-per-token (DeepSeek) LAST. The input `Vec<AccountInfo>` is built
    /// in the EXACT scrambled shape `discover_all` produces today (native
    /// slots 14/16 precede per-slot 3P slots 13/15/17/18 despite 13 < 14
    /// numerically) — this is the defect the sort must correct.
    #[test]
    fn compose_status_full_required_provider_group_order() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0); // Anthropic (writes creds + a window)
        setup_window_quota(dir.path(), 12, 10.0); // Codex
        setup_window_quota(dir.path(), 14, 5.0); // Kimi — native
        setup_window_quota(dir.path(), 16, 7.0); // Grok — native
        setup_window_quota(dir.path(), 13, 30.0); // Kimi — 3P bearer
        setup_window_quota(dir.path(), 17, 40.0); // Z.AI
        setup_window_quota(dir.path(), 18, 50.0); // MiniMax
                                                  // DeepSeek: balance only, no window — the pay-per-token shape.
        setup_quota_row(
            dir.path(),
            15,
            AccountQuota {
                balance: Some(BalanceInfo {
                    currency: "USD".into(),
                    remaining: 165.32,
                }),
                ..Default::default()
            },
        );

        let accounts = vec![
            account_info(
                1,
                "alice@example.com",
                AccountSource::Anthropic,
                Surface::ClaudeCode,
                "oauth",
            ),
            account_info(
                12,
                "codex-12",
                AccountSource::Codex,
                Surface::Codex,
                "oauth",
            ),
            account_info(
                14,
                "kimi-14",
                AccountSource::Native {
                    surface: Surface::Kimi,
                },
                Surface::Kimi,
                "native_cli",
            ),
            account_info(
                16,
                "grok-16",
                AccountSource::Native {
                    surface: Surface::Grok,
                },
                Surface::Grok,
                "native_cli",
            ),
            account_info(
                13,
                "Kimi",
                AccountSource::ThirdParty {
                    provider: "Kimi".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
            account_info(
                15,
                "DeepSeek",
                AccountSource::ThirdParty {
                    provider: "DeepSeek".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
            account_info(
                17,
                "Z.AI",
                AccountSource::ThirdParty {
                    provider: "Z.AI".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
            account_info(
                18,
                "MiniMax",
                AccountSource::ThirdParty {
                    provider: "MiniMax".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
        ];

        let status = compose_status(dir.path(), accounts, None);
        let ids: Vec<u16> = status.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![1, 12, 13, 14, 16, 17, 18, 15],
            "expected Claude native -> Codex -> Kimi (both, slot-ascending) \
             -> Grok -> Z.AI -> MiniMax -> DeepSeek (balance-only, last); got {ids:?}"
        );
    }

    /// Both Kimi account shapes — a native self-authenticating CLI slot
    /// (`surface == Kimi`) and a 3P Bearer-key slot (`source ==
    /// ThirdParty { provider: "Kimi" }`, `surface == ClaudeCode`) — MUST
    /// land adjacent despite the differing `method` (`native_cli` vs
    /// `api_key`), even when a Grok slot's id sits numerically between
    /// them in the input.
    #[test]
    fn compose_status_both_kimi_shapes_land_adjacent_despite_differing_method() {
        let dir = TempDir::new().unwrap();
        setup_window_quota(dir.path(), 20, 5.0); // Kimi native
        setup_window_quota(dir.path(), 21, 6.0); // Grok — numerically between the two Kimis
        setup_window_quota(dir.path(), 22, 7.0); // Kimi 3P bearer

        let accounts = vec![
            account_info(
                20,
                "kimi-20",
                AccountSource::Native {
                    surface: Surface::Kimi,
                },
                Surface::Kimi,
                "native_cli",
            ),
            account_info(
                21,
                "grok-21",
                AccountSource::Native {
                    surface: Surface::Grok,
                },
                Surface::Grok,
                "native_cli",
            ),
            account_info(
                22,
                "Kimi",
                AccountSource::ThirdParty {
                    provider: "Kimi".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
        ];

        let status = compose_status(dir.path(), accounts, None);
        let ids: Vec<u16> = status.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![20, 22, 21],
            "the two Kimi shapes (20, 22) must be adjacent, ahead of Grok (21); got {ids:?}"
        );
    }

    /// A GENUINELY balance-only account (positive balance data present,
    /// reset fields null because there is no window to carry them) sorts
    /// last, via [`AccountStatus::is_balance_only`]'s positive assertion
    /// — NOT via the absence of window data alone. Distinct from
    /// `compose_status_stale_subscription_account_stays_in_provider_group_not_trailing_bucket`,
    /// which pins the opposite case: a subscription account with equally
    /// null reset fields (because its poller is stale, not because it's
    /// pay-per-token) must NOT sort last.
    #[test]
    fn compose_status_balance_only_account_sorts_last_with_null_reset_fields() {
        let dir = TempDir::new().unwrap();
        setup_window_quota(dir.path(), 30, 10.0); // MiniMax, polled
        setup_quota_row(
            dir.path(),
            31,
            AccountQuota {
                balance: Some(BalanceInfo {
                    currency: "USD".into(),
                    remaining: 165.32,
                }),
                ..Default::default()
            },
        ); // DeepSeek — genuinely balance-only

        let accounts = vec![
            account_info(
                31,
                "DeepSeek",
                AccountSource::ThirdParty {
                    provider: "DeepSeek".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
            account_info(
                30,
                "MiniMax",
                AccountSource::ThirdParty {
                    provider: "MiniMax".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 2);
        let deepseek = status.iter().find(|s| s.id == 31).unwrap();
        assert!(deepseek.five_hour_resets_in.is_none());
        assert!(deepseek.seven_day_resets_in.is_none());
        let ids: Vec<u16> = status.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![30, 31],
            "MiniMax (polled window) must precede DeepSeek (never polled); got {ids:?}"
        );
    }

    /// Ties within the same (window-bucket, provider-group) are resolved
    /// deterministically by ascending slot id — proven here by feeding
    /// the SAME provider group in DESCENDING id order and asserting the
    /// output is ascending regardless.
    #[test]
    fn compose_status_same_group_ties_resolve_by_ascending_slot_id() {
        let dir = TempDir::new().unwrap();
        setup_window_quota(dir.path(), 40, 5.0);
        setup_window_quota(dir.path(), 39, 6.0);
        setup_window_quota(dir.path(), 38, 7.0);

        // Input fed in DESCENDING id order — same provider group (Z.AI)
        // throughout, so provider_group_rank alone can't distinguish them.
        let accounts = vec![
            account_info(
                40,
                "Z.AI",
                AccountSource::ThirdParty {
                    provider: "Z.AI".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
            account_info(
                39,
                "Z.AI",
                AccountSource::ThirdParty {
                    provider: "Z.AI".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
            account_info(
                38,
                "Z.AI",
                AccountSource::ThirdParty {
                    provider: "Z.AI".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
        ];

        let status = compose_status(dir.path(), accounts, None);
        let ids: Vec<u16> = status.iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![38, 39, 40]);
    }

    /// A SUBSCRIPTION account (Kimi group) whose poller has gone stale —
    /// no window data AND no balance data, i.e. genuinely no quota row at
    /// all — MUST still sort by its provider group, directly after Codex.
    /// It MUST NOT fall into the trailing balance-only bucket alongside a
    /// genuine pay-per-token account.
    ///
    /// This is the live defect found by the maintainer's smoke test on
    /// `csq status`: two real Kimi accounts had gone stale (expired vendor
    /// tokens, `stale 2h`/`stale 2d`) and sorted to the bottom of the list
    /// instead of directly after Codex, because the OLD key's primary
    /// bucket was `!shows_window()` — true for BOTH "genuinely
    /// pay-per-token" (DeepSeek) AND "subscription account whose poll
    /// happens to be stale right now" (Kimi here). Those are different
    /// facts about the account; `!shows_window()` alone cannot tell them
    /// apart. The fix keys the trailing bucket on the POSITIVE assertion
    /// `is_balance_only()` (has balance data AND no window), which
    /// mirrors the exact predicate `render_status_table`'s body branch
    /// uses to decide whether to print the `$X balance` suffix.
    #[test]
    fn compose_status_stale_subscription_account_stays_in_provider_group_not_trailing_bucket() {
        let dir = TempDir::new().unwrap();
        setup_window_quota(dir.path(), 12, 10.0); // Codex — has a window
                                                  // id 14: Kimi native, NO quota row at all — mirrors a stale poller
                                                  // (expired vendor token) that has written neither a window nor a
                                                  // balance. Deliberately no `setup_quota_row` call.
        setup_window_quota(dir.path(), 16, 7.0); // Grok — has a window
        setup_window_quota(dir.path(), 17, 40.0); // Z.AI — has a window

        let accounts = vec![
            account_info(
                12,
                "codex-12",
                AccountSource::Codex,
                Surface::Codex,
                "oauth",
            ),
            account_info(
                14,
                "kimi-14",
                AccountSource::Native {
                    surface: Surface::Kimi,
                },
                Surface::Kimi,
                "native_cli",
            ),
            account_info(
                16,
                "grok-16",
                AccountSource::Native {
                    surface: Surface::Grok,
                },
                Surface::Grok,
                "native_cli",
            ),
            account_info(
                17,
                "Z.AI",
                AccountSource::ThirdParty {
                    provider: "Z.AI".into(),
                },
                Surface::ClaudeCode,
                "api_key",
            ),
        ];

        let status = compose_status(dir.path(), accounts, None);
        let kimi = status.iter().find(|s| s.id == 14).unwrap();
        assert!(
            kimi.balance.is_none(),
            "fixture must have no balance data — that's the case under test"
        );
        assert!(
            kimi.five_hour_resets_in.is_none() && kimi.seven_day_resets_in.is_none(),
            "fixture must have no window data — that's the case under test"
        );

        let ids: Vec<u16> = status.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![12, 14, 16, 17],
            "stale Kimi (no window, no balance) must sort directly after Codex, \
             not trail behind Grok/Z.AI; got {ids:?}"
        );
    }

    // ── --json shape ────────────────────────────────────────────────

    #[test]
    fn account_status_json_omits_stale_secs_when_none() {
        let s = anthropic_status(1); // stale_secs: None via the helper
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("stale_secs"),
            "stale_secs key must be omitted when None (skip_serializing_if): {json}"
        );
    }

    #[test]
    fn account_status_json_includes_stale_secs_when_stale() {
        let mut s = anthropic_status(1);
        s.stale_secs = Some(56_160);
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains("\"stale_secs\":56160"),
            "stale_secs missing from --json shape: {json}"
        );
    }

    /// Back-compat: pre-existing snapshots (older csq builds) never wrote
    /// `stale_secs` — the field MUST default to `None`, never fail to
    /// deserialize.
    #[test]
    fn account_status_deserializes_without_stale_secs_field() {
        let legacy = r#"{
            "id": 1,
            "label": "alice@example.com",
            "is_active": true,
            "five_hour_pct": 12.0,
            "five_hour_resets_in": 3600,
            "seven_day_pct": 3.0,
            "seven_day_resets_in": 86400
        }"#;
        let parsed: AccountStatus = serde_json::from_str(legacy).expect("legacy JSON parses");
        assert!(
            parsed.stale_secs.is_none(),
            "missing stale_secs must default to None"
        );
    }
}
