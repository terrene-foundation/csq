//! Phase B' aggregator — scans CC's per-session transcripts, attributes them
//! to slots via the launch log, converts to [`UsageEvent`]s, and is consumed
//! by the daemon to append to per-account ledgers.
//!
//! Per an internal journal entry D2 (post-hoc time correlation attribution).
//!
//! ## Data source (an internal ticket)
//!
//! The v1 aggregator read `~/.claude/usage-data/session-meta/*.json` on the
//! assumption that CC writes one metadata file per session. **CC never wrote
//! there** — that directory does not exist on any real install, so the ledger
//! was empty for every slot since it shipped. The real per-session usage lives
//! in CC's transcripts:
//!
//! ```text
//! ~/.claude/projects/<encoded-cwd>/<session-id>.jsonl
//! ```
//!
//! Each line carries `cwd` (== the launch-log `project_path` exactly, so the
//! existing [`attribute_session`] correlation is unchanged), `timestamp`,
//! `sessionId`, and — on assistant lines — `message.usage` token counts. A
//! session spans MANY lines; the scanner sums usage across all of them.
//!
//! ## Privacy invariant (D6)
//!
//! [`TranscriptLine`] below is the SOLE deserialization shape used here. It
//! includes ONLY metadata fields — `cwd`, `timestamp`, `sessionId`, and the
//! numeric `message.usage` token counts + `message.model` name. It CANNOT see
//! `message.content`, `first_prompt`, tool payloads, or any conversational
//! text: those fields are simply absent from the struct, so serde discards
//! them. Transcripts are read via a line-streaming [`BufReader`] so no
//! transcript is ever held whole in memory. The relaxed D6 contract (vs the
//! v1 "transcript is NEVER read"): transcript CONTENT is never retained or
//! persisted; only token/cwd/timestamp/model metadata is extracted in-memory.
//! If a future change adds a content field to [`TranscriptLine`] or
//! [`TranscriptMessage`], the privacy contract is violated.

use crate::types::AccountNum;
use crate::usage::ledger::{UsageEvent, UsageSource};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use super::launch_log::LaunchEvent;

/// Skip transcript files whose mtime is older than this many days. The widest
/// ledger window is 30 days ([`super::ledger::summarize`]); the extra day is
/// slack for timezone/rounding. On a host with thousands of historical
/// transcripts this bounds the per-render scan to recently-active sessions.
const SCAN_MAX_AGE_DAYS: i64 = 31;

/// One transcript line, projected to METADATA ONLY. PRIVACY (D6): this struct
/// and [`TranscriptMessage`] / [`TranscriptUsage`] are the privacy gate — they
/// contain NO content fields (`content`, `text`, `first_prompt`, tool payloads
/// are absent, so serde drops them). Never add a content field here.
#[derive(Debug, Deserialize)]
struct TranscriptLine {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(rename = "sessionId", default)]
    session_id: Option<String>,
    #[serde(default)]
    message: Option<TranscriptMessage>,
}

/// The `message` object on assistant/user lines. METADATA ONLY — carries the
/// model name and usage counts; `content` is deliberately absent.
#[derive(Debug, Deserialize)]
struct TranscriptMessage {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<TranscriptUsage>,
}

/// The per-turn token counts inside `message.usage`. All numeric.
#[derive(Debug, Default, Deserialize)]
struct TranscriptUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

/// Returns the canonical CC projects directory under `claude_home`, where CC
/// writes per-session transcripts as `<encoded-cwd>/<session-id>.jsonl`.
fn projects_dir(claude_home: &Path) -> PathBuf {
    claude_home.join("projects")
}

/// Scans the CC projects directory (`~/.claude/projects`) and returns one
/// [`ScannedSession`] per transcript that carries at least one usage line.
///
/// Bounded by mtime ([`SCAN_MAX_AGE_DAYS`]) so a host with thousands of
/// historical transcripts does not pay a full scan on every dashboard render.
/// Files that fail to open, contain no usage, or lack a `cwd`/`timestamp` are
/// skipped — the aggregator's job is best-effort billing telemetry.
fn scan_project_transcripts(projects_dir: &Path, now: DateTime<Utc>) -> Vec<ScannedSession> {
    let cutoff = now - Duration::days(SCAN_MAX_AGE_DAYS);
    let project_entries = match std::fs::read_dir(projects_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for project in project_entries.flatten() {
        let project_path = project.path();
        if !project_path.is_dir() {
            continue;
        }
        let files = match std::fs::read_dir(&project_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            // mtime bound — skip transcripts untouched since the cutoff.
            if let Ok(meta) = file.metadata() {
                if let Ok(modified) = meta.modified() {
                    let modified: DateTime<Utc> = modified.into();
                    if modified < cutoff {
                        continue;
                    }
                }
            }
            if let Some(session) = scan_one_transcript(&path) {
                out.push(session);
            }
        }
    }
    out
}

/// Streams one transcript file line-by-line (never holding it whole) and folds
/// the metadata into a [`ScannedSession`]. Returns `None` when the file has no
/// usage-bearing line or is missing `cwd`/`timestamp` (unattributable).
fn scan_one_transcript(path: &Path) -> Option<ScannedSession> {
    let file = std::fs::File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut project_path: Option<String> = None;
    let mut start_time: Option<String> = None;
    let mut start_ts: Option<DateTime<chrono::FixedOffset>> = None;
    let mut session_id: Option<String> = None;
    let mut model: Option<String> = None;
    let mut input_tokens: u64 = 0;
    let mut output_tokens: u64 = 0;
    let mut cache_creation_tokens: u64 = 0;
    let mut cache_read_tokens: u64 = 0;
    let mut saw_usage = false;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // truncated/binary — stop, keep what we have
        };
        if line.is_empty() {
            continue;
        }
        // Perf prefilter (an internal ticket): a transcript is mostly content/user/
        // attachment lines that carry no token counts. Once the attribution
        // header (cwd + sessionId + first timestamp) is captured — which CC
        // writes on the earliest lines — only lines bearing a `usage` object
        // can still contribute, so skip the serde parse on everything else.
        // This turns an O(all lines) parse into O(header + usage lines) and is
        // the difference between a multi-second and a sub-second per-file scan
        // on transcripts with hundreds of large content lines. CC appends in
        // timestamp order, so the earliest timestamp is on an early line and
        // is never on a skipped tail line.
        let header_complete =
            project_path.is_some() && session_id.is_some() && start_time.is_some();
        if header_complete && !line.contains("\"usage\"") {
            continue;
        }
        let rec: TranscriptLine = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue, // tolerate non-conforming lines
        };
        if project_path.is_none() {
            if let Some(cwd) = rec.cwd {
                project_path = Some(cwd);
            }
        }
        if session_id.is_none() {
            session_id = rec.session_id;
        }
        // Earliest timestamp seen. NOTE: the perf prefilter above skips
        // non-`usage` tail lines once the header is complete, so this only sees
        // the min across header + usage lines. That is exact under CC's
        // append-in-timestamp-order guarantee (the earliest timestamp is on an
        // early, non-skipped line). If CC ever wrote an out-of-order earlier
        // timestamp on a skipped tail line, `start_time` could be a few minutes
        // too late — which only shifts a session's window bucket (Today/5d/7d/
        // 30d) at the margin; it never loses tokens (Total is bucket-agnostic)
        // nor changes attribution (project_path match is exact).
        if let Some(ts) = rec.timestamp {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(&ts) {
                match start_ts {
                    Some(prev) if parsed >= prev => {}
                    _ => {
                        start_ts = Some(parsed);
                        start_time = Some(ts);
                    }
                }
            }
        }
        if let Some(msg) = rec.message {
            if model.is_none() {
                // Treat an empty model string as absent so the caller's slot
                // fallback applies instead of passing "" to the rate table.
                model = msg.model.filter(|m| !m.is_empty());
            }
            if let Some(u) = msg.usage {
                saw_usage = true;
                input_tokens = input_tokens.saturating_add(u.input_tokens);
                output_tokens = output_tokens.saturating_add(u.output_tokens);
                cache_creation_tokens =
                    cache_creation_tokens.saturating_add(u.cache_creation_input_tokens);
                cache_read_tokens = cache_read_tokens.saturating_add(u.cache_read_input_tokens);
            }
        }
    }

    // Require usage + attribution keys; otherwise the session cannot be
    // billed or attributed and is dropped.
    if !saw_usage {
        return None;
    }
    let project_path = project_path?;
    let start_time = start_time?;
    // Fall back to the file stem for session_id (CC names files by session id).
    let session_id = session_id.or_else(|| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    })?;

    Some(ScannedSession {
        session_id,
        project_path,
        start_time,
        model,
        input_tokens,
        output_tokens,
        cache_creation_tokens,
        cache_read_tokens,
    })
}

/// One scanned session — the metadata projection used for attribution.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannedSession {
    pub session_id: String,
    pub project_path: String,
    pub start_time: String,
    /// The model name observed in the transcript (first assistant line with a
    /// non-empty model). `None` for sessions with no model line — the caller
    /// then falls back to the slot's configured model. Per-turn (multi-model)
    /// billing is a documented follow-up; v1 attributes the session to its
    /// first model.
    pub model: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Cache-write tokens summed across the session (`cache_creation_input_tokens`).
    pub cache_creation_tokens: u64,
    /// Cache-read tokens summed across the session (`cache_read_input_tokens`).
    pub cache_read_tokens: u64,
}

/// Result of attributing a session to a slot.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributedSession {
    pub slot: AccountNum,
    pub session: ScannedSession,
}

/// Classifies a TRANSCRIPT model NAME into its provider-family id in the
/// `providers::catalog` id namespace (`claude`/`codex`/`gemini`/`deepseek`/
/// `mm`/`zai`/`ollama`), so it can be compared against a slot's family
/// resolved from its [`crate::accounts::AccountSource`] via
/// [`provider_family_for_source`]. Used ONLY by [`attribute_session`]'s
/// provider-consistency gate.
///
/// Case-insensitive substring match. Returns `None` for names it cannot
/// classify (Ollama-hosted open models like `qwen`/`llama`, future providers)
/// — the gate treats `None` as "don't know, don't gate", preserving cwd+time
/// attribution for unclassifiable models rather than over-rejecting.
///
/// The MiniMax and OpenAI arms are ANCHORED (`starts_with` / dotted prefixes)
/// rather than bare `contains` so a stray `m2.`/`o3` substring inside another
/// provider's model name cannot misclassify it (`deepseek`/`glm`/`gemini`/
/// `claude` are provider-unique tokens and stay `contains`).
fn model_provider_family(model: &str) -> Option<&'static str> {
    let lc = model.to_lowercase();
    if lc.contains("claude") {
        Some("claude")
    } else if lc.contains("deepseek") {
        Some("deepseek")
    } else if lc.contains("kimi") {
        Some("kimi")
    } else if lc.contains("glm") {
        Some("zai")
    } else if lc.contains("minimax")
        || lc.contains("abab")
        || lc.starts_with("m2.")
        || lc.starts_with("m3.")
        || lc.starts_with("m4.")
        || lc == "m2"
        || lc == "m3"
        || lc == "m4"
    {
        Some("mm")
    } else if lc.contains("gemini") {
        Some("gemini")
    } else if lc.contains("gpt")
        || lc.contains("codex")
        || lc == "o1"
        || lc == "o3"
        || lc == "o4"
        || lc.starts_with("o1-")
        || lc.starts_with("o3-")
        || lc.starts_with("o4-")
    {
        Some("codex")
    } else {
        None
    }
}

/// Resolves a slot's provider-family id (same namespace as
/// [`model_provider_family`]) from its authoritative
/// [`crate::accounts::AccountSource`]. This is the slot side of the
/// provider-consistency gate — using the account source (not the slot's
/// configured `ANTHROPIC_MODEL`) is what makes the gate correct for EVERY
/// surface: Codex slots store their model in `config.toml` and Gemini slots in
/// `~/.gemini`, so a model-string lookup would resolve `None` and mis-default
/// them to the Anthropic family, letting a `claude` session bleed onto a
/// Codex/Gemini card. `Manual` sources classify to `None` (unknown → gate does
/// not fire).
fn provider_family_for_source(source: &crate::accounts::AccountSource) -> Option<&'static str> {
    use crate::accounts::AccountSource as S;
    match source {
        S::Anthropic => Some("claude"),
        S::Codex => Some("codex"),
        S::Gemini => Some("gemini"),
        // Display name (`"DeepSeek"`/`"MiniMax"`/`"Z.AI"`/`"Ollama"`) → catalog id.
        S::ThirdParty { provider } => crate::providers::catalog::id_from_display_name(provider),
        S::Manual => None,
        // Native-CLI session surfaces (Wave 3, an internal journal entry) — `kimi` / `grok`.
        // In practice this arm is inert for attribution: `kimi`/`grok` are
        // vendor binaries, NOT `claude`, so they write no CC-shaped JSONL
        // transcript for `attribute_session` to scan in the first place. The
        // mapping is filled for exhaustiveness + symmetry with the 3P Kimi
        // bearer id ("kimi", matched by `model_provider_family`'s
        // `contains("kimi")` arm above).
        S::Native { surface } => Some(surface.as_str()),
    }
}

/// Attributes a session to a slot using the launch log. Returns `None` if no
/// matching launch event is found — those sessions remain unattributed and
/// are excluded from per-slot ledgers (visible in a future "unattributed"
/// total in the UI per an internal journal entry §FD #1).
///
/// Match heuristic: pick the most recent launch event whose `project_path`
/// equals the session's `project_path` AND whose timestamp is ≤ the session's
/// `start_time` AND whose slot's provider family is consistent with the
/// transcript's model family. The launch event closest in time before the
/// session start wins. If no project_path match exists, we return None (do NOT
/// cross-match across cwds — that would smear telemetry across unrelated work).
///
/// ## Provider-consistency gate (cross-provider attribution bleed)
///
/// cwd+time alone mis-attributes: a plain `claude` (Anthropic subscription)
/// session run in a directory where a DeepSeek/Codex/Gemini slot was last
/// `csq run` gets billed onto that slot, because CC's transcript carries a
/// matching `cwd` and that slot's launch event is the closest prior. But CC's
/// transcript reports the ACTUAL model — `claude-*` for a genuine Anthropic
/// session, `deepseek-*` for a DeepSeek slot — so the transcript's model
/// family must agree with the slot's provider family. `slot_family` resolves a
/// candidate slot's provider family (the caller derives it from the slot's
/// [`crate::accounts::AccountSource`] — authoritative for Anthropic, Codex,
/// Gemini, and 3P alike); a candidate whose family is KNOWN and disagrees with
/// the transcript model's KNOWN family is skipped. When either side is unknown
/// (model-less transcript, unclassifiable model, unresolvable slot) the gate
/// does not fire and cwd+time attribution stands — no over-rejection.
///
/// KNOWN LIMITATION (inherent to cwd+time correlation, not the gate): two
/// slots of the SAME provider family run in the same cwd are indistinguishable
/// — the gate is provider-family-granular, so both pass and the closest-prior
/// launch wins. Resolving that needs a per-session→slot signal CC does not
/// emit (e.g. the config dir written into the transcript). The gate closes the
/// CROSS-family bleed (claude-onto-DeepSeek), not same-family ambiguity.
pub fn attribute_session<G>(
    session: &ScannedSession,
    launch_events: &[LaunchEvent],
    mut slot_family: G,
) -> Option<AttributedSession>
where
    G: FnMut(AccountNum) -> Option<&'static str>,
{
    use chrono::DateTime;

    let session_ts = DateTime::parse_from_rfc3339(&session.start_time).ok()?;
    let session_family = session.model.as_deref().and_then(model_provider_family);

    let mut best: Option<&LaunchEvent> = None;
    for ev in launch_events {
        if ev.project_path != session.project_path {
            continue;
        }
        let ev_ts = match DateTime::parse_from_rfc3339(&ev.ts) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ev_ts > session_ts {
            continue;
        }
        // Provider-consistency gate: reject a candidate slot whose provider
        // family is known and disagrees with the transcript model's known
        // family (see the doc comment). Only gates when BOTH families are
        // known, so model-less/unclassifiable sessions fall through to
        // cwd+time.
        if let Some(sf) = session_family {
            if let Ok(cand_slot) = AccountNum::try_from(ev.slot) {
                if let Some(cf) = slot_family(cand_slot) {
                    if sf != cf {
                        continue;
                    }
                }
            }
        }
        // Pick the latest launch event ≤ session_ts.
        match best {
            None => best = Some(ev),
            Some(prev) => {
                let prev_ts = DateTime::parse_from_rfc3339(&prev.ts).ok()?;
                if ev_ts > prev_ts {
                    best = Some(ev);
                }
            }
        }
    }

    let matched = best?;
    let slot = AccountNum::try_from(matched.slot).ok()?;
    Some(AttributedSession {
        slot,
        session: session.clone(),
    })
}

/// Converts an attributed session to a [`UsageEvent`], costed via the cost
/// rates table. The model is sourced from the TRANSCRIPT (the real model CC
/// used) when present — an internal ticket's v2 model source, realizing the
/// `UsageEvent::model` doc's "v2: per-turn model from projects/jsonl". Only
/// when the transcript carried no model line does it fall back to
/// `fallback_model` (the slot's configured model, resolved by the caller).
///
/// If the resolved model is unknown to the rate table, `cost_usd_estimate` is
/// `None` and the UI shows "n/a" for the cost column.
///
/// COST NOTE (an internal ticket): the estimate bills cache tokens — cache-write
/// (`cache_creation_tokens`) and cache-read (`cache_read_tokens`) — in addition
/// to `input_tokens` + `output_tokens`, via
/// [`super::cost_rates::CostRate::estimate_usd_with_cache`], at each rate row's
/// OWN stored cache prices. A row with no verified price for a dimension bills
/// that dimension at $0, so csq never applies one vendor's cache economics to
/// another's row.
///
/// Today that means: Anthropic Claude rows bill both cache dimensions;
/// DeepSeek rows bill cache-READ at DeepSeek's published per-tier price and
/// cache-WRITE at $0 (DeepSeek publishes no write price — see
/// `TIME_VARYING_RATES`); every other provider bills both at $0.
///
/// Sessions with zero cache tokens bill identically on every provider, so no
/// cost regresses. DeepSeek sessions WITH cache reads become more expensive
/// than they previously reported — that is the an internal ticket under-report being
/// corrected, not a rate change.
pub fn attributed_session_to_event(
    attributed: &AttributedSession,
    fallback_model: &str,
) -> UsageEvent {
    let session = &attributed.session;
    let model = session.model.as_deref().unwrap_or(fallback_model);
    // Price at the instant the SESSION ran, not wall-clock now (an internal ticket): a
    // DeepSeek session's rate depends on whether it predates the 2026-08-16
    // peak/off-peak cutover and, after it, which UTC window it started in.
    // `start_time` is the session's own earliest transcript timestamp, so a
    // historical ledger entry keeps pricing at the rate that was charged then.
    // An unparseable timestamp yields `None`, which the rate table treats as
    // "cannot select a tier" — flat rows still resolve, time-varying rows
    // render `n/a` rather than guessing (fail-loud contract).
    let at = DateTime::parse_from_rfc3339(&session.start_time)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc));
    // Unconditional since an internal ticket: each rate row carries its OWN cache prices, and
    // a row with no verified price contributes exactly $0 for that dimension, so
    // `estimate_usd_with_cache` reduces to `estimate_usd` on such a row for any
    // token counts. The former `if r.cache_eligible` branch existed only to keep
    // Anthropic's multipliers off non-Anthropic rows; with prices stored per row
    // there is no longer a wrong multiplier to guard against.
    let cost = super::cost_rates::rate_for_model_at(model, at).map(|r| {
        r.estimate_usd_with_cache(
            session.input_tokens,
            session.output_tokens,
            session.cache_creation_tokens,
            session.cache_read_tokens,
        )
    });
    UsageEvent {
        ts: session.start_time.clone(),
        session_id: session.session_id.clone(),
        model: model.to_string(),
        input_tokens: session.input_tokens,
        output_tokens: session.output_tokens,
        cache_creation_tokens: session.cache_creation_tokens,
        cache_read_tokens: session.cache_read_tokens,
        cost_usd_estimate: cost,
        source: UsageSource::ProjectsJsonl,
        project_path: Some(session.project_path.clone()),
    }
}

/// Top-level aggregator entry — scans CC's projects transcripts, reads the
/// launch log, attributes each session, returns the (slot, event) pairs ready
/// to be appended to per-account ledgers.
///
/// `now` bounds the transcript scan by mtime ([`SCAN_MAX_AGE_DAYS`]); pass
/// `chrono::Utc::now()` in production (a parameter so tests are deterministic).
///
/// `model_for_slot` is a FALLBACK callback returning the slot's configured
/// model — used only for sessions whose transcript carried no model line. The
/// real per-turn model from the transcript takes precedence (an internal ticket).
///
/// The attribution provider-consistency gate ([`attribute_session`]) resolves
/// each slot's provider family internally from [`crate::accounts::discovery`]
/// (`AccountSource`), so no extra caller wiring is needed — the signature is
/// unchanged.
pub fn aggregate<F>(
    claude_home: &Path,
    base_dir: &Path,
    now: DateTime<Utc>,
    mut model_for_slot: F,
) -> Vec<(AccountNum, UsageEvent)>
where
    F: FnMut(AccountNum) -> String,
{
    let sessions = scan_project_transcripts(&projects_dir(claude_home), now);
    let launch = match super::launch_log::read_all(base_dir) {
        Ok(r) => r.events,
        Err(_) => Vec::new(),
    };
    // Resolve each slot's provider family ONCE from its authoritative
    // `AccountSource` (Anthropic / Codex / Gemini / 3P), for the attribution
    // provider-consistency gate. Built once per aggregation; a slot absent from
    // the map (or `Manual`) resolves to `None`, which disables the gate for
    // that candidate (falls through to cwd+time — no over-rejection).
    let mut source_family_by_slot: std::collections::HashMap<AccountNum, &'static str> =
        crate::accounts::discovery::discover_all(base_dir)
            .into_iter()
            .filter_map(|a| {
                let slot = AccountNum::try_from(a.id).ok()?;
                let family = provider_family_for_source(&a.source)?;
                Some((slot, family))
            })
            .collect();
    // 3P-dominance overlay: a slot actively routing through a 3P endpoint (its
    // `settings.json` `ANTHROPIC_BASE_URL` is what CC uses at runtime) IS that
    // 3P provider for billing — even if a stale Anthropic `by_slot` mapping
    // from a pre-rebind `csq login` still shadows it (discover_all lists
    // Anthropic before per-slot 3P, so the stale map would otherwise win). Left
    // un-overlaid, a rebind-without-`csq logout` slot classifies Anthropic and
    // the gate REJECTS its own `deepseek-*` sessions — a blank card, strictly
    // worse than the bleed this gate fixes. The live base-URL binding is the
    // authoritative runtime signal, so it dominates the OAuth map here.
    for a in crate::accounts::discovery::discover_per_slot_third_party(base_dir) {
        if let (Ok(slot), Some(family)) = (
            AccountNum::try_from(a.id),
            provider_family_for_source(&a.source),
        ) {
            source_family_by_slot.insert(slot, family);
        }
    }
    let mut out = Vec::with_capacity(sessions.len());
    for session in sessions {
        let attributed = attribute_session(&session, &launch, |slot| {
            source_family_by_slot.get(&slot).copied()
        });
        if let Some(attributed) = attributed {
            let fallback = model_for_slot(attributed.slot);
            let event = attributed_session_to_event(&attributed, &fallback);
            out.push((attributed.slot, event));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn launch_ev(ts: &str, slot: u16, project: &str) -> LaunchEvent {
        LaunchEvent {
            ts: ts.into(),
            event: "run".into(),
            slot,
            pid: 1,
            project_path: project.into(),
        }
    }

    fn scanned(ts: &str, project: &str, in_tok: u64, out_tok: u64) -> ScannedSession {
        ScannedSession {
            session_id: format!("sess-{ts}"),
            project_path: project.into(),
            start_time: ts.into(),
            model: None,
            input_tokens: in_tok,
            output_tokens: out_tok,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        }
    }

    /// A fixed "now" far enough after the fixture timestamps that a
    /// just-written file's real mtime is always within the scan window.
    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Writes `<projects>/<project_dir>/<filename>` with the given jsonl lines.
    fn write_transcript(
        projects: &Path,
        project_dir: &str,
        filename: &str,
        lines: &[&str],
    ) -> PathBuf {
        let dir = projects.join(project_dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(filename);
        std::fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    /// A "don't know the slot's family" resolver — bypasses the provider gate
    /// (the gate only fires when BOTH families are known). Used by tests whose
    /// session carries no model, where the gate is irrelevant.
    fn no_family(_: AccountNum) -> Option<&'static str> {
        None
    }

    #[test]
    fn attribute_session_picks_closest_prior_launch() {
        let session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        let launches = vec![
            // Earlier same project — wrong (outdated)
            launch_ev("2026-05-06T09:00:00Z", 1, "/repo/a"),
            // Closer prior same project — correct
            launch_ev("2026-05-06T11:00:00Z", 4, "/repo/a"),
            // After session start — must be ignored
            launch_ev("2026-05-06T12:00:00Z", 7, "/repo/a"),
            // Different project — must be ignored
            launch_ev("2026-05-06T11:15:00Z", 2, "/repo/b"),
        ];
        let result = attribute_session(&session, &launches, no_family).unwrap();
        assert_eq!(result.slot, slot(4));
    }

    #[test]
    fn attribute_session_returns_none_when_no_project_match() {
        let session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/different")];
        assert!(attribute_session(&session, &launches, no_family).is_none());
    }

    #[test]
    fn attribute_session_returns_none_for_session_before_any_launch() {
        let session = scanned("2026-05-06T08:00:00Z", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/a")];
        assert!(attribute_session(&session, &launches, no_family).is_none());
    }

    #[test]
    fn attribute_session_skips_malformed_timestamp() {
        let session = scanned("not-a-ts", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/a")];
        assert!(attribute_session(&session, &launches, no_family).is_none());
    }

    /// Bug-2 regression: a `claude-*` (Anthropic) transcript run in a cwd whose
    /// only launch event is a DeepSeek (3P) slot MUST NOT attribute to that
    /// slot — the provider gate rejects the sole candidate, leaving it
    /// unattributed. This is the $246.50-opus-on-the-DeepSeek-card bleed.
    #[test]
    fn attribute_session_rejects_cross_provider_slot() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.model = Some("claude-opus-4-8".into());
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 11, "/repo/a")];
        // Slot 11 is DeepSeek; the opus transcript is claude-family → rejected.
        let result = attribute_session(&session, &launches, |s| {
            if s == slot(11) {
                Some("deepseek")
            } else {
                Some("claude")
            }
        });
        assert!(result.is_none());
    }

    /// The gate FILTERS candidates rather than only rejecting post-hoc: when a
    /// cwd hosted BOTH an Anthropic-slot launch and a (closer-in-time) DeepSeek
    /// launch, a claude transcript attributes to the Anthropic slot even though
    /// the DeepSeek launch is nearer the session start.
    #[test]
    fn attribute_session_prefers_provider_consistent_launch() {
        let mut session = scanned("2026-05-06T12:00:00Z", "/repo/a", 100, 50);
        session.model = Some("claude-opus-4-8".into());
        let launches = vec![
            // Anthropic slot, earlier.
            launch_ev("2026-05-06T10:00:00Z", 1, "/repo/a"),
            // DeepSeek slot, CLOSER to session start — but provider-inconsistent.
            launch_ev("2026-05-06T11:30:00Z", 11, "/repo/a"),
        ];
        let result = attribute_session(&session, &launches, |s| {
            if s == slot(11) {
                Some("deepseek")
            } else {
                Some("claude")
            }
        })
        .unwrap();
        assert_eq!(result.slot, slot(1));
    }

    /// A DeepSeek transcript still attributes to its DeepSeek slot (the gate
    /// must not reject provider-CONSISTENT matches).
    #[test]
    fn attribute_session_keeps_provider_consistent_3p_slot() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.model = Some("deepseek-v4-pro".into());
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 11, "/repo/a")];
        let result = attribute_session(&session, &launches, |_| Some("deepseek")).unwrap();
        assert_eq!(result.slot, slot(11));
    }

    /// When the transcript model is unclassifiable (unknown family), the gate
    /// does not fire and cwd+time attribution stands — no over-rejection.
    #[test]
    fn attribute_session_unknown_model_family_falls_through() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.model = Some("some-local-ollama-model".into());
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 11, "/repo/a")];
        // Even though the slot family is "deepseek", the unknown transcript
        // family means the gate cannot fire → attributed by cwd+time.
        let result = attribute_session(&session, &launches, |_| Some("deepseek")).unwrap();
        assert_eq!(result.slot, slot(11));
    }

    #[test]
    fn model_provider_family_classifies_known_families() {
        // Namespace matches the catalog provider ids so it compares against
        // `provider_family_for_source`.
        assert_eq!(model_provider_family("claude-opus-4-8"), Some("claude"));
        assert_eq!(model_provider_family("claude-sonnet-4-6"), Some("claude"));
        assert_eq!(model_provider_family("deepseek-v4-pro"), Some("deepseek"));
        assert_eq!(model_provider_family("deepseek-v4-flash"), Some("deepseek"));
        assert_eq!(model_provider_family("glm-4.6"), Some("zai"));
        assert_eq!(model_provider_family("m2.7-coder"), Some("mm"));
        assert_eq!(model_provider_family("MiniMax-M3"), Some("mm"));
        assert_eq!(model_provider_family("m3.1-coder"), Some("mm"));
        assert_eq!(model_provider_family("M3"), Some("mm")); // bare short form
        assert_eq!(model_provider_family("gemini-2.5-pro"), Some("gemini"));
        assert_eq!(model_provider_family("gpt-5-codex"), Some("codex"));
        assert_eq!(model_provider_family("o3-mini"), Some("codex"));
        // Unclassifiable → None (Ollama-hosted open models; no false OpenAI
        // match on a stray `o3`/`m2.` substring inside another name).
        assert_eq!(model_provider_family("qwen2.5-coder"), None);
        assert_eq!(model_provider_family("llama-3-o3-tune"), None);
        assert_eq!(model_provider_family(""), None);
    }

    #[test]
    fn provider_family_for_source_maps_every_variant() {
        use crate::accounts::AccountSource as S;
        assert_eq!(provider_family_for_source(&S::Anthropic), Some("claude"));
        assert_eq!(provider_family_for_source(&S::Codex), Some("codex"));
        assert_eq!(provider_family_for_source(&S::Gemini), Some("gemini"));
        assert_eq!(
            provider_family_for_source(&S::ThirdParty {
                provider: "DeepSeek".into()
            }),
            Some("deepseek")
        );
        assert_eq!(
            provider_family_for_source(&S::ThirdParty {
                provider: "MiniMax".into()
            }),
            Some("mm")
        );
        assert_eq!(provider_family_for_source(&S::Manual), None);
        // The transcript-side and source-side namespaces MUST agree, else a
        // DeepSeek transcript would never match its DeepSeek-source slot.
        assert_eq!(
            provider_family_for_source(&S::ThirdParty {
                provider: "DeepSeek".into()
            }),
            model_provider_family("deepseek-v4-pro")
        );
    }

    #[test]
    fn attributed_session_to_event_estimates_cost() {
        let attr = AttributedSession {
            slot: slot(4),
            session: scanned("2026-05-06T11:30:00Z", "/repo/a", 1_000_000, 1_000_000),
        };
        // Transcript has no model → falls back to the supplied model.
        let event = attributed_session_to_event(&attr, "deepseek-chat");
        assert_eq!(event.input_tokens, 1_000_000);
        assert_eq!(event.output_tokens, 1_000_000);
        // 1M input + 1M output @ deepseek-chat (V4-flash rate) = $0.14 + $0.28 = $0.42
        let cost = event.cost_usd_estimate.unwrap();
        assert!((cost - 0.42).abs() < 0.001, "expected ~0.42, got {cost}");
        assert_eq!(event.source, UsageSource::ProjectsJsonl);
        assert_eq!(event.project_path, Some("/repo/a".to_string()));
        assert_eq!(event.model, "deepseek-chat");
    }

    #[test]
    fn attributed_session_to_event_prefers_transcript_model_over_fallback() {
        // The transcript's real model must win over the caller's slot-configured
        // fallback — an internal ticket's second bug (caller hardcoded sonnet for all).
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 1_000_000, 1_000_000);
        session.model = Some("deepseek-chat".into());
        let attr = AttributedSession {
            slot: slot(11),
            session,
        };
        let event = attributed_session_to_event(&attr, "claude-sonnet-4-6");
        assert_eq!(event.model, "deepseek-chat");
        // Cost is deepseek's $0.42, NOT sonnet's ($3 + $15 = $18.00).
        let cost = event.cost_usd_estimate.unwrap();
        assert!(
            (cost - 0.42).abs() < 0.001,
            "expected deepseek 0.42, got {cost}"
        );
    }

    /// an internal ticket end-to-end: the DeepSeek rate is selected by the SESSION's own
    /// timestamp, so three otherwise-identical sessions differing only in when
    /// they ran get three different bills — and a July session keeps pricing at
    /// July's rate no matter when the aggregator runs.
    #[test]
    fn attributed_session_to_event_prices_deepseek_by_session_time() {
        // 1M in + 1M out @ deepseek-v4-pro, at three fixed instants.
        for (ts, expected, label) in [
            (
                "2026-07-04T02:30:00Z",
                1.305,
                "pre-cutover flat (0.435 + 0.87)",
            ),
            (
                "2026-08-20T02:30:00Z",
                5.28,
                "post-cutover PEAK (1.32 + 3.96)",
            ),
            (
                "2026-08-20T12:30:00Z",
                2.64,
                "post-cutover OFF-PEAK (0.66 + 1.98)",
            ),
        ] {
            let mut session = scanned(ts, "/repo/a", 1_000_000, 1_000_000);
            session.model = Some("deepseek-v4-pro".into());
            let attr = AttributedSession {
                slot: slot(7),
                session,
            };
            let event = attributed_session_to_event(&attr, "deepseek-v4-pro");
            let cost = event.cost_usd_estimate.expect("v4-pro is a rated model");
            assert!(
                (cost - expected).abs() < 0.001,
                "{ts} ({label}): expected ~${expected}, got ${cost}"
            );
        }
    }

    /// an internal ticket fail-loud: a session whose timestamp will not parse cannot select
    /// a DeepSeek tier, so the cost renders `n/a` rather than guessing one of
    /// two rates that differ by 2×. A time-invariant model is unaffected.
    #[test]
    fn attributed_session_to_event_unparseable_ts_yields_na_for_deepseek_only() {
        let mut session = scanned("not-a-timestamp", "/repo/a", 1_000_000, 1_000_000);
        session.model = Some("deepseek-v4-pro".into());
        let attr = AttributedSession {
            slot: slot(7),
            session,
        };
        assert!(
            attributed_session_to_event(&attr, "deepseek-v4-pro")
                .cost_usd_estimate
                .is_none(),
            "unparseable timestamp must render n/a, never a guessed tier"
        );

        // Claude's rate does not depend on when → still priced.
        let mut session = scanned("not-a-timestamp", "/repo/a", 100_000, 50_000);
        session.model = Some("claude-sonnet-4-6".into());
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let cost = attributed_session_to_event(&attr, "claude-sonnet-4-6")
            .cost_usd_estimate
            .expect("time-invariant rows must not regress to n/a");
        assert!((cost - 1.05).abs() < 0.001, "expected ~$1.05, got ${cost}");
    }

    #[test]
    fn attributed_session_to_event_unknown_model_returns_none_cost() {
        let attr = AttributedSession {
            slot: slot(4),
            session: scanned("2026-05-06T11:30:00Z", "/repo/a", 1000, 500),
        };
        let event = attributed_session_to_event(&attr, "future-model-not-in-table");
        assert!(event.cost_usd_estimate.is_none());
        // Tokens still record correctly.
        assert_eq!(event.input_tokens, 1000);
    }

    #[test]
    fn attributed_session_to_event_captures_cache_tokens() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.cache_creation_tokens = 930_906;
        session.cache_read_tokens = 8_839_479;
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let event = attributed_session_to_event(&attr, "claude-opus-4-8");
        // Cache tokens are captured on the event.
        assert_eq!(event.cache_creation_tokens, 930_906);
        assert_eq!(event.cache_read_tokens, 8_839_479);
        // an internal ticket: cost now bills input + output + cache-write(1.25×) + cache-read(0.10×)
        // at claude-opus input rate ($15/1M).
        let cost = event.cost_usd_estimate.unwrap();
        let expected = 100.0 * 15.0 / 1e6            // input
            + 50.0 * 75.0 / 1e6                       // output
            + 930_906.0 * 15.0 * 1.25 / 1e6           // cache write
            + 8_839_479.0 * 15.0 * 0.10 / 1e6; // cache read
        assert!(
            (cost - expected).abs() < 1e-9,
            "expected cache-inclusive ${expected}, got ${cost}"
        );
    }

    #[test]
    fn attributed_session_to_event_bills_deepseek_cache_read_but_not_write() {
        // an internal ticket: DeepSeek publishes a cache-HIT price, so cache reads now bill
        // at that row's own per-tier price — this is the under-report being
        // corrected. Cache WRITES stay at $0 because DeepSeek publishes no
        // write price and csq does not guess one (guessing would OVER-bill).
        //
        // This assertion previously read "non-Anthropic cache must be $0" and
        // was correct only while csq had no DeepSeek cache price at all.
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 1_000, 500);
        session.model = Some("deepseek-v4-pro".into());
        session.cache_creation_tokens = 5_000_000;
        session.cache_read_tokens = 20_000_000;
        let attr = AttributedSession {
            slot: slot(7),
            session,
        };
        let event = attributed_session_to_event(&attr, "claude-sonnet-4-6");
        assert_eq!(event.cache_creation_tokens, 5_000_000);
        assert_eq!(event.cache_read_tokens, 20_000_000);
        // Pre-cutover v4-pro: $0.435/1M in, $0.87/1M out, $0.003625/1M cache-hit.
        // Cache WRITE contributes exactly nothing despite 5M write tokens.
        let cost = event.cost_usd_estimate.unwrap();
        let expected = 1_000.0 * 0.435 / 1e6          // input
            + 500.0 * 0.87 / 1e6                       // output
            + 20_000_000.0 * 0.003625 / 1e6; // cache read (write = $0)
        assert!(
            (cost - expected).abs() < 1e-12,
            "deepseek cache-read must bill, cache-write must not: expected ${expected}, got ${cost}"
        );
    }

    #[test]
    fn scan_one_transcript_sums_usage_and_extracts_metadata() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        // Real CC shape: a non-usage first line (no cwd), then assistant lines
        // each carrying message.usage; cwd/timestamp appear on later lines.
        let path = write_transcript(
            &projects,
            "-Users-me-repos-foo",
            "00d5e35f-affc-42cf-8c22-87e0ff54c260.jsonl",
            &[
                r#"{"type":"mode","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","mode":"default"}"#,
                r#"{"type":"assistant","cwd":"/Users/me/repos/foo","timestamp":"2026-05-06T09:38:21.837Z","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","message":{"model":"claude-opus-4-8","content":"SECRET CONTENT MUST NOT BE READ","usage":{"input_tokens":10000,"output_tokens":174,"cache_creation_input_tokens":36777,"cache_read_input_tokens":18562}}}"#,
                r#"{"type":"user","cwd":"/Users/me/repos/foo","timestamp":"2026-05-06T09:40:00.000Z","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","message":{"content":"more secret"}}"#,
                r#"{"type":"assistant","cwd":"/Users/me/repos/foo","timestamp":"2026-05-06T09:41:00.000Z","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","message":{"model":"claude-opus-4-8","usage":{"input_tokens":6673,"output_tokens":13782,"cache_creation_input_tokens":100,"cache_read_input_tokens":200}}}"#,
            ],
        );

        let s = scan_one_transcript(&path).unwrap();
        assert_eq!(s.session_id, "00d5e35f-affc-42cf-8c22-87e0ff54c260");
        assert_eq!(s.project_path, "/Users/me/repos/foo");
        // Earliest timestamp wins.
        assert_eq!(s.start_time, "2026-05-06T09:38:21.837Z");
        assert_eq!(s.model.as_deref(), Some("claude-opus-4-8"));
        // Summed across BOTH usage lines.
        assert_eq!(s.input_tokens, 16673);
        assert_eq!(s.output_tokens, 13956);
        assert_eq!(s.cache_creation_tokens, 36877);
        assert_eq!(s.cache_read_tokens, 18762);
        // Privacy (D6): ScannedSession has no content field — message.content
        // above is never captured (compile-time guarantee).
    }

    #[test]
    fn scan_one_transcript_none_without_usage() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "no-usage.jsonl",
            &[
                r#"{"type":"user","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","sessionId":"no-usage","message":{"content":"hi"}}"#,
            ],
        );
        assert!(scan_one_transcript(&path).is_none());
    }

    #[test]
    fn scan_one_transcript_none_without_cwd() {
        // Usage present but NO cwd on any line → unattributable → dropped
        // (the largest silent-drop path; lock it with a test).
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "no-cwd.jsonl",
            &[
                r#"{"type":"assistant","timestamp":"2026-05-06T09:00:00Z","sessionId":"no-cwd","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        assert!(scan_one_transcript(&path).is_none());
    }

    #[test]
    fn scan_one_transcript_empty_file_is_none() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(&projects, "-p", "empty.jsonl", &[""]);
        assert!(scan_one_transcript(&path).is_none());
    }

    #[test]
    fn scan_one_transcript_tolerates_malformed_lines_midfile() {
        // A broken line between two good usage lines must not abort the scan;
        // both good lines still sum.
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "mixed.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","sessionId":"mixed","message":{"model":"gpt-5","usage":{"input_tokens":10,"output_tokens":1}}}"#,
                r#"{ this is not valid json"#,
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:01:00Z","message":{"model":"gpt-5","usage":{"input_tokens":20,"output_tokens":2}}}"#,
            ],
        );
        let s = scan_one_transcript(&path).unwrap();
        assert_eq!(s.input_tokens, 30);
        assert_eq!(s.output_tokens, 3);
    }

    #[test]
    fn scan_one_transcript_empty_model_falls_through_to_none() {
        // `"model":""` must be treated as absent so the slot fallback applies.
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "empty-model.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","sessionId":"em","message":{"model":"","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        let s = scan_one_transcript(&path).unwrap();
        assert_eq!(s.model, None);
    }

    #[test]
    fn scan_one_transcript_falls_back_to_filename_for_session_id() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        // No sessionId field anywhere → derive from the file stem.
        let path = write_transcript(
            &projects,
            "-p",
            "abc-123.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        let s = scan_one_transcript(&path).unwrap();
        assert_eq!(s.session_id, "abc-123");
    }

    #[test]
    fn scan_project_transcripts_skips_files_older_than_window() {
        use std::time::SystemTime;
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let now = fixed_now();

        let recent = write_transcript(
            &projects,
            "-p",
            "recent.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        let old = write_transcript(
            &projects,
            "-p",
            "old.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        // Age the "old" file well beyond the 31-day window. NOTE: Windows
        // requires the file be opened for WRITE to set its mtime (Unix allows
        // it on a read handle), so use OpenOptions::write, not File::open.
        let set_mtime = |path: &Path, mtime: SystemTime| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        };
        set_mtime(&old, (now - Duration::days(40)).into());
        // Keep the recent file inside the window.
        set_mtime(&recent, (now - Duration::days(1)).into());

        let sessions = scan_project_transcripts(&projects, now);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "recent");
    }

    #[test]
    fn scan_project_transcripts_skips_non_jsonl_and_missing_dir() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        // Missing dir → empty.
        assert!(scan_project_transcripts(&projects, fixed_now()).is_empty());

        std::fs::create_dir_all(projects.join("-p")).unwrap();
        std::fs::write(projects.join("-p").join("notes.txt"), "ignored").unwrap();
        write_transcript(
            &projects,
            "-p",
            "good.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":1,"output_tokens":2}}}"#,
            ],
        );
        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(sessions.len(), 1);
    }

    /// Plants a `config-<slot>/settings.json` with a DeepSeek
    /// `ANTHROPIC_BASE_URL` so `accounts::discovery::discover_all` classifies
    /// the slot as `ThirdParty { provider: "DeepSeek" }` — the on-disk state a
    /// real 3P DeepSeek slot carries, which the provider-consistency gate reads.
    fn plant_deepseek_slot(base: &Path, slot: u16) {
        let config = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_MODEL":"deepseek-v4-pro","ANTHROPIC_AUTH_TOKEN":"sk-test"}}"#,
        )
        .unwrap();
    }

    #[test]
    fn aggregate_end_to_end() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        // Plant a real-shape transcript for slot 4's project.
        write_transcript(
            &claude_home.join("projects"),
            "-repo-a",
            "sess1.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/a","timestamp":"2026-05-06T11:30:00Z","sessionId":"sess1","message":{"model":"deepseek-chat","usage":{"input_tokens":10000,"output_tokens":5000}}}"#,
            ],
        );

        // Plant a launch event that attributes /repo/a to slot 4.
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 4, "/repo/a"))
            .unwrap();

        // Slot 4 is a DeepSeek slot (discovered via its 3P base-URL binding), so
        // the provider gate keeps the deepseek transcript.
        plant_deepseek_slot(base, 4);
        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "deepseek-v4-pro".to_string()
        });
        assert_eq!(result.len(), 1);
        let (s, ev) = &result[0];
        assert_eq!(*s, slot(4));
        assert_eq!(ev.input_tokens, 10000);
        assert_eq!(ev.session_id, "sess1");
        // Real transcript model (deepseek) wins over the fallback.
        assert_eq!(ev.model, "deepseek-chat");
        assert_eq!(ev.source, UsageSource::ProjectsJsonl);
        assert!(ev.cost_usd_estimate.is_some());
    }

    /// Bug-2 end-to-end: a `claude-*` transcript in a cwd whose only launch is a
    /// DeepSeek slot is NOT attributed to that slot (the $246.50 opus-on-the-
    /// DeepSeek-card bleed), because slot 11's authoritative `AccountSource`
    /// (ThirdParty DeepSeek) classifies to a different provider family than the
    /// claude transcript. Exercises the real `discover_all` wiring in `aggregate`.
    #[test]
    fn aggregate_does_not_bleed_claude_onto_3p_slot() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        // A real Anthropic (opus) session run in slot 11's cwd.
        write_transcript(
            &claude_home.join("projects"),
            "-repo-astro",
            "opus.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/astro","timestamp":"2026-05-06T11:30:00Z","sessionId":"opus","message":{"model":"claude-opus-4-8","usage":{"input_tokens":10000,"output_tokens":5000}}}"#,
            ],
        );

        // The only launch event for that cwd is DeepSeek slot 11.
        super::super::launch_log::append(
            base,
            &launch_ev("2026-05-06T11:00:00Z", 11, "/repo/astro"),
        )
        .unwrap();

        // Slot 11 is a DeepSeek 3P slot (discovered via its base-URL binding) →
        // provider gate rejects the opus transcript → zero attributed events.
        plant_deepseek_slot(base, 11);
        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "deepseek-v4-pro".to_string()
        });
        assert!(
            result.is_empty(),
            "claude transcript must not attribute to the DeepSeek slot, got {result:?}"
        );
    }

    /// Guards the fall-through: when a slot is NOT discoverable (no 3P binding,
    /// no anthropic credential → `AccountSource` unresolved), the gate is
    /// disabled for it and cwd+time attribution stands — a claude session in an
    /// undiscovered slot's cwd still attributes (no over-rejection).
    #[test]
    fn aggregate_undiscovered_slot_falls_through_to_cwd_time() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        write_transcript(
            &claude_home.join("projects"),
            "-repo-b",
            "sess.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/b","timestamp":"2026-05-06T11:30:00Z","sessionId":"sess","message":{"model":"claude-opus-4-8","usage":{"input_tokens":100,"output_tokens":50}}}"#,
            ],
        );
        // Slot 2 has NO on-disk discovery state → source unresolved → gate off.
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 2, "/repo/b"))
            .unwrap();

        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "claude-sonnet-4-6".to_string()
        });
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, slot(2));
    }

    /// Regression (redteam R2 F1): a slot that was Anthropic-logged (a stale
    /// `by_slot` mapping survives) THEN rebound to DeepSeek without `csq logout`
    /// (a live 3P `settings.json` base-URL binding) must classify as DeepSeek —
    /// the live 3P binding dominates the stale Anthropic map. Otherwise the gate
    /// would reject the slot's own `deepseek-*` sessions and blank its card
    /// (worse than the bleed). `discover_all` lists Anthropic (by_slot) before
    /// per-slot 3P, so WITHOUT the 3P-dominance overlay slot 3 resolves
    /// `claude` and this session is rejected.
    #[test]
    fn aggregate_3p_binding_dominates_stale_anthropic_by_slot() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();
        std::fs::create_dir_all(base).unwrap();

        // Stale Anthropic `by_slot` for slot 3 (pre-rebind login) — no identity
        // credentials planted, but the by_slot branch still emits Anthropic.
        std::fs::write(
            base.join("profiles.json"),
            r#"{"accounts":{},"by_slot":{"3":"550e8400-e29b-41d4-a716-446655440003"}}"#,
        )
        .unwrap();
        // Live DeepSeek 3P binding on the same slot (rebind without logout).
        plant_deepseek_slot(base, 3);

        write_transcript(
            &claude_home.join("projects"),
            "-repo-ds",
            "ds.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/ds","timestamp":"2026-05-06T11:30:00Z","sessionId":"ds","message":{"model":"deepseek-v4-pro","usage":{"input_tokens":1000,"output_tokens":500}}}"#,
            ],
        );
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 3, "/repo/ds"))
            .unwrap();

        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "deepseek-v4-pro".to_string()
        });
        assert_eq!(
            result.len(),
            1,
            "the deepseek session must attribute to its rebound 3P slot (3P binding \
             dominates the stale Anthropic by_slot), got {result:?}"
        );
        assert_eq!(result[0].0, slot(3));
    }
}
