//! Phase B' aggregator — scans CC's session-meta files, attributes them to
//! slots via the launch log, converts to [`UsageEvent`]s, and is consumed by
//! the daemon to append to per-account ledgers.
//!
//! Per journal 0050 D2 (post-hoc time correlation attribution).
//!
//! ## Privacy invariant (D6)
//!
//! [`SessionMetaRecord`] below is the SOLE deserialization shape used here.
//! It includes ONLY metadata fields — no `first_prompt`, no message content,
//! no `tool_errors` content, no facets. If a future change adds a content
//! field to this struct, the privacy contract is violated.

use crate::types::AccountNum;
use crate::usage::ledger::{UsageEvent, UsageSource};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use super::launch_log::LaunchEvent;

/// CC's session-meta metadata fields. PRIVACY: this struct is the privacy
/// gate — never add content fields. If you need richer data, source from
/// projects/jsonl in a SEPARATE struct that the privacy CI lint can audit
/// independently.
#[derive(Debug, Deserialize)]
struct SessionMetaRecord {
    session_id: String,
    project_path: String,
    start_time: String,
    /// CC may emit duration as integer minutes. Unused by the aggregator
    /// today; reserved for v2 enrichment.
    #[serde(default)]
    #[allow(dead_code)]
    duration_minutes: Option<u32>,
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

/// Returns the canonical CC session-meta directory under `claude_home`.
/// CC writes here regardless of which CLAUDE_CONFIG_DIR is active —
/// `~/.claude/accounts/term-<pid>/usage-data` is symlinked to
/// `~/.claude/usage-data/`, so all sessions land in one place.
pub fn session_meta_dir(claude_home: &Path) -> PathBuf {
    claude_home.join("usage-data").join("session-meta")
}

/// Scans a session-meta directory and returns one `(SessionMetaRecord-like
/// projection, file path)` per parseable file. Files that fail to parse OR
/// contain unrecognized fields are silently skipped — the aggregator's job is
/// best-effort billing telemetry, not validation.
fn scan_session_metas(dir: &Path) -> Vec<ScannedSession> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rec: SessionMetaRecord = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(_) => continue,
        };
        out.push(ScannedSession {
            session_id: rec.session_id,
            project_path: rec.project_path,
            start_time: rec.start_time,
            input_tokens: rec.input_tokens,
            output_tokens: rec.output_tokens,
            file_path: path,
        });
    }
    out
}

/// One scanned session — the metadata projection used for attribution.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannedSession {
    pub session_id: String,
    pub project_path: String,
    pub start_time: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub file_path: PathBuf,
}

/// Result of attributing a session to a slot.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributedSession {
    pub slot: AccountNum,
    pub session: ScannedSession,
}

/// Attributes a session to a slot using the launch log. Returns `None` if no
/// matching launch event is found — those sessions remain unattributed and
/// are excluded from per-slot ledgers (visible in a future "unattributed"
/// total in the UI per journal 0050 §FD #1).
///
/// Match heuristic: pick the most recent launch event whose `project_path`
/// equals the session's `project_path` AND whose timestamp is ≤ the session's
/// `start_time`. The launch event closest in time before the session start
/// wins. If no project_path match exists, we return None (do NOT cross-match
/// across cwds — that would smear telemetry across unrelated work).
pub fn attribute_session(
    session: &ScannedSession,
    launch_events: &[LaunchEvent],
) -> Option<AttributedSession> {
    use chrono::DateTime;

    let session_ts = DateTime::parse_from_rfc3339(&session.start_time).ok()?;

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

/// Converts an attributed session to a [`UsageEvent`] using the slot's
/// configured model + the cost rates table. Per journal 0050 D3 v1, the
/// model is the slot's CURRENT configured model; v2 will source per-turn
/// model from projects/jsonl.
///
/// `model` is the slot's configured model (caller resolves from the slot's
/// settings). If the model is unknown, `cost_usd_estimate` is `None` and
/// the UI shows "n/a" for the cost column.
pub fn attributed_session_to_event(attributed: &AttributedSession, model: &str) -> UsageEvent {
    let cost = super::cost_rates::rate_for_model(model).map(|r| {
        r.estimate_usd(
            attributed.session.input_tokens,
            attributed.session.output_tokens,
        )
    });
    UsageEvent {
        ts: attributed.session.start_time.clone(),
        session_id: attributed.session.session_id.clone(),
        model: model.to_string(),
        input_tokens: attributed.session.input_tokens,
        output_tokens: attributed.session.output_tokens,
        cost_usd_estimate: cost,
        source: UsageSource::SessionMeta,
        project_path: Some(attributed.session.project_path.clone()),
    }
}

/// Top-level aggregator entry — scans the session-meta dir, reads the launch
/// log, attributes each session, returns the (slot, event) pairs ready to be
/// appended to per-account ledgers.
///
/// `model_for_slot` is a callback that returns the current configured model
/// for a given slot. Caller wires this from `providers::settings` or similar.
pub fn aggregate<F>(
    claude_home: &Path,
    base_dir: &Path,
    mut model_for_slot: F,
) -> Vec<(AccountNum, UsageEvent)>
where
    F: FnMut(AccountNum) -> String,
{
    let sessions = scan_session_metas(&session_meta_dir(claude_home));
    let launch = match super::launch_log::read_all(base_dir) {
        Ok(r) => r.events,
        Err(_) => Vec::new(),
    };
    let mut out = Vec::with_capacity(sessions.len());
    for session in sessions {
        if let Some(attributed) = attribute_session(&session, &launch) {
            let model = model_for_slot(attributed.slot);
            let event = attributed_session_to_event(&attributed, &model);
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
            input_tokens: in_tok,
            output_tokens: out_tok,
            file_path: PathBuf::from("/tmp/fake.json"),
        }
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
        let result = attribute_session(&session, &launches).unwrap();
        assert_eq!(result.slot, slot(4));
    }

    #[test]
    fn attribute_session_returns_none_when_no_project_match() {
        let session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/different")];
        assert!(attribute_session(&session, &launches).is_none());
    }

    #[test]
    fn attribute_session_returns_none_for_session_before_any_launch() {
        let session = scanned("2026-05-06T08:00:00Z", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/a")];
        assert!(attribute_session(&session, &launches).is_none());
    }

    #[test]
    fn attribute_session_skips_malformed_timestamp() {
        let session = scanned("not-a-ts", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/a")];
        assert!(attribute_session(&session, &launches).is_none());
    }

    #[test]
    fn attributed_session_to_event_estimates_cost() {
        let attr = AttributedSession {
            slot: slot(4),
            session: scanned("2026-05-06T11:30:00Z", "/repo/a", 1_000_000, 1_000_000),
        };
        let event = attributed_session_to_event(&attr, "deepseek-chat");
        assert_eq!(event.input_tokens, 1_000_000);
        assert_eq!(event.output_tokens, 1_000_000);
        // 1M input + 1M output @ deepseek-chat = $0.27 + $1.10 = $1.37
        let cost = event.cost_usd_estimate.unwrap();
        assert!((cost - 1.37).abs() < 0.001, "expected ~1.37, got {cost}");
        assert_eq!(event.source, UsageSource::SessionMeta);
        assert_eq!(event.project_path, Some("/repo/a".to_string()));
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
    fn scan_session_metas_parses_real_shape() {
        let dir = TempDir::new().unwrap();
        let session_meta = dir.path().join("usage-data").join("session-meta");
        std::fs::create_dir_all(&session_meta).unwrap();

        // Real-shape file mirroring CC's actual output.
        std::fs::write(
            session_meta.join("00d5e35f-affc-42cf-8c22-87e0ff54c260.json"),
            r#"{
              "session_id": "00d5e35f-affc-42cf-8c22-87e0ff54c260",
              "project_path": "/Users/me/repos/foo",
              "start_time": "2026-03-02T09:38:21.837Z",
              "duration_minutes": 76,
              "input_tokens": 16673,
              "output_tokens": 13956,
              "tool_counts": {"Read": 20},
              "first_prompt": "this is content that MUST NOT be persisted"
            }"#,
        )
        .unwrap();

        let sessions = scan_session_metas(&session_meta);
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].session_id,
            "00d5e35f-affc-42cf-8c22-87e0ff54c260"
        );
        assert_eq!(sessions[0].project_path, "/Users/me/repos/foo");
        assert_eq!(sessions[0].input_tokens, 16673);
        assert_eq!(sessions[0].output_tokens, 13956);
        // Privacy: scanned struct does NOT carry first_prompt or tool_counts.
        // (Compile-time guarantee — ScannedSession has no such fields.)
    }

    #[test]
    fn scan_session_metas_missing_dir_returns_empty() {
        let dir = TempDir::new().unwrap();
        let sessions = scan_session_metas(&dir.path().join("nonexistent"));
        assert!(sessions.is_empty());
    }

    #[test]
    fn scan_session_metas_skips_non_json_files() {
        let dir = TempDir::new().unwrap();
        let session_meta = dir.path().join("usage-data").join("session-meta");
        std::fs::create_dir_all(&session_meta).unwrap();
        std::fs::write(session_meta.join("not-json.txt"), "ignored").unwrap();
        std::fs::write(session_meta.join("malformed.json"), "{ broken").unwrap();
        std::fs::write(
            session_meta.join("good.json"),
            r#"{"session_id":"a","project_path":"/p","start_time":"2026-05-06T11:00:00Z","input_tokens":1,"output_tokens":2}"#,
        )
        .unwrap();
        let sessions = scan_session_metas(&session_meta);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn aggregate_end_to_end() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        // Plant a session-meta file.
        let session_meta = claude_home.join("usage-data").join("session-meta");
        std::fs::create_dir_all(&session_meta).unwrap();
        std::fs::write(
            session_meta.join("sess1.json"),
            r#"{"session_id":"sess1","project_path":"/repo/a","start_time":"2026-05-06T11:30:00Z","input_tokens":10000,"output_tokens":5000}"#,
        )
        .unwrap();

        // Plant a launch event.
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 4, "/repo/a"))
            .unwrap();

        let result = aggregate(claude_home, base, |_slot| "deepseek-chat".to_string());
        assert_eq!(result.len(), 1);
        let (s, ev) = &result[0];
        assert_eq!(*s, slot(4));
        assert_eq!(ev.input_tokens, 10000);
        assert_eq!(ev.session_id, "sess1");
        assert!(ev.cost_usd_estimate.is_some());
    }
}
