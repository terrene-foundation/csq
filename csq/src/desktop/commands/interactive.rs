//! Tauri command wrappers for the M-IC interactive per-turn enforcement
//! surface (#793).
//!
//! These thin commands let the desktop renderer drive the daemon's
//! `/api/interactive/*` routes (open / submit / override / abandon / close)
//! over the Unix socket, carrying the daemon-minted `X-CSQ-Session-Key`
//! capability header on every keyed call.
//!
//! # Edition + activation posture
//!
//! The daemon routes are **enterprise-only** (`#[cfg(feature = "enterprise")]`
//! in `csq-core/src/daemon/server.rs`) AND fail-closed behind the §10.5
//! activation gate. These wrappers therefore compile in **both** editions and
//! carry **zero** governance logic — they only relay a socket POST and the
//! redacted state view back. The renderer NEVER makes an enforcement decision;
//! it relays the operator's input and displays the daemon's verdict (R1-S7).
//! When the surface is absent (community daemon → route 404) or inactive
//! (enterprise, gate closed → 503), every command returns the
//! `interactive_unavailable` tag and the renderer hides/greys the console.
//!
//! # Error vocabulary (mirrors the daemon)
//!
//! Errors are returned as the daemon's fixed-vocabulary tag string
//! (`InteractiveIpcError::tag()`), which the renderer maps to specific UI text
//! (`rules/tauri-commands.md` MUST Rule 6). Transport failures map to
//! `daemon_unreachable`; an unparseable success body maps to
//! `interactive_bad_response`.

use serde::{Deserialize, Serialize};

/// Per-turn user-input byte cap. Mirrors
/// `csq_core::phase2b::interactive::INPUT_MAX_BYTES` (enterprise-gated, so it is
/// re-stated rather than imported — these wrappers compile in both editions).
/// The daemon is the authoritative validator; this mirror gives the operator a
/// fast local rejection for UX (`rules/tauri-commands.md` MUST Rule 6).
const INPUT_MAX_BYTES: usize = 16 * 1024;

/// Override-justification byte cap. Mirrors
/// `csq_core::phase2b::interactive::JUSTIFICATION_MAX_BYTES`.
const JUSTIFICATION_MAX_BYTES: usize = 16 * 1024;

// Compile-time drift guard: when the desktop crate IS built with `enterprise`,
// the re-stated caps above MUST equal the authoritative csq-core constants.
// A divergence is a hard compile error, not a silent UX/daemon mismatch.
#[cfg(feature = "enterprise")]
const _: () = {
    assert!(INPUT_MAX_BYTES == csq_core::phase2b::interactive::INPUT_MAX_BYTES);
    assert!(JUSTIFICATION_MAX_BYTES == csq_core::phase2b::interactive::JUSTIFICATION_MAX_BYTES);
};

/// Flat, renderer-facing mirror of the daemon's `SessionStateView`.
///
/// The daemon serializes `SessionStateView` as
/// `{ "state": "idle" | "enforcing" | "blocked" | "complete", "reason"?, "content"? }`
/// (internally tagged on `state`). This flat struct deserializes that shape
/// without depending on the enterprise-gated type. `reason` is present iff
/// `blocked`; `content` iff `complete`. Both are already token-redacted at the
/// daemon's IPC boundary before they reach this struct.
#[derive(Debug, Serialize, Deserialize)]
pub struct InteractiveStateView {
    /// `"idle"` | `"enforcing"` | `"blocked"` | `"complete"`.
    pub state: String,
    /// The redacted block reason — present only when `state == "blocked"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The redacted completion content — present only when `state == "complete"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
}

/// Response of [`interactive_open`]: the daemon-minted session key the renderer
/// MUST echo on every subsequent call, plus the initial (`idle`) state.
#[derive(Debug, Serialize, Deserialize)]
pub struct InteractiveOpenView {
    pub session_key: String,
    pub state: InteractiveStateView,
    /// #793: the session's auth mode tag, captured once at open and rendered as a
    /// badge in the Enforcement console. The daemon serializes
    /// `OpenSessionResponse.auth_mode` as the kebab strings `"subscription"` /
    /// `"direct-api"` (from `csq_core::phase2b::interactive::AuthMode`), or omits
    /// the field for untagged (mock/test) sessions. Carried as `Option<String>`
    /// rather than the enterprise-gated `AuthMode` so these wrappers compile in
    /// both editions; the daemon is the authority for the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
}

/// One selectable subscription account for the Enforcement-tab picker (#793,
/// an internal journal entry §FD1). Flat mirror of the daemon's `CandidateSlot`
/// (`{ slot, label, seven_day_pct }`). Carried renderer-side to populate the
/// account dropdown; `seven_day_pct` (PR-3) lets the picker default to the lowest
/// non-capped account and render utilization in labels. `None` when the daemon
/// has no quota row for the slot.
#[derive(Debug, Serialize, Deserialize)]
pub struct InteractiveCandidateSlot {
    pub slot: u16,
    pub label: String,
    #[serde(default)]
    pub seven_day_pct: Option<f64>,
}

/// Response of [`interactive_options`]: the gate's default provider plus the
/// subscription accounts the operator may pick BEFORE opening a session (#793).
/// Mirror of the daemon's `SessionOptionsResponse`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InteractiveSessionOptions {
    pub provider: String,
    pub candidate_slots: Vec<InteractiveCandidateSlot>,
}

/// Validate untrusted text the same way the daemon does at the session boundary:
/// non-empty, within `cap` bytes, free of control characters other than ordinary
/// `\n` / `\r` / `\t`. Returns the supplied fixed `tag` on failure so the
/// renderer maps the same vocabulary whether the rejection happened locally or
/// at the daemon.
fn validate_text(s: &str, cap: usize, tag: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > cap {
        return Err(tag.to_string());
    }
    if s.chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(tag.to_string());
    }
    Ok(())
}

/// Validate the client-echoed session key against the daemon's charset/length
/// rule (`[A-Za-z0-9_-]`, 1..=64, no `..`). Mirrors
/// `SessionKey::try_from_client` so a malformed key is rejected before it can be
/// interpolated into the request header (defense-in-depth with the daemon-client
/// CRLF guard).
fn validate_session_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 64 || key.contains("..") {
        return Err("session_key_invalid".to_string());
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("session_key_invalid".to_string());
    }
    Ok(())
}

/// The fixed daemon error-tag vocabulary the interactive routes can emit
/// (`InteractiveIpcError::tag()` + the route-level `interactive_deserialize_error`).
/// Only these are passed through verbatim; any other `error` value collapses to
/// `interactive_request_failed` so a daemon-controlled free-text string can never
/// reach the renderer's error banner (defense-in-depth — the renderer maps these
/// tags to fixed UI text).
const KNOWN_DAEMON_TAGS: &[&str] = &[
    "interactive_unavailable",
    "session_wrong_state",
    "session_not_blocked",
    "input_invalid",
    "justification_invalid",
    "turn_operational_error",
    "session_not_found",
    "session_key_invalid",
    "session_config_invalid",
    "too_many_sessions",
    "conversation_too_long",
    // T-M4.2 PACT operating-envelope gate verdicts.
    "action_denied",
    "action_escalation_required",
    "interactive_deserialize_error",
];

/// Map a non-2xx daemon response to its fixed-vocabulary error tag.
///
/// The enterprise routes return `{ "error": "<tag>" }`; a community daemon
/// (routes absent) returns a 404 with a non-interactive body. Both collapse to
/// an actionable tag the renderer can map. An `error` value outside
/// [`KNOWN_DAEMON_TAGS`] (e.g. a free-text body from a future non-interactive
/// route sharing the socket) collapses to `interactive_request_failed` rather
/// than reaching the UI verbatim.
fn error_tag_from_body(body: &str, status: u16) -> String {
    #[derive(Deserialize)]
    struct ErrBody {
        error: String,
    }
    if let Ok(e) = serde_json::from_str::<ErrBody>(body) {
        if KNOWN_DAEMON_TAGS.contains(&e.error.as_str()) {
            return e.error;
        }
        return "interactive_request_failed".to_string();
    }
    // No interactive error body → the surface is absent here (community daemon,
    // or any daemon without the enterprise routes compiled in).
    if status == 404 {
        "interactive_unavailable".to_string()
    } else {
        "interactive_request_failed".to_string()
    }
}

/// Interpret a daemon `(status, body)` pair as an [`InteractiveStateView`] or
/// its error tag.
fn parse_state(status: u16, body: &str) -> Result<InteractiveStateView, String> {
    if (200..300).contains(&status) {
        serde_json::from_str::<InteractiveStateView>(body)
            .map_err(|_| "interactive_bad_response".to_string())
    } else {
        Err(error_tag_from_body(body, status))
    }
}

/// POST to an `/api/interactive/*` route over the daemon socket, optionally
/// carrying the `X-CSQ-Session-Key` header. Returns the `(status, body)` pair.
///
/// Returns `daemon_unreachable` when the socket is absent or the connect fails
/// (the daemon isn't running), and `interactive_request_failed` for any other
/// transport error. On non-Unix platforms the interactive surface is not served
/// → `interactive_unavailable`.
///
/// The `(u16, String)` return (rather than the daemon-client `DaemonResponse`,
/// which is `#[cfg(unix)]`-only) keeps every command below platform-agnostic at
/// the type boundary so `generate_handler!` resolves them on every target.
#[cfg(unix)]
fn call_daemon(
    base_dir: &str,
    path: &str,
    json_body: &str,
    session_key: Option<&str>,
) -> Result<(u16, String), String> {
    let base = std::path::PathBuf::from(base_dir);
    let sock = csq_core::daemon::socket_path(&base);
    if !sock.exists() {
        return Err("daemon_unreachable".to_string());
    }
    let headers: Vec<(&str, &str)> = match session_key {
        Some(k) => vec![("X-CSQ-Session-Key", k)],
        None => Vec::new(),
    };
    csq_core::daemon::http_post_unix_json_with_headers(&sock, path, json_body, &headers)
        .map(|resp| (resp.status, resp.body))
        .map_err(|e| match e {
            csq_core::daemon::DaemonClientError::Connect(_) => "daemon_unreachable".to_string(),
            _ => "interactive_request_failed".to_string(),
        })
}

#[cfg(not(unix))]
fn call_daemon(
    _base_dir: &str,
    _path: &str,
    _json_body: &str,
    _session_key: Option<&str>,
) -> Result<(u16, String), String> {
    Err("interactive_unavailable".to_string())
}

/// Open a new governed interactive session.
///
/// Returns the daemon-minted session key (the renderer echoes it on every
/// subsequent call) and the initial `idle` state. `terminal_label` is sanitized
/// daemon-side; `terminal_pid` is this process's PID so the daemon can reap the
/// session if the desktop app dies.
#[tauri::command]
pub fn interactive_open(
    base_dir: String,
    terminal_label: Option<String>,
    slot: Option<u16>,
) -> Result<InteractiveOpenView, String> {
    // `slot` (#793 §FD1 escape hatch): the operator-picked subscription account.
    // `None` → daemon default (lowest-with-creds). The daemon validates it is a
    // provider-matching account with credentials and rejects an arbitrary slot
    // (`session_config_invalid`); this wrapper just relays the choice.
    let body = serde_json::json!({
        "terminal_label": terminal_label,
        "terminal_pid": std::process::id(),
        "slot": slot,
    })
    .to_string();
    let (status, body) = call_daemon(&base_dir, "/api/interactive/open", &body, None)?;
    if (200..300).contains(&status) {
        serde_json::from_str::<InteractiveOpenView>(&body)
            .map_err(|_| "interactive_bad_response".to_string())
    } else {
        Err(error_tag_from_body(&body, status))
    }
}

/// List the subscription accounts the operator may pick before opening a session,
/// plus the gate's default provider (#793 Enforcement-tab picker, an internal journal entry
/// §FD1). No session key required — this is a pre-open query.
///
/// Returns `interactive_unavailable` when the activation gate is closed (the
/// community daemon, or enterprise with the §10.5 gate not open) so the renderer
/// hides the picker and falls back to the daemon default.
#[tauri::command]
pub fn interactive_options(base_dir: String) -> Result<InteractiveSessionOptions, String> {
    let (status, body) = call_daemon(&base_dir, "/api/interactive/options", "", None)?;
    if (200..300).contains(&status) {
        serde_json::from_str::<InteractiveSessionOptions>(&body)
            .map_err(|_| "interactive_bad_response".to_string())
    } else {
        Err(error_tag_from_body(&body, status))
    }
}

/// Submit one user input turn on an open session. Returns the resulting state
/// (`blocked` when governance held the turn, `complete` when it passed).
#[tauri::command]
pub fn interactive_submit(
    base_dir: String,
    session_key: String,
    input: String,
) -> Result<InteractiveStateView, String> {
    validate_session_key(&session_key)?;
    validate_text(&input, INPUT_MAX_BYTES, "input_invalid")?;
    let body = serde_json::json!({ "input": input }).to_string();
    let (status, body) = call_daemon(
        &base_dir,
        "/api/interactive/submit",
        &body,
        Some(&session_key),
    )?;
    parse_state(status, &body)
}

/// Authorize a blocked turn with an operator justification. The daemon records
/// the override as a signed audit event and runs the corrective turn.
#[tauri::command]
pub fn interactive_override(
    base_dir: String,
    session_key: String,
    justification: String,
) -> Result<InteractiveStateView, String> {
    validate_session_key(&session_key)?;
    validate_text(
        &justification,
        JUSTIFICATION_MAX_BYTES,
        "justification_invalid",
    )?;
    let body = serde_json::json!({ "justification": justification }).to_string();
    let (status, body) = call_daemon(
        &base_dir,
        "/api/interactive/override",
        &body,
        Some(&session_key),
    )?;
    parse_state(status, &body)
}

/// Abandon a blocked turn; the session returns to `idle`.
#[tauri::command]
pub fn interactive_abandon(
    base_dir: String,
    session_key: String,
) -> Result<InteractiveStateView, String> {
    validate_session_key(&session_key)?;
    let (status, body) = call_daemon(
        &base_dir,
        "/api/interactive/abandon",
        "",
        Some(&session_key),
    )?;
    parse_state(status, &body)
}

/// Close a session and free its daemon-side slot.
#[tauri::command]
pub fn interactive_close(
    base_dir: String,
    session_key: String,
) -> Result<InteractiveStateView, String> {
    validate_session_key(&session_key)?;
    let (status, body) = call_daemon(&base_dir, "/api/interactive/close", "", Some(&session_key))?;
    parse_state(status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_text_rejects_empty_oversized_and_control() {
        assert!(validate_text("", INPUT_MAX_BYTES, "input_invalid").is_err());
        assert!(validate_text(
            &"x".repeat(INPUT_MAX_BYTES + 1),
            INPUT_MAX_BYTES,
            "input_invalid"
        )
        .is_err());
        assert!(validate_text("bad\u{0007}bell", INPUT_MAX_BYTES, "input_invalid").is_err());
        // ordinary whitespace control chars are allowed
        assert!(validate_text("line1\nline2\ttab", INPUT_MAX_BYTES, "input_invalid").is_ok());
        assert!(validate_text("ok", INPUT_MAX_BYTES, "input_invalid").is_ok());
    }

    #[test]
    fn validate_text_returns_supplied_tag() {
        assert_eq!(
            validate_text("", JUSTIFICATION_MAX_BYTES, "justification_invalid").unwrap_err(),
            "justification_invalid"
        );
    }

    #[test]
    fn validate_session_key_mirrors_daemon_charset() {
        assert!(validate_session_key("01J9ZK7C8QABCDEF0123456789").is_ok());
        assert!(validate_session_key("abc-DEF_123").is_ok());
        assert!(validate_session_key("").is_err());
        assert!(validate_session_key(&"a".repeat(65)).is_err());
        assert!(validate_session_key("abc..def").is_err());
        assert!(validate_session_key("abc:def").is_err());
        assert!(validate_session_key("abc/def").is_err());
        assert!(validate_session_key("abc def").is_err());
    }

    #[test]
    fn error_tag_extracts_interactive_vocabulary() {
        assert_eq!(
            error_tag_from_body(r#"{"error":"session_not_found"}"#, 404),
            "session_not_found"
        );
        assert_eq!(
            error_tag_from_body(r#"{"error":"interactive_unavailable"}"#, 503),
            "interactive_unavailable"
        );
    }

    #[test]
    fn error_tag_falls_back_to_unavailable_on_bare_404() {
        // Community daemon: route absent → 404 with no interactive error body.
        assert_eq!(
            error_tag_from_body("Not Found", 404),
            "interactive_unavailable"
        );
        assert_eq!(error_tag_from_body("", 500), "interactive_request_failed");
    }

    #[test]
    fn error_tag_collapses_unknown_tag_to_request_failed() {
        // A free-text or out-of-vocabulary `error` body must NOT reach the UI
        // verbatim — it collapses to a known tag (defense-in-depth).
        assert_eq!(
            error_tag_from_body(r#"{"error":"some daemon free text 12345"}"#, 500),
            "interactive_request_failed"
        );
        // Every known daemon tag passes through unchanged.
        for tag in KNOWN_DAEMON_TAGS {
            let body = format!(r#"{{"error":"{tag}"}}"#);
            assert_eq!(&error_tag_from_body(&body, 500), tag);
        }
    }

    #[test]
    fn parse_state_reads_blocked_complete_idle() {
        let blocked =
            parse_state(200, r#"{"state":"blocked","reason":"schema mismatch"}"#).unwrap();
        assert_eq!(blocked.state, "blocked");
        assert_eq!(blocked.reason.as_deref(), Some("schema mismatch"));
        assert!(blocked.content.is_none());

        let complete =
            parse_state(200, r#"{"state":"complete","content":{"answer":"ok"}}"#).unwrap();
        assert_eq!(complete.state, "complete");
        assert_eq!(complete.content.as_ref().unwrap()["answer"], "ok");

        let idle = parse_state(200, r#"{"state":"idle"}"#).unwrap();
        assert_eq!(idle.state, "idle");
        assert!(idle.reason.is_none() && idle.content.is_none());
    }

    #[test]
    fn parse_state_maps_error_status_to_tag() {
        let err = parse_state(409, r#"{"error":"session_not_blocked"}"#).unwrap_err();
        assert_eq!(err, "session_not_blocked");
    }

    #[test]
    fn open_view_captures_auth_mode_tag() {
        // Daemon emits the kebab tag in the open-response (#793); the wrapper
        // carries it through verbatim for the console badge.
        let sub = serde_json::from_str::<InteractiveOpenView>(
            r#"{"session_key":"abc-123","state":{"state":"idle"},"auth_mode":"subscription"}"#,
        )
        .unwrap();
        assert_eq!(sub.auth_mode.as_deref(), Some("subscription"));
        assert_eq!(sub.state.state, "idle");

        let direct = serde_json::from_str::<InteractiveOpenView>(
            r#"{"session_key":"abc-123","state":{"state":"idle"},"auth_mode":"direct-api"}"#,
        )
        .unwrap();
        assert_eq!(direct.auth_mode.as_deref(), Some("direct-api"));
    }

    #[test]
    fn session_options_parses_candidate_slots() {
        // The daemon's /api/interactive/options body (#793 §FD1) deserializes into
        // the renderer-facing mirror.
        // First candidate carries a 7d quota (PR-3); second omits it → None.
        let opts = serde_json::from_str::<InteractiveSessionOptions>(
            r#"{"provider":"claude","candidate_slots":[{"slot":1,"label":"a@x.com","seven_day_pct":42.5},{"slot":3,"label":"b@x.com"}]}"#,
        )
        .unwrap();
        assert_eq!(opts.provider, "claude");
        assert_eq!(opts.candidate_slots.len(), 2);
        assert_eq!(opts.candidate_slots[0].slot, 1);
        assert_eq!(opts.candidate_slots[0].label, "a@x.com");
        assert_eq!(opts.candidate_slots[0].seven_day_pct, Some(42.5));
        assert_eq!(opts.candidate_slots[1].slot, 3);
        assert_eq!(
            opts.candidate_slots[1].seven_day_pct, None,
            "absent seven_day_pct → None (serde default)"
        );
    }

    #[test]
    fn session_options_parses_empty_candidate_list() {
        let opts = serde_json::from_str::<InteractiveSessionOptions>(
            r#"{"provider":"codex","candidate_slots":[]}"#,
        )
        .unwrap();
        assert_eq!(opts.provider, "codex");
        assert!(opts.candidate_slots.is_empty());
    }

    #[test]
    fn open_view_tolerates_absent_auth_mode() {
        // Untagged (mock/test) sessions omit the field — the daemon's
        // `skip_serializing_if = "Option::is_none"` means it may be absent.
        let untagged = serde_json::from_str::<InteractiveOpenView>(
            r#"{"session_key":"abc-123","state":{"state":"idle"}}"#,
        )
        .unwrap();
        assert!(untagged.auth_mode.is_none());
    }
}
