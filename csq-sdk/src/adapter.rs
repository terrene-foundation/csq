//! Provider output adapters — parse a spawned CLI's captured stdout into the shared
//! [`Completion`] shape.
//!
//! An adapter is a **pure** function over captured bytes: no spawning, no IO. That
//! keeps it unit-testable against a recorded fixture and keeps the spawn/timeout/env
//! machinery (which lives in the `csq` CLI crate) separate from output normalization.
//!
//! `csq.exec.v1` grounds exactly one adapter today — [`parse_claude_json`] for
//! `claude --print --output-format json`. A second provider is a second adapter here,
//! not a change to the envelope.

use crate::envelope::{Completion, FinishReason, Usage};
use crate::error::{SdkError, SdkErrorCode};

/// Parse the stdout of `claude --print --output-format json` into a [`Completion`].
///
/// Claude Code emits a **JSON array of events**; this adapter reads two of them:
///
/// - the `system`/`init` event supplies the model that actually SERVED the request
///   (which may differ from the requested `--model` under a server-side override —
///   memory `discovery_cc_model_default_not_csq_pinned`); and
/// - the final `type == "result"` event supplies `result` (the completion text),
///   `stop_reason` (mapped onto [`FinishReason`]), `usage`, and the `is_error` /
///   `subtype` pair that distinguishes a clean completion from a provider error.
///
/// # Errors
/// - [`SdkErrorCode::OutputParseFailed`] if the bytes are not a JSON array, or carry
///   no `result` event.
/// - [`SdkErrorCode::ProviderError`] if the result event reports `is_error == true`
///   (max-turns, execution error, …); the message is the result text (redacted).
pub fn parse_claude_json(stdout: &[u8]) -> Result<Completion, SdkError> {
    let root: serde_json::Value = serde_json::from_slice(stdout).map_err(|e| {
        SdkError::new(
            SdkErrorCode::OutputParseFailed,
            format!("claude json parse failed: {e}"),
        )
    })?;
    let events = root.as_array().ok_or_else(|| {
        SdkError::trusted(
            SdkErrorCode::OutputParseFailed,
            "claude --output-format json did not emit a JSON array of events",
        )
    })?;

    // Served model from the system/init event (best-effort; "unknown" if absent).
    let model = events
        .iter()
        .find(|e| {
            event_type(e) == Some("system")
                && e.get("subtype").and_then(|s| s.as_str()) == Some("init")
        })
        .and_then(|e| e.get("model"))
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();

    // The final result event (there is exactly one; scan from the end defensively).
    let result = events
        .iter()
        .rev()
        .find(|e| event_type(e) == Some("result"))
        .ok_or_else(|| {
            SdkError::trusted(
                SdkErrorCode::OutputParseFailed,
                "claude output contained no result event",
            )
        })?;

    let subtype = result.get("subtype").and_then(|s| s.as_str()).unwrap_or("");
    let is_error = result
        .get("is_error")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if is_error {
        // A provider-side error (max-turns, execution error). The exec envelope
        // becomes ok:false; the message is the result text or, failing that, subtype.
        let msg = result
            .get("result")
            .and_then(|r| r.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(subtype);
        return Err(SdkError::new(
            SdkErrorCode::ProviderError,
            format!("claude reported an error ({subtype}): {msg}"),
        ));
    }

    let text = result
        .get("result")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    let stop_reason = result.get("stop_reason").and_then(|s| s.as_str());
    let finish_reason = map_stop_reason(stop_reason);
    let usage = parse_usage(result.get("usage"));

    Ok(Completion {
        text,
        model,
        provider: "claude".to_string(),
        usage,
        finish_reason,
        finish_reason_raw: stop_reason.map(str::to_string),
    })
}

fn event_type(e: &serde_json::Value) -> Option<&str> {
    e.get("type").and_then(|t| t.as_str())
}

/// Map Claude's raw `stop_reason` onto the closed [`FinishReason`] vocabulary (R4).
/// An unknown or absent token defaults to `Stop` — a successful result event with no
/// recognized stop reason is a normal end-of-turn.
fn map_stop_reason(stop_reason: Option<&str>) -> FinishReason {
    match stop_reason {
        Some("max_tokens") => FinishReason::Length,
        Some("tool_use") => FinishReason::ToolUse,
        Some("refusal") => FinishReason::ContentFilter,
        // "end_turn", "stop_sequence", None, or any future token → natural stop.
        _ => FinishReason::Stop,
    }
}

fn parse_usage(usage: Option<&serde_json::Value>) -> Option<Usage> {
    let u = usage?;
    let field = |k: &str| u.get(k).and_then(serde_json::Value::as_u64);
    let out = Usage {
        input_tokens: field("input_tokens"),
        output_tokens: field("output_tokens"),
        cache_creation_input_tokens: field("cache_creation_input_tokens"),
        cache_read_input_tokens: field("cache_read_input_tokens"),
    };
    // If the usage object had none of our counters, surface null rather than an
    // all-None object.
    if out.input_tokens.is_none()
        && out.output_tokens.is_none()
        && out.cache_creation_input_tokens.is_none()
        && out.cache_read_input_tokens.is_none()
    {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed but structurally faithful capture of
    /// `claude -p 'Reply with exactly: ok' --output-format json --model sonnet`
    /// (recorded 2026-07-05). Secret-free by construction (no tokens in CC's
    /// result JSON); session_id/uuid replaced with placeholders.
    const CLAUDE_SUCCESS: &str = r#"[
      {"type":"system","subtype":"init","cwd":"/private/tmp","session_id":"sess-x","model":"claude-sonnet-5","permissionMode":"bypassPermissions"},
      {"type":"rate_limit_event"},
      {"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}},
      {"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"ok","stop_reason":"end_turn","session_id":"sess-x","total_cost_usd":0.0103,
       "usage":{"input_tokens":2,"cache_creation_input_tokens":0,"cache_read_input_tokens":32245,"output_tokens":4,"service_tier":"standard"}}
    ]"#;

    #[test]
    fn parses_served_model_text_finish_reason_and_usage() {
        let c = parse_claude_json(CLAUDE_SUCCESS.as_bytes()).unwrap();
        assert_eq!(c.text, "ok");
        assert_eq!(c.model, "claude-sonnet-5"); // SERVED model from system/init
        assert_eq!(c.provider, "claude");
        assert_eq!(c.finish_reason, FinishReason::Stop);
        assert_eq!(c.finish_reason_raw.as_deref(), Some("end_turn"));
        let u = c.usage.expect("usage present");
        assert_eq!(u.input_tokens, Some(2));
        assert_eq!(u.output_tokens, Some(4));
        assert_eq!(u.cache_read_input_tokens, Some(32245));
    }

    #[test]
    fn max_tokens_stop_reason_maps_to_length() {
        let json = r#"[
          {"type":"system","subtype":"init","model":"claude-opus-4-8"},
          {"type":"result","subtype":"success","is_error":false,"result":"partial","stop_reason":"max_tokens","usage":{"output_tokens":100}}
        ]"#;
        let c = parse_claude_json(json.as_bytes()).unwrap();
        assert_eq!(c.finish_reason, FinishReason::Length);
        assert_eq!(c.finish_reason_raw.as_deref(), Some("max_tokens"));
    }

    #[test]
    fn tool_use_stop_reason_maps_to_tool_use() {
        let json = r#"[{"type":"result","subtype":"success","is_error":false,"result":"","stop_reason":"tool_use"}]"#;
        let c = parse_claude_json(json.as_bytes()).unwrap();
        assert_eq!(c.finish_reason, FinishReason::ToolUse);
    }

    #[test]
    fn is_error_result_becomes_provider_error() {
        let json = r#"[
          {"type":"system","subtype":"init","model":"claude-opus-4-8"},
          {"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":5,"result":"reached max turns"}
        ]"#;
        let err = parse_claude_json(json.as_bytes()).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::ProviderError);
        assert!(err.message.as_str().contains("error_max_turns"));
    }

    #[test]
    fn non_array_output_is_parse_failed() {
        let err = parse_claude_json(br#"{"type":"result"}"#).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::OutputParseFailed);
    }

    #[test]
    fn missing_result_event_is_parse_failed() {
        let err = parse_claude_json(br#"[{"type":"system","subtype":"init"}]"#).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::OutputParseFailed);
    }

    #[test]
    fn garbage_bytes_are_parse_failed_not_panic() {
        let err = parse_claude_json(b"not json at all").unwrap_err();
        assert_eq!(err.code, SdkErrorCode::OutputParseFailed);
    }

    #[test]
    fn model_absent_defaults_to_unknown() {
        let json = r#"[{"type":"result","subtype":"success","is_error":false,"result":"hi","stop_reason":"end_turn"}]"#;
        let c = parse_claude_json(json.as_bytes()).unwrap();
        assert_eq!(c.model, "unknown");
        assert!(c.usage.is_none(), "no usage object → null usage");
    }
}
