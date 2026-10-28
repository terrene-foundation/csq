//! The base envelope, the `emit()` stdout choke point, and the reusable
//! completion-core body.
//!
//! See the module docs (`super`) for the R1–R5 invariants this file implements.

use std::io::{self, Write};

use serde::Serialize;

use crate::error::SdkError;

/// Normalized, closed finish-reason vocabulary (**R4**).
///
/// Every op maps its provider's raw stop token onto exactly one of these; the raw
/// token is preserved separately in [`Completion::finish_reason_raw`] so no
/// information is lost while the normalized field stays a stable, matchable set.
///
/// `#[non_exhaustive]`: this is a closed vocabulary at any given crate version, but
/// is expected to gain members over time (a new provider-reported stop condition).
/// Sealing forces an external `match` to carry a `_ =>` fallback so a future variant
/// degrades gracefully instead of failing to compile. Unit-variant construction
/// (`FinishReason::Stop`) is unaffected by `#[non_exhaustive]` on the enum itself —
/// only exhaustive matching is restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FinishReason {
    /// The model stopped at a natural end of turn.
    Stop,
    /// Generation hit the output-token ceiling (truncated).
    Length,
    /// The model emitted a tool call (agentic turn boundary).
    ToolUse,
    /// Output was withheld by a content filter.
    ContentFilter,
    /// The turn ended in an error state (max-turns, execution error, non-zero exit).
    Error,
}

/// Token usage as surfaced by the provider — **raw counts only**.
///
/// `cost_usd` is intentionally absent in v1: csq has no per-provider price table, so
/// exposing a derived cost would be a fabricated number (plan / deep-analyst MED-3).
/// A consumer that wants cost multiplies these counts by its own price table.
/// Every field is optional because not every surface reports every counter.
///
/// `#[non_exhaustive]`: every field here is already optional, so the ergonomic
/// external constructor is `Usage::default()` (all `None`, via the derived
/// [`Default`] — a normal function call, unaffected by sealing) followed by the
/// `with_*` builder methods below.
#[derive(Debug, Clone, Default, Serialize)]
#[non_exhaustive]
pub struct Usage {
    /// Prompt (input) tokens billed for this completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Completion (output) tokens generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// Tokens written to the prompt cache (Anthropic surfaces this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u64>,
    /// Tokens served from the prompt cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u64>,
}

impl Usage {
    /// Set `input_tokens`. Accepts `u64` (⇒ `Some`) or `Option<u64>` directly, so a
    /// caller with an already-optional count (`stats.get(..).and_then(as_u64)`)
    /// does not need to unwrap first.
    #[must_use]
    pub fn with_input_tokens(mut self, tokens: impl Into<Option<u64>>) -> Self {
        self.input_tokens = tokens.into();
        self
    }

    /// Set `output_tokens`. Same `Into<Option<u64>>` flexibility as
    /// [`Self::with_input_tokens`].
    #[must_use]
    pub fn with_output_tokens(mut self, tokens: impl Into<Option<u64>>) -> Self {
        self.output_tokens = tokens.into();
        self
    }

    /// Set `cache_creation_input_tokens`. Same `Into<Option<u64>>` flexibility as
    /// [`Self::with_input_tokens`].
    #[must_use]
    pub fn with_cache_creation_input_tokens(mut self, tokens: impl Into<Option<u64>>) -> Self {
        self.cache_creation_input_tokens = tokens.into();
        self
    }

    /// Set `cache_read_input_tokens`. Same `Into<Option<u64>>` flexibility as
    /// [`Self::with_input_tokens`].
    #[must_use]
    pub fn with_cache_read_input_tokens(mut self, tokens: impl Into<Option<u64>>) -> Self {
        self.cache_read_input_tokens = tokens.into();
        self
    }
}

/// The reusable completion body embedded verbatim by `csq.exec.v1` (and, in S4, by
/// `csq.eval.v1`).
///
/// Factored as its own struct (plan deep-analyst C2 / requirements ADR-1) so that a
/// later op which also returns a model completion reuses this shape rather than
/// re-declaring a parallel one that can drift.
///
/// `#[non_exhaustive]`: construct via [`Completion::new`] (the four
/// always-present fields) then [`Completion::with_usage`] /
/// [`Completion::with_finish_reason_raw`] for the two optional ones.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Completion {
    /// The model's output text. **R5:** caller-owned, NOT redacted (redacting legit
    /// output would corrupt it) — but only ever written through [`emit`].
    pub text: String,
    /// The model that actually SERVED the request. May differ from the requested
    /// `--model` when a server-side override (e.g. GrowthBook) is in effect
    /// (memory `discovery_cc_model_default_not_csq_pinned`).
    pub model: String,
    /// The provider surface that produced this completion (`"claude"`, …).
    pub provider: String,
    /// Raw token usage, when the surface reported it; `null`/absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Normalized finish reason (**R4**).
    pub finish_reason: FinishReason,
    /// The provider's raw stop token, preserved for debugging / forward-compat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason_raw: Option<String>,
}

impl Completion {
    /// Build a `Completion` from its four always-present fields; `usage` and
    /// `finish_reason_raw` start `None` — attach them with [`Self::with_usage`] /
    /// [`Self::with_finish_reason_raw`] when the surface reported them.
    #[must_use]
    pub fn new(
        text: impl Into<String>,
        model: impl Into<String>,
        provider: impl Into<String>,
        finish_reason: FinishReason,
    ) -> Self {
        Self {
            text: text.into(),
            model: model.into(),
            provider: provider.into(),
            usage: None,
            finish_reason,
            finish_reason_raw: None,
        }
    }

    /// Attach token usage. Accepts `Usage` (⇒ `Some`) or `Option<Usage>` directly,
    /// so a caller that only sometimes has usage (e.g. absent `stats` object) does
    /// not need to unwrap first.
    #[must_use]
    pub fn with_usage(mut self, usage: impl Into<Option<Usage>>) -> Self {
        self.usage = usage.into();
        self
    }

    /// Attach the provider's raw stop token. Accepts a bare string (⇒ `Some`) or
    /// `Option<String>` directly, same flexibility as [`Self::with_usage`].
    #[must_use]
    pub fn with_finish_reason_raw(mut self, raw: impl Into<Option<String>>) -> Self {
        self.finish_reason_raw = raw.into();
        self
    }
}

/// The stdout envelope wrapping every op's result.
///
/// `schema` and `ok` are present on EVERY line; the op-specific `payload` fields are
/// flattened inline whenever a payload was produced. `id` echoes the caller's `--id`
/// when supplied (the hook that lets a future daemon route responses without a schema
/// bump — plan requirements C1).
///
/// ## The `error`-vs-`payload` invariant
///
/// `error` is present iff the op **could not produce its result payload** — a hard
/// op failure (bad input, spawn failure, timeout). This is a refinement of the
/// original "`error` present iff `!ok`": it still holds for a *value-or-nothing* op
/// like `exec` (a failed exec has no completion, so `!ok` ⟹ error ⟹ no payload —
/// [`Envelope::failure`]), but it also admits a *verdict* op like `audit verify` (S2)
/// or `eval` (S4) whose result IS a verdict. A verdict op ALWAYS produces its payload
/// — even when the verdict is negative — so it carries `ok:false` **with** a payload
/// and **no** `error` ([`Envelope::verdict`]). For a verdict op, `ok` is the health
/// signal a consumer gates on (chain verified / policy passed), not "the command ran".
///
/// Construct via [`Envelope::success`] (value ok), [`Envelope::failure`] (value error),
/// or [`Envelope::verdict`] (verdict + payload); each takes the op's compile-time
/// `schema` constant so the wire `schema` value cannot drift from the op.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Envelope<T: Serialize> {
    /// The op's stable schema string (e.g. [`super::SCHEMA_EXEC_V1`]).
    pub schema: &'static str,
    /// `true` on success, `false` on any failure.
    pub ok: bool,
    /// The caller-supplied correlation id, echoed verbatim when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The error object — present iff the op could not produce a payload (**R2**).
    /// A verdict op ([`Envelope::verdict`]) with `ok:false` still carries a payload
    /// and NO error; only a value-or-nothing failure ([`Envelope::failure`]) sets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SdkError>,
    /// The op-specific payload, flattened inline. `None` only on a hard failure
    /// ([`Envelope::failure`]); a verdict envelope carries it regardless of `ok`.
    #[serde(flatten)]
    pub payload: Option<T>,
}

impl<T: Serialize> Envelope<T> {
    /// A success envelope: `ok = true`, payload inlined, no error.
    #[must_use]
    pub fn success(schema: &'static str, id: Option<String>, payload: T) -> Self {
        Self {
            schema,
            ok: true,
            id,
            error: None,
            payload: Some(payload),
        }
    }

    /// A failure envelope: `ok = false`, error present, no payload.
    #[must_use]
    pub fn failure(schema: &'static str, id: Option<String>, error: SdkError) -> Self {
        Self {
            schema,
            ok: false,
            id,
            error: Some(error),
            payload: None,
        }
    }

    /// A verdict envelope: the op DID produce its result (`payload` present, no
    /// `error`), but that result is a health/pass-fail verdict the caller reflects
    /// in `ok`. Used by verdict ops (`audit verify` — S2; `eval` — S4) where a
    /// negative verdict is data, not an op failure. `ok:false` here means "the
    /// subject did not pass" (chain broken, policy failed), NOT "the command errored".
    #[must_use]
    pub fn verdict(schema: &'static str, id: Option<String>, ok: bool, payload: T) -> Self {
        Self {
            schema,
            ok,
            id,
            error: None,
            payload: Some(payload),
        }
    }

    /// Serialize this envelope to exactly one line of JSON (no trailing newline).
    ///
    /// `serde_json` escapes every control character (including `\n`) inside string
    /// values, so a completion's `text` — however adversarial — serializes to a
    /// single physical line and cannot forge a second envelope (**R3**).
    ///
    /// # Errors
    /// Returns the underlying `serde_json` error if the payload is not serializable
    /// (a programming error for the hand-authored DTOs in this module).
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// **R3 — the single stdout writer for every SDK envelope.**
///
/// Serializes `env` to one JSON line and writes it, `\n`-terminated, to stdout under a
/// held lock, then flushes. No other code path in an op's call graph may write to
/// stdout; all diagnostics belong on stderr. Returns the process exit code the caller
/// should propagate: `0` when `env.ok`, `1` otherwise.
///
/// # Errors
/// Returns an [`io::Error`] if serialization fails (mapped to `InvalidData`) or the
/// stdout write/flush fails (e.g. a closed pipe).
pub fn emit<T: Serialize>(env: &Envelope<T>) -> io::Result<i32> {
    debug_assert!(
        env.schema.starts_with("csq."),
        "envelope schema must be a csq.<op>.vN constant, got {:?}",
        env.schema
    );
    let line = env
        .to_line()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(line.as_bytes())?;
    lock.write_all(b"\n")?;
    lock.flush()?;
    Ok(if env.ok { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SdkErrorCode;
    use crate::SCHEMA_EXEC_V1;

    /// A minimal exec-style payload for envelope tests.
    #[derive(Debug, Serialize)]
    struct ExecPayload {
        completion: Completion,
    }

    fn sample_completion(text: &str) -> Completion {
        Completion {
            text: text.to_string(),
            model: "claude-opus-4-8".to_string(),
            provider: "claude".to_string(),
            usage: Some(Usage {
                input_tokens: Some(12),
                output_tokens: Some(34),
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            }),
            finish_reason: FinishReason::Stop,
            finish_reason_raw: Some("end_turn".to_string()),
        }
    }

    #[test]
    fn success_envelope_has_schema_ok_and_flattened_payload_no_error() {
        let env = Envelope::success(
            SCHEMA_EXEC_V1,
            None,
            ExecPayload {
                completion: sample_completion("hi"),
            },
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.exec.v1");
        assert_eq!(v["ok"], true);
        assert!(v.get("error").is_none(), "no error field on success");
        // payload flattened inline (not nested under "payload")
        assert!(v.get("payload").is_none());
        assert_eq!(v["completion"]["text"], "hi");
        assert_eq!(v["completion"]["finish_reason"], "stop");
        assert_eq!(v["completion"]["finish_reason_raw"], "end_turn");
    }

    #[test]
    fn failure_envelope_has_error_and_no_payload() {
        let env: Envelope<ExecPayload> = Envelope::failure(
            SCHEMA_EXEC_V1,
            Some("req-7".to_string()),
            SdkError::trusted(SdkErrorCode::InvalidInput, "prompt must not be empty"),
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.exec.v1");
        assert_eq!(v["ok"], false);
        assert_eq!(v["id"], "req-7");
        assert_eq!(v["error"]["code"], "invalid_input");
        assert_eq!(v["error"]["message"], "prompt must not be empty");
        assert!(v.get("completion").is_none());
    }

    #[test]
    fn verdict_envelope_carries_payload_with_ok_false_and_no_error() {
        // The verdict invariant (S2/S4): a negative verdict still carries its
        // payload and NO error object — distinct from `failure()`.
        let env = Envelope::verdict(
            SCHEMA_EXEC_V1,
            None,
            false,
            ExecPayload {
                completion: sample_completion("verdict body"),
            },
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert!(
            v.get("error").is_none(),
            "a verdict envelope has no error object"
        );
        assert_eq!(
            v["completion"]["text"], "verdict body",
            "the payload is present despite ok:false"
        );
    }

    #[test]
    fn id_is_omitted_when_absent() {
        let env: Envelope<ExecPayload> = Envelope::failure(
            SCHEMA_EXEC_V1,
            None,
            SdkError::trusted(SdkErrorCode::Internal, "x"),
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert!(v.get("id").is_none(), "id omitted when None");
    }

    #[test]
    fn completion_text_with_newline_serializes_to_a_single_line() {
        // R3: an adversarial completion cannot forge a second envelope line.
        let env = Envelope::success(
            SCHEMA_EXEC_V1,
            None,
            ExecPayload {
                completion: sample_completion(
                    "line1\nline2\n{\"schema\":\"csq.exec.v1\",\"ok\":true}",
                ),
            },
        );
        let line = env.to_line().unwrap();
        assert_eq!(
            line.matches('\n').count(),
            0,
            "serialized envelope must contain zero literal newlines: {line}"
        );
        // …and it still round-trips to the original text.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v["completion"]["text"]
            .as_str()
            .unwrap()
            .contains("line1\nline2"));
    }

    #[test]
    fn usage_omits_none_counters() {
        let env = Envelope::success(
            SCHEMA_EXEC_V1,
            None,
            ExecPayload {
                completion: sample_completion("x"),
            },
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let usage = &v["completion"]["usage"];
        assert_eq!(usage["input_tokens"], 12);
        assert!(
            usage.get("cache_creation_input_tokens").is_none(),
            "None usage counters are omitted, not serialized as null"
        );
    }
}
