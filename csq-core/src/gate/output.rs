//! Event-native result folding; denies survive all later row results.
use super::dispatch::{DispatchResult, RowFailure, RowOutput, MAX_ROW_OUTPUT_BYTES};
use super::registry;
use super::registry::{Event, FailurePolicy, HookRow, ProtocolKind};
use serde_json::{json, Value};

#[derive(Default)]
pub(super) struct Fold {
    denied: bool,
    failure: bool,
    rewrite: Option<Value>,
    values: Vec<(Value, bool)>,
    raw: Vec<Vec<u8>>,
    raw_denied: Vec<bool>,
    stderr: Vec<u8>,
    original_exit: i32,
    output_bytes: usize,
    reserved_bytes: usize,
}
impl Fold {
    pub(super) fn retain_exit_two(&mut self, exit_code: i32) {
        if exit_code == 2 {
            self.denied = true;
            self.original_exit = 2;
        }
    }
    pub(super) fn reserve_native(&mut self, bytes: usize) -> bool {
        if bytes > MAX_ROW_OUTPUT_BYTES {
            return false;
        }
        self.reserved_bytes = bytes;
        true
    }
    pub(super) fn release_native(&mut self) {
        self.reserved_bytes = 0;
    }
    pub(super) fn failed(&mut self, row: &HookRow, failure: RowFailure) {
        let policy = match failure {
            RowFailure::Incomplete => row.on_incomplete,
            RowFailure::Crash => row.on_crash,
            RowFailure::Timeout => row.on_timeout,
            RowFailure::DemotionLedger => FailurePolicy::Deny,
        };
        if policy == FailurePolicy::Deny {
            self.failure(match failure {
                RowFailure::Incomplete => "hook_row_incomplete",
                RowFailure::Crash => "hook_row_crashed",
                RowFailure::Timeout => "hook_row_timed_out",
                RowFailure::DemotionLedger => "hook_demotion_ledger_unavailable",
            });
        }
    }
    pub(super) fn failure(&mut self, reason: &str) {
        self.denied = true;
        self.failure = true;
        let body = remediation(reason);
        self.stderr.extend_from_slice(body.as_bytes());
        self.stderr.push(b'\n');
    }
    pub(super) fn accept(
        &mut self,
        event: Event,
        output: &RowOutput,
        row: Option<&HookRow>,
    ) -> Result<(), RowFailure> {
        // An actual native denial is authoritative even when its diagnostic
        // output cannot be admitted. A continue-on-incomplete policy only
        // covers the diagnostic failure; it cannot downgrade exit code 2.
        self.retain_exit_two(output.exit_code);
        let bytes = output
            .stdout
            .len()
            .checked_add(output.stderr.len())
            .ok_or(RowFailure::Incomplete)?;
        if bytes > MAX_ROW_OUTPUT_BYTES
            || self.output_bytes.saturating_add(bytes)
                > MAX_ROW_OUTPUT_BYTES.saturating_sub(self.reserved_bytes)
        {
            return Err(RowFailure::Incomplete);
        }
        if !matches!(output.exit_code, 0 | 2) {
            return Err(RowFailure::Crash);
        }
        // Count admitted bytes and retain bounded stderr before decoding stdout.
        // Failed decoding may continue, but must not discard native diagnostics
        // or let multiple malformed rows bypass the aggregate output ceiling.
        self.output_bytes += bytes;
        self.stderr.extend_from_slice(&output.stderr);
        if !output.stderr.is_empty() && !output.stderr.ends_with(b"\n") {
            self.stderr.push(b'\n');
        }
        let value = if output.stdout.is_empty() {
            None
        } else {
            let text = std::str::from_utf8(&output.stdout).map_err(|_| RowFailure::Incomplete)?;
            if !text.trim_start().starts_with('{') {
                Some(Value::String(text.to_owned()))
            } else {
                let value =
                    registry::strict_json(&output.stdout).map_err(|_| RowFailure::Incomplete)?;
                if !value.is_object()
                    || value.get("continue") == Some(&Value::Bool(false))
                    || value.get("stopReason").is_some()
                {
                    return Err(RowFailure::Incomplete);
                }
                Some(value)
            }
        };
        let mut denied = output.exit_code == 2;
        if let Some(value) = value.as_ref().filter(|value| value.is_object()) {
            validate_output(value, event)?;
            let specific = value.get("hookSpecificOutput");
            if specific
                .and_then(|v| v.get("hookEventName"))
                .is_some_and(|name| name.as_str() != Some(event.as_str()))
            {
                return Err(RowFailure::Incomplete);
            }
            if let Some(rewrite) = specific.and_then(|v| v.get("updatedInput")) {
                if event != Event::PreToolUse
                    || !row.is_some_and(|r| {
                        r.contract.may_rewrite_input
                            && r.contract.protocol.kind == ProtocolKind::PermissionDecision
                            && r.contract
                                .protocol
                                .decision_fields
                                .iter()
                                .any(|field| field == "updatedInput")
                    })
                    || !rewrite.is_object()
                {
                    return Err(RowFailure::Incomplete);
                }
                if self
                    .rewrite
                    .as_ref()
                    .is_some_and(|earlier| earlier != rewrite)
                {
                    self.failure("hook_rewrite_conflict");
                } else {
                    self.rewrite = Some(rewrite.clone());
                }
            }
            denied |= value.get("decision").and_then(Value::as_str) == Some("block")
                || specific
                    .and_then(|v| v.get("permissionDecision"))
                    .and_then(Value::as_str)
                    == Some("deny");
        }
        self.denied |= denied;
        self.original_exit = self.original_exit.max(output.exit_code);
        if let Some(value) = value {
            self.values.push((value, denied));
            self.raw.push(output.stdout.clone());
            self.raw_denied.push(denied);
        }
        Ok(())
    }
    pub(super) fn finish(mut self, event: Event) -> DispatchResult {
        // A sole accepted native/repository body is byte-identical, including
        // Stop decision:block, unless dispatcher failures/rewrite filtering alter it.
        if !self.failure
            && self.raw.len() == 1
            && self.raw_denied[0] == self.denied
            && (!self.denied || self.rewrite.is_none())
            && (self.original_exit != 2 || !self.stderr.is_empty())
        {
            return DispatchResult {
                denied: self.denied,
                stdout: self.raw.remove(0),
                stderr: self.stderr,
                exit_code: self.original_exit,
            };
        }
        let mut contexts = Vec::new();
        let mut messages = Vec::new();
        let mut reasons = Vec::new();
        let mut permission = None;
        for (value, denied) in &self.values {
            if let Some(text) = value.as_str() {
                // Claude injects successful plain stdout as context only on these
                // events. Exit-2 diagnostics come from stderr, never stdout.
                if matches!(
                    event,
                    Event::SessionStart | Event::UserPromptSubmit | Event::PreCompact
                ) && !denied
                {
                    contexts.push(text);
                }
                continue;
            }
            if let Some(text) = value.get("systemMessage").and_then(Value::as_str) {
                messages.push(text);
            }
            if let Some(text) = value.get("reason").and_then(Value::as_str) {
                reasons.push(text);
            }
            // Claude's deprecated PreToolUse approve maps to modern allow.
            if event == Event::PreToolUse
                && value.get("decision").and_then(Value::as_str) == Some("approve")
                && permission != Some("ask")
            {
                permission = Some("allow");
            }
            if let Some(specific) = value.get("hookSpecificOutput") {
                if let Some(decision) = specific.get("permissionDecision").and_then(Value::as_str) {
                    if permission != Some("ask") || decision == "ask" {
                        permission = Some(decision);
                    }
                }
                if let Some(text) = specific.get("additionalContext").and_then(Value::as_str) {
                    contexts.push(text);
                }
                if let Some(text) = specific
                    .get("permissionDecisionReason")
                    .and_then(Value::as_str)
                {
                    reasons.push(text);
                }
            }
        }
        let mut value = json!({});
        if event == Event::PreCompact && !self.denied {
            return DispatchResult {
                denied: false,
                stdout: contexts.join("\n").into_bytes(),
                stderr: self.stderr,
                exit_code: self.original_exit,
            };
        }
        let mut specific = json!({"hookEventName":event.as_str()});
        if !contexts.is_empty() {
            specific["additionalContext"] = contexts.join("\n").into();
        }
        if !messages.is_empty() {
            value["systemMessage"] = messages.join("\n").into();
        }
        if self.denied {
            let reason = if self.failure || reasons.iter().all(|reason| reason.is_empty()) {
                remediation("gate_refused")
            } else {
                reasons.join("\n")
            };
            if event == Event::PreToolUse {
                specific["permissionDecision"] = "deny".into();
                specific["permissionDecisionReason"] = reason.clone().into();
            } else if matches!(
                event,
                Event::PostToolUse
                    | Event::Stop
                    | Event::SubagentStop
                    | Event::UserPromptSubmit
                    | Event::PreCompact
            ) {
                value["decision"] = "block".into();
                value["reason"] = reason.clone().into();
            } else {
                value["systemMessage"] = reason.clone().into();
            }
            if self.stderr.is_empty() {
                self.stderr.extend_from_slice(reason.as_bytes());
            }
        } else {
            if let Some(permission) = permission {
                specific["permissionDecision"] = permission.into();
                if !reasons.is_empty() {
                    specific["permissionDecisionReason"] = reasons.join("\n").into();
                }
            }
            if let Some(rewrite) = self.rewrite {
                specific["updatedInput"] = rewrite;
            }
        }
        if specific.as_object().is_some_and(|map| map.len() > 1) {
            value["hookSpecificOutput"] = specific;
        }
        let stdout = if value.as_object().is_some_and(|map| map.is_empty()) {
            Vec::new()
        } else {
            value.to_string().into_bytes()
        };
        // PostToolUse feedback cannot undo a completed action. Lifecycle denials
        // are feedback; no continue:false or stopReason is ever emitted.
        let exit_code = if self.denied && event == Event::PreToolUse {
            2
        } else {
            self.original_exit
        };
        DispatchResult {
            denied: self.denied,
            stdout,
            stderr: self.stderr,
            exit_code,
        }
    }
}

fn validate_output(value: &Value, event: Event) -> Result<(), RowFailure> {
    for key in ["systemMessage", "reason"] {
        if value.get(key).is_some_and(|v| !v.is_string()) {
            return Err(RowFailure::Incomplete);
        }
    }
    if value
        .get("continue")
        .is_some_and(|v| v != &Value::Bool(true))
    {
        return Err(RowFailure::Incomplete);
    }
    if value
        .get("decision")
        .is_some_and(|v| !matches!(v.as_str(), Some("block" | "approve")))
    {
        return Err(RowFailure::Incomplete);
    }
    if let Some(specific) = value.get("hookSpecificOutput") {
        if !specific.is_object()
            || specific.get("hookEventName").and_then(Value::as_str) != Some(event.as_str())
        {
            return Err(RowFailure::Incomplete);
        }
        for key in ["additionalContext", "permissionDecisionReason"] {
            if specific.get(key).is_some_and(|v| !v.is_string()) {
                return Err(RowFailure::Incomplete);
            }
        }
        if specific.get("permissionDecision").is_some_and(|v| {
            event != Event::PreToolUse || !matches!(v.as_str(), Some("allow" | "deny" | "ask"))
        }) {
            return Err(RowFailure::Incomplete);
        }
    }
    Ok(())
}

fn remediation(reason: &str) -> String {
    json!({"severity":"block", "what_happened":"The hook decision could not be completed safely.",
        "why":reason,"agent_must_report":["Report the incomplete hook check and its cause."],
        "agent_must_wait":"Resolve the hook admission or runtime failure before retrying; review changed hook bytes before re-pinning.",
        "user_summary":"Hook dispatch refused an incomplete decision."}).to_string()
}
