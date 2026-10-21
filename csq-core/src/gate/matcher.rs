//! Claude matcher semantics, with an explicit incomplete result for JS syntax
//! outside the native subset. A legacy event host can supply a full JS matcher.
use super::registry::Event;
use regex::RegexBuilder;
use serde_json::Value;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchError {
    InvalidInput,
    UnsupportedPattern,
    Timeout,
}

pub trait Matcher {
    fn matches(
        &mut self,
        event: Event,
        pattern: &str,
        payload: &Value,
        deadline: Instant,
    ) -> Result<bool, MatchError>;
}

/// Exact/list matchers and a conservative ASCII JS-compatible regex subset.
/// No equivalence claim for arbitrary JavaScript RegExp: lookarounds,
/// backreferences, Unicode, character classes and JS identity escapes refuse.
#[derive(Default)]
pub struct NativeMatcher;

impl Matcher for NativeMatcher {
    fn matches(
        &mut self,
        event: Event,
        pattern: &str,
        payload: &Value,
        deadline: Instant,
    ) -> Result<bool, MatchError> {
        if Instant::now() >= deadline {
            return Err(MatchError::Timeout);
        }
        // Claude ignores matcher fields on these events.
        let field = match event {
            Event::PreToolUse | Event::PostToolUse => "tool_name",
            Event::SessionStart => "source",
            Event::SessionEnd => "reason",
            Event::PreCompact => "trigger",
            Event::SubagentStop => "agent_type",
            Event::UserPromptSubmit | Event::Stop => return Ok(true),
        };
        if pattern.is_empty() || pattern == "*" {
            return Ok(true);
        }
        let target = payload
            .get(field)
            .and_then(Value::as_str)
            .ok_or(MatchError::InvalidInput)?;
        if target.len() > 4096 || target.chars().any(char::is_control) {
            return Err(MatchError::InvalidInput);
        }
        // Current Claude exact-path alphabet; alternatives match whole strings,
        // case-sensitively, with comma or pipe and surrounding whitespace.
        if pattern
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_- ,|".contains(&b))
        {
            return Ok(pattern.split(['|', ',']).any(|part| part.trim() == target));
        }
        if !target.is_ascii() || !compatible_regex(pattern) {
            return Err(MatchError::UnsupportedPattern);
        }
        let regex = RegexBuilder::new(pattern)
            .size_limit(512 * 1024)
            .dfa_size_limit(128 * 1024)
            .build()
            .map_err(|_| MatchError::UnsupportedPattern)?;
        if Instant::now() >= deadline {
            return Err(MatchError::Timeout);
        }
        Ok(regex.is_match(target)) // JS RegExp.test is unanchored.
    }
}

fn compatible_regex(pattern: &str) -> bool {
    if pattern.len() > 4096 || !pattern.is_ascii() {
        return false;
    }
    let bytes = pattern.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_control() || matches!(byte, b'[' | b']') {
            return false;
        }
        if byte == b'\\' {
            index += 1;
            if index == bytes.len() || !b"\\^$.*+?(){}|/dDwWsSbBnrtvf".contains(&bytes[index]) {
                return false;
            }
        } else if byte == b'(' && bytes.get(index + 1) == Some(&b'?') {
            if bytes.get(index + 2) != Some(&b':') {
                return false;
            }
            index += 2;
        } else if byte == b'{' {
            let Some(end) = bytes[index + 1..].iter().position(|b| *b == b'}') else {
                return false;
            };
            let quantifier = &pattern[index + 1..index + 1 + end];
            let mut parts = quantifier.split(',');
            if !parts
                .next()
                .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                || !parts
                    .next()
                    .is_none_or(|part| part.bytes().all(|b| b.is_ascii_digit()))
                || parts.next().is_some()
            {
                return false;
            }
            index += end + 1;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn matches(event: Event, pattern: &str, payload: Value) -> Result<bool, MatchError> {
        NativeMatcher.matches(
            event,
            pattern,
            &payload,
            Instant::now() + Duration::from_secs(1),
        )
    }

    #[test]
    fn claude_exact_lists_do_not_match_substrings_but_regex_does() {
        let input = json!({"tool_name":"NotebookEdit"});
        assert_eq!(matches(Event::PreToolUse, "Edit", input.clone()), Ok(false));
        assert_eq!(
            matches(Event::PreToolUse, "Edit|Write", input.clone()),
            Ok(false)
        );
        assert_eq!(matches(Event::PreToolUse, "Edit.*", input), Ok(true));
        assert_eq!(
            matches(
                Event::PreToolUse,
                "Edit, Write",
                json!({"tool_name":"Write"})
            ),
            Ok(true)
        );
        assert_eq!(
            matches(Event::PreToolUse, "Bash", json!({"tool_name":"bash"})),
            Ok(false)
        );
        assert_eq!(
            matches(
                Event::PreToolUse,
                "^Edit$",
                json!({"tool_name":"NotebookEdit"})
            ),
            Ok(false)
        );
        assert_eq!(
            matches(
                Event::PreToolUse,
                "mcp__memory__.*",
                json!({"tool_name":"mcp__memory__write"})
            ),
            Ok(true)
        );
    }

    #[test]
    fn claude_matcher_event_axes_and_ignored_matchers() {
        assert_eq!(
            matches(
                Event::SubagentStop,
                "Explore",
                json!({"agent_type":"Explore", "tool_name":"Bash"})
            ),
            Ok(true)
        );
        assert_eq!(
            matches(
                Event::SubagentStop,
                "Bash",
                json!({"agent_type":"Explore", "tool_name":"Bash"})
            ),
            Ok(false)
        );
        assert_eq!(
            matches(
                Event::SessionStart,
                "resume",
                json!({"source":"resume","tool_name":"Bash"})
            ),
            Ok(true)
        );
        assert_eq!(
            matches(Event::SessionEnd, "logout", json!({"reason":"logout"})),
            Ok(true)
        );
        assert_eq!(
            matches(Event::PreCompact, "auto", json!({"trigger":"manual"})),
            Ok(false)
        );
        assert_eq!(
            matches(Event::UserPromptSubmit, "does-not-match", json!({})),
            Ok(true)
        );
        assert_eq!(matches(Event::Stop, "[", json!({})), Ok(true));
        for pattern in ["", "*"] {
            assert_eq!(matches(Event::PostToolUse, pattern, json!({})), Ok(true));
        }
    }

    #[test]
    fn unsupported_js_semantics_are_incomplete_instead_of_no_match() {
        for pattern in [
            "(?i)Bash",
            "(?=Bash)Bash",
            "(Bash)\\1",
            "\\AEdit",
            "[a&&b]",
            "\\u0042ash",
        ] {
            assert_eq!(
                matches(Event::PreToolUse, pattern, json!({"tool_name":"Bash"})),
                Err(MatchError::UnsupportedPattern),
                "{pattern}"
            );
        }
        assert_eq!(
            matches(Event::PreToolUse, "Bash", json!({})),
            Err(MatchError::InvalidInput)
        );
        assert_eq!(
            matches(Event::PreToolUse, "^Bash$", json!({"tool_name":"Bash\n"})),
            Err(MatchError::InvalidInput)
        );
    }
}
