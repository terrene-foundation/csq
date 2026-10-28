//! Key validation via HTTP probe.
//!
//! Sends a `max_tokens=1` test request to the provider endpoint and
//! classifies the response.

use super::catalog::Provider;

/// Result of a key validation probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Key is valid (HTTP 200).
    Valid,
    /// Key is invalid (HTTP 401 or 403).
    Invalid,
    /// Endpoint unreachable (network error, DNS, timeout).
    Unreachable(String),
    /// Unexpected response (other status or malformed response).
    Unexpected { status: u16, body: String },
}

/// Builds the JSON body for a validation probe request.
///
/// Format: minimal Anthropic-compatible message request with max_tokens=1.
///
/// The model goes through
/// [`strip_context_annotation`](super::models::strip_context_annotation): the
/// catalog defaults carry Claude Code's `[1m]` annotation (`k3.1-pro[1m]`,
/// `glm-5.3[1m]`), which the raw API rejects with HTTP 400 (live probe
/// 2026-10-24). Sent raw, a valid key validated as `Unexpected { 400 }`.
pub fn build_probe_body(model: &str) -> String {
    serde_json::json!({
        "model": super::models::strip_context_annotation(model),
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "."}]
    })
    .to_string()
}

/// Returns the headers needed for a provider's validation probe.
pub fn build_probe_headers(provider: &Provider, api_key: &str) -> Vec<(String, String)> {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];

    match provider.auth_type {
        super::catalog::AuthType::OAuth | super::catalog::AuthType::Bearer => {
            // Anthropic and Anthropic-compatible APIs use x-api-key OR Authorization
            if provider.id == "claude" {
                headers.push(("x-api-key".to_string(), api_key.to_string()));
                headers.push(("anthropic-version".to_string(), "2023-06-01".to_string()));
            } else {
                headers.push(("Authorization".to_string(), format!("Bearer {api_key}")));
            }
        }
        super::catalog::AuthType::None => {}
    }

    headers
}

/// Classifies an HTTP response into a validation result.
///
/// This is a pure function — it takes the HTTP status code and body,
/// and returns the corresponding ValidationResult. The actual HTTP call
/// is delegated to the caller to keep this module transport-agnostic.
pub fn classify_response(status: u16, body: &str) -> ValidationResult {
    classify_response_for_secrets(status, body, &[])
}

/// [`classify_response`] for a caller that holds the submitted key: the key
/// (whole, segments, and truncated prefixes) is scrubbed structurally before
/// shape redaction and the 200-char cut (`csq_redact::scrub_secrets`).
pub fn classify_response_for_secret(status: u16, body: &str, api_key: &str) -> ValidationResult {
    classify_response_for_secrets(status, body, &[api_key])
}

fn classify_response_for_secrets(status: u16, body: &str, secrets: &[&str]) -> ValidationResult {
    match status {
        200..=299 => ValidationResult::Valid,
        401 | 403 => ValidationResult::Invalid,
        _ => ValidationResult::Unexpected {
            status,
            // Scrub held secrets, redact the WHOLE body, and only THEN
            // truncate to 200 chars. Some 3P bridges (DeepSeek, custom
            // proxies) echo a partial or full token in 4xx response bodies;
            // truncating first would cut a token crossing the limit to a
            // stub that no longer matches a redaction pattern (security
            // review HIGH-1).
            body: crate::error::redact_excerpt_with_secrets(body.as_bytes(), secrets, 200),
        },
    }
}

/// Validates a key using an injected HTTP function.
///
/// The `http_post` function receives `(url, headers, body)` and returns
/// either `Ok((status, body))` on HTTP success, or `Err(message)` on
/// connection failure.
pub fn validate_key<F>(provider: &Provider, api_key: &str, http_post: F) -> ValidationResult
where
    F: FnOnce(&str, &[(String, String)], &str) -> Result<(u16, String), String>,
{
    let endpoint = match provider.validation_endpoint {
        Some(e) => e,
        None => return ValidationResult::Unreachable("no validation endpoint".into()),
    };

    let headers = build_probe_headers(provider, api_key);
    let body = build_probe_body(provider.default_model);

    match http_post(endpoint, &headers, &body) {
        Ok((status, body)) => classify_response_for_secret(status, &body, api_key),
        Err(e) => ValidationResult::Unreachable(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::catalog::get_provider;
    use super::*;

    fn unexpected_body(result: ValidationResult) -> String {
        match result {
            ValidationResult::Unexpected { body, .. } => body,
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }

    /// A token echoed across the 200-char excerpt boundary MUST be redacted
    /// in full (redact the whole body, then truncate).
    #[test]
    fn classify_unexpected_redacts_token_straddling_truncation_point() {
        let mut body = "x".repeat(189);
        body.push(' ');
        body.push_str("sk-ant-api03-FAKETESTstraddle0123456789abcdefghij");
        body.push(' ');
        body.push_str(&"y".repeat(300));
        let out = unexpected_body(classify_response(500, &body));
        assert!(!out.contains("sk-ant"), "token prefix leaked: {out}");
        assert!(!out.contains("FAKETEST"), "token body leaked: {out}");
        assert!(out.contains("[REDACTED]"), "token not redacted: {out}");
        assert!(out.chars().count() <= 200);
    }

    /// Characterization pin, NOT a regression test: it also passes on the
    /// pre-fix code (which cut on a char boundary via `chars().take`), so it
    /// does not discriminate the redact-before-truncate change. It pins that a
    /// cut landing inside a multi-byte char keeps whole chars and never panics.
    #[test]
    fn classify_unexpected_truncates_on_char_boundary_without_panicking() {
        let mut body = "x".repeat(199);
        body.push('\u{e9}');
        body.push_str(&"z".repeat(100));
        assert!(!body.is_char_boundary(200));
        let out = unexpected_body(classify_response(500, &body));
        assert_eq!(out.chars().count(), 200);
        assert!(out.ends_with('\u{e9}'));
    }

    /// A Z.AI-shaped `<32hex>.<secret>` key echoed in a 500 body without a
    /// marker: neither the id half nor the secret half may survive.
    #[test]
    fn validate_key_scrubs_echoed_unprefixed_key_from_unexpected_body() {
        let p = get_provider("zai").unwrap();
        let key = "0123456789abcdef0123456789abcdef.Zq9xLmN2pRsTuVwXyZ";
        let echoed = format!("upstream error: bad request for credential {key} (retry later)");
        let result = validate_key(p, key, |_u, _h, _b| Ok((500, echoed.clone())));
        let out = unexpected_body(result);
        assert!(
            !out.contains("Zq9xLmN2pRsTuVwXyZ"),
            "secret half leaked: {out}"
        );
        assert!(!out.contains("0123456789abcdef"), "id half leaked: {out}");
        let half = "partial echo Zq9xLmN2pRsTuVwXyZ only";
        let out = unexpected_body(validate_key(p, key, |_u, _h, _b| Ok((500, half.into()))));
        assert!(
            !out.contains("Zq9xLmN2pRsTuVwXyZ"),
            "half echo leaked: {out}"
        );
    }

    /// G2: a truncated echo (7-char prefix of the secret half) is scrubbed too.
    #[test]
    fn validate_key_scrubs_truncated_prefix_echo() {
        let p = get_provider("zai").unwrap();
        let key = "0123456789abcdef0123456789abcdef.Zq9xLmN2pRsTuVwXyZ";
        let body = "rejected key beginning Zq9xLmN (truncated)";
        let out = unexpected_body(validate_key(p, key, |_u, _h, _b| Ok((500, body.into()))));
        assert!(!out.contains("Zq9xLmN"), "prefix echo leaked: {out}");
    }

    #[test]
    fn classify_200_is_valid() {
        assert_eq!(
            classify_response(200, r#"{"content": []}"#),
            ValidationResult::Valid
        );
    }

    #[test]
    fn classify_401_is_invalid() {
        assert_eq!(
            classify_response(401, r#"{"error": "invalid key"}"#),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn classify_403_is_invalid() {
        assert_eq!(classify_response(403, ""), ValidationResult::Invalid);
    }

    #[test]
    fn classify_500_is_unexpected() {
        let result = classify_response(500, "server error");
        match result {
            ValidationResult::Unexpected { status, .. } => assert_eq!(status, 500),
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }

    #[test]
    fn probe_body_format() {
        let body = build_probe_body("test-model");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.get("model").unwrap().as_str().unwrap(), "test-model");
        assert_eq!(parsed.get("max_tokens").unwrap().as_u64().unwrap(), 1);
    }

    #[test]
    fn probe_body_strips_the_cc_context_annotation_for_every_3p_default() {
        for (id, bare) in [("kimi", "k3.1-pro"), ("zai", "glm-5.3")] {
            let p = get_provider(id).unwrap();
            let body = build_probe_body(p.default_model);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["model"].as_str(), Some(bare), "{id}");
        }
    }

    #[test]
    fn claude_probe_headers_use_x_api_key() {
        let p = get_provider("claude").unwrap();
        let headers = build_probe_headers(p, "sk-test-key");

        assert!(headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "sk-test-key"));
        assert!(headers.iter().any(|(k, _)| k == "anthropic-version"));
    }

    #[test]
    fn minimax_probe_headers_use_bearer() {
        let p = get_provider("mm").unwrap();
        let headers = build_probe_headers(p, "mm-key");

        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer mm-key"));
    }

    #[test]
    fn validate_key_unreachable() {
        let p = get_provider("mm").unwrap();
        let result = validate_key(p, "key", |_url, _h, _b| Err("connection refused".into()));

        match result {
            ValidationResult::Unreachable(msg) => assert!(msg.contains("connection refused")),
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn validate_key_success() {
        let p = get_provider("mm").unwrap();
        let result = validate_key(p, "key", |_url, _h, _b| {
            Ok((200, r#"{"content": []}"#.into()))
        });

        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn validate_key_invalid() {
        let p = get_provider("mm").unwrap();
        let result = validate_key(p, "bad-key", |_url, _h, _b| {
            Ok((401, r#"{"error": "unauthorized"}"#.into()))
        });

        assert_eq!(result, ValidationResult::Invalid);
    }

    #[test]
    fn validate_key_no_endpoint_unreachable() {
        let p = get_provider("ollama").unwrap();
        let result = validate_key(p, "", |_url, _h, _b| Ok((200, "".into())));

        match result {
            ValidationResult::Unreachable(_) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }
}
