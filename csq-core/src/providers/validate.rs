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
pub fn build_probe_body(model: &str) -> String {
    serde_json::json!({
        "model": model,
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
    match status {
        200..=299 => ValidationResult::Valid,
        401 | 403 => ValidationResult::Invalid,
        _ => ValidationResult::Unexpected {
            status,
            body: body.chars().take(200).collect(),
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
        Ok((status, body)) => classify_response(status, &body),
        Err(e) => ValidationResult::Unreachable(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::catalog::get_provider;
    use super::*;

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
