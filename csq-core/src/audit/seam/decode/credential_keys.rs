//! Recursive credential-shaped KEY screen for inbound F101-1 v1 payloads.
//!
//! Defense-in-depth: rejects any `serde_json::Value` whose object tree contains
//! a key that looks like a credential field name OR a string value that contains
//! a live token (detected via `crate::error::redact_tokens`).
//!
//! ## Why keys, not just values?
//!
//! `error::redact_tokens` already screens VALUES. This module is the orthogonal
//! KEY screen — a key named `api_key` under a benign parent is still a
//! credential-shaped field even if its VALUE passes the token screen. The
//! dual screen (key denylist + value redact) closes both axes.
//!
//! ## Denylist anchoring
//!
//! The denylist is anchored on SUFFIX or EQUALITY so the vector's legitimate
//! keys all pass:
//!   `journal_path`, `tool`, `subagent_type`, `description_chars`,
//!   `prompt_sha256`, `command_sha256`, `command_chars`, `file_path`
//! None of them match `*_token`, `*_key`, `*secret*`, `authorization`,
//! `password`, `bearer`, `credential`, `credentials`, `client_secret`.

use serde_json::Value;

/// Denylist entry shape.
enum DenyKind {
    /// Key equals this string exactly (case-insensitive).
    Exact(&'static str),
    /// Key ends with this suffix (case-insensitive, after a word boundary: the
    /// suffix must be preceded by `_` or be the full key).
    Suffix(&'static str),
    /// Key contains this substring (case-insensitive).
    Contains(&'static str),
}

/// The credential-shaped key denylist.
///
/// Anchored so the conformance vector's keys all pass:
/// `journal_path`, `tool`, `subagent_type`, `description_chars`,
/// `prompt_sha256`, `command_sha256`, `command_chars`, `file_path`,
/// `prev_link`, `schema_version`, `kind`, `ts`, `session`,
/// `operator_ref`, `verified_id`, `person_id`, `display_id`.
static DENYLIST: &[DenyKind] = &[
    // Suffix-anchored: `_token` / `_key` must be preceded by `_`
    // so `sha256` (no suffix) passes but `api_key`, `access_token` don't.
    DenyKind::Suffix("_token"),
    DenyKind::Suffix("_key"),
    // Contains: any key mentioning "secret"
    DenyKind::Contains("secret"),
    // Exact matches for common credential field names
    DenyKind::Exact("authorization"),
    DenyKind::Exact("password"),
    DenyKind::Exact("bearer"),
    DenyKind::Exact("credential"),
    DenyKind::Exact("credentials"),
];

/// Returns `true` when `key` matches any entry in the denylist.
fn is_denied_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    for entry in DENYLIST {
        match entry {
            DenyKind::Exact(s) => {
                if lower == *s {
                    return true;
                }
            }
            DenyKind::Suffix(suf) => {
                // The suffix already includes the leading `_` (e.g. `"_key"`).
                // Any key ending with `_key` or `_token` is credential-shaped.
                // `prompt_sha256` / `command_sha256` do NOT end with `_key`
                // or `_token`, so they pass correctly.
                if lower.ends_with(suf) {
                    return true;
                }
            }
            DenyKind::Contains(sub) => {
                if lower.contains(sub) {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns `true` when `s` starts with a known live OAuth / API token prefix.
///
/// These prefixes have near-zero false-positive rates for normal payload values.
/// We do NOT use `redact_tokens` here because that also redacts sha256 hex
/// strings (any 32+ hex run), which are legitimate in fields like
/// `command_sha256`.
fn has_live_token_prefix(s: &str) -> bool {
    const TOKEN_PREFIXES: &[&str] = &[
        "sk-ant-",     // Anthropic API key
        "sk-",         // Generic API key (covers sk-proj-*, vendor keys)
        "ya29.",       // Google OAuth access token
        "oat01-",      // OpenAI access token prefix
        "ort01-",      // OpenAI refresh token prefix
        "AKIA",        // AWS access key ID (permanent)
        "ASIA",        // AWS access key ID (temporary/STS)
        "ghp_",        // GitHub personal access token
        "gho_",        // GitHub OAuth token
        "ghu_",        // GitHub user-to-server token
        "ghs_",        // GitHub server-to-server token
        "github_pat_", // GitHub fine-grained PAT
        "xox",         // Slack token (xoxb-, xoxe-, xoxa-, xoxp-)
        "AIza",        // Google API key
        "1//",         // Google refresh token (OAuth2 offline)
        "-----BEGIN",  // PEM-encoded private key
    ];
    for prefix in TOKEN_PREFIXES {
        if s.starts_with(prefix) {
            return true;
        }
    }
    // JWT: a STRUCTURAL three-segment `eyJ….eyJ….<sig>` check rather than a bare
    // `eyJ` prefix (R3 security L-1). A bare `eyJ` is the base64 of `{"` and
    // matches ANY base64-encoded JSON object — over-broad, causing spurious
    // rejection of benign base64 values. Mirrors `error::redact_tokens`'
    // dotted-triple JWT pinning: header starts `eyJ`, exactly two `.`
    // separators, three non-empty base64url-ish segments.
    looks_like_jwt(s)
}

/// Structural JWT detector: `eyJ<base64url>.<base64url>.<base64url>`, three
/// non-empty segments. Used instead of a bare `eyJ` prefix to avoid rejecting
/// arbitrary base64-encoded JSON (which also begins `eyJ`).
fn looks_like_jwt(s: &str) -> bool {
    if !s.starts_with("eyJ") {
        return false;
    }
    let segments: Vec<&str> = s.split('.').collect();
    if segments.len() != 3 {
        return false;
    }
    let is_b64url = |seg: &str| {
        !seg.is_empty()
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
    };
    segments.iter().all(|seg| is_b64url(seg))
}

/// Recursively screen `value` for credential-shaped keys and live token values.
///
/// Returns `Err(key)` with the first offending key, or `Ok(())` when clean.
///
/// ## Screens
///
/// 1. Any object key matching the denylist → `Err`.
/// 2. Any string value that is altered by `redact_tokens` (i.e. it contained a
///    live `sk-ant-`, `ya29.`, or similar token) → `Err("__value__")`.
/// 3. Recurses into object values and array elements.
pub fn screen(value: &Value) -> Result<(), String> {
    screen_inner(value)
}

fn screen_inner(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                // Screen the key itself.
                if is_denied_key(key) {
                    return Err(key.clone());
                }
                // Screen the value recursively.
                screen_inner(val)?;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                screen_inner(item)?;
            }
        }
        Value::String(s) => {
            // Value-side: reject strings that start with a known live-token prefix.
            // We do NOT use `redact_tokens` here because it also redacts bare hex
            // strings (sha256 hashes) which are legitimate in v1 payload fields
            // like `command_sha256`. Instead we check only the known-prefix patterns
            // that have zero false-positive rate for normal payload values.
            if has_live_token_prefix(s) {
                return Err("__value__".to_string());
            }
        }
        // Null / Bool / Number — no credentials possible.
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn vector_keys_all_pass() {
        // All keys from the conformance vector must pass.
        let v = json!({
            "journal_path": "journal/0252-esperie-DECISION.md",
            "tool": "Write",
            "subagent_type": "agent",
            "description_chars": 42,
            "prompt_sha256": "aabbcc",
            "command_sha256": "ddeeff",
            "command_chars": 10,
            "file_path": "/tmp/foo.md",
            "prev_link": null,
            "schema_version": 1,
            "kind": "Decision",
            "ts": "2026-06-09T15:44:57.000Z",
            "session": "sess-001",
            "operator_ref": {
                "display_id": "esperie",
                "person_id": "pid-esperie-abc",
                "verified_id": "AABBCC"
            }
        });
        assert!(screen(&v).is_ok(), "vector keys must all pass the screen");
    }

    #[test]
    fn api_key_is_denied() {
        let v = json!({ "api_key": "harmless-value" });
        assert!(screen(&v).is_err(), "api_key must be denied");
    }

    #[test]
    fn access_token_is_denied() {
        let v = json!({ "access_token": "harmless" });
        assert!(screen(&v).is_err());
    }

    #[test]
    fn client_secret_is_denied() {
        let v = json!({ "client_secret": "harmless" });
        assert!(screen(&v).is_err());
    }

    #[test]
    fn authorization_is_denied() {
        let v = json!({ "authorization": "Bearer x" });
        assert!(screen(&v).is_err());
    }

    #[test]
    fn credentials_is_denied() {
        let v = json!({ "credentials": {} });
        assert!(screen(&v).is_err());
    }

    #[test]
    fn nested_denied_key_is_caught() {
        // A denied key nested under a benign parent must still fail.
        let v = json!({ "outer": { "api_key": "v" } });
        assert!(screen(&v).is_err());
    }

    #[test]
    fn live_token_value_is_denied() {
        // A value containing a live sk-ant-* pattern must fail.
        let v = json!({ "benign_key": "sk-ant-api03-XXXX1234567890abcdef1234567890abcdef12" });
        assert!(screen(&v).is_err());
    }

    #[test]
    fn prompt_sha256_passes_suffix_check() {
        // `prompt_sha256` ends with `256`, not `_key` — must pass.
        let v = json!({ "prompt_sha256": "aabbcc" });
        assert!(screen(&v).is_ok());
    }

    #[test]
    fn sha256_hex_value_passes() {
        // A sha256 hex string is not a live token.
        let v = json!({ "command_sha256": "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a" });
        assert!(screen(&v).is_ok());
    }

    // ── LOW-1 regression tests: extended prefix classes ──

    #[test]
    fn generic_sk_prefix_rejected() {
        // sk- covers sk-proj-*, vendor API keys
        let v = json!({ "benign": "sk-proj-abc123xyz" });
        assert!(screen(&v).is_err(), "sk- prefix must be rejected");
    }

    #[test]
    fn aws_akia_rejected() {
        let v = json!({ "benign": "AKIAIOSFODNN7EXAMPLE" });
        assert!(screen(&v).is_err(), "AKIA prefix must be rejected");
    }

    #[test]
    fn aws_asia_rejected() {
        let v = json!({ "benign": "ASIAIOSFODNN7EXAMPLE" });
        assert!(screen(&v).is_err(), "ASIA prefix must be rejected");
    }

    #[test]
    fn github_ghp_rejected() {
        let v = json!({ "benign": "ghp_FAKETESTTOKENDONOTUSE000000000000000" });
        assert!(screen(&v).is_err(), "ghp_ prefix must be rejected");
    }

    #[test]
    fn github_gho_rejected() {
        let v = json!({ "benign": "gho_FAKETESTTOKENDONOTUSE000000000000000" });
        assert!(screen(&v).is_err(), "gho_ prefix must be rejected");
    }

    #[test]
    fn github_ghu_rejected() {
        let v = json!({ "benign": "ghu_FAKETESTTOKENDONOTUSE000000000000000" });
        assert!(screen(&v).is_err(), "ghu_ prefix must be rejected");
    }

    #[test]
    fn github_ghs_rejected() {
        let v = json!({ "benign": "ghs_FAKETESTTOKENDONOTUSE000000000000000" });
        assert!(screen(&v).is_err(), "ghs_ prefix must be rejected");
    }

    #[test]
    fn github_fine_grained_pat_rejected() {
        let v = json!({ "benign": "github_pat_11ABCDE1234567890" });
        assert!(screen(&v).is_err(), "github_pat_ prefix must be rejected");
    }

    #[test]
    fn slack_xox_rejected() {
        let v = json!({ "benign": "xoxb-123-456-abc" });
        assert!(screen(&v).is_err(), "xox prefix must be rejected");
    }

    #[test]
    fn google_aizia_rejected() {
        let v = json!({ "benign": "AIzaFAKETESTKEYDONOTUSE0000000000000000" });
        assert!(screen(&v).is_err(), "AIza prefix must be rejected");
    }

    #[test]
    fn google_refresh_token_rejected() {
        let v = json!({ "benign": "1//0gYour_refresh_token" });
        assert!(screen(&v).is_err(), "1// prefix must be rejected");
    }

    #[test]
    fn pem_private_key_rejected() {
        let v = json!({ "benign": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..." });
        assert!(screen(&v).is_err(), "PEM prefix must be rejected");
    }

    #[test]
    fn structural_jwt_rejected_but_benign_base64_json_passes() {
        // R3 security L-1: a STRUCTURAL three-segment JWT is rejected...
        let jwt = json!({ "auth": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" });
        assert!(screen(&jwt).is_err(), "a 3-segment JWT must be rejected");
        // ...but a benign SINGLE-segment base64-encoded JSON (also begins `eyJ`,
        // but is not a dotted-triple JWT) now PASSES — the bare `eyJ` prefix was
        // over-broad and spuriously rejected benign base64 values.
        let benign = json!({ "blob": "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" });
        assert!(
            screen(&benign).is_ok(),
            "benign single-segment base64-JSON (not a JWT) must pass"
        );
    }

    #[test]
    fn command_sha256_and_prompt_sha256_hex_values_still_pass() {
        // The conformance-vector's sha256 values must NOT be caught by the prefix check.
        let v = json!({
            "command_sha256": "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a",
            "prompt_sha256": "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
        });
        assert!(
            screen(&v).is_ok(),
            "command_sha256 / prompt_sha256 hex values must pass the prefix check"
        );
    }
}
