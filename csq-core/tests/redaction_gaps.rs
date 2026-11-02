//! Current production boundaries for an internal ticket, an internal ticket and an internal ticket.
//! The generic and chat profiles are exercised directly; this is not the
//! historical Q7 matrix. All credentials below are synthetic FAKETEST values.
use csq_core::audit::types::RedactedString;
use csq_core::chat_sessions::{ChatMessage, SessionStore};
use csq_core::error::{redact_excerpt, redact_excerpt_with_secrets, redact_tokens, OAuthError};

const ID: &str = "00000000-0000-4000-8000-000000000001";

fn outputs(input: &str) -> Vec<(&'static str, String)> {
    let untrusted = RedactedString::from_untrusted(input);
    // A forged persisted value must cross Deserialize, not a trusted constructor.
    let forged: RedactedString =
        serde_json::from_value(serde_json::Value::String(input.to_owned()))
            .expect("fixture_deserialize");
    let mut outputs = vec![
        ("tokens", redact_tokens(input)),
        ("excerpt", redact_excerpt(input.as_bytes(), 2048)),
        (
            "excerpt_empty_secrets",
            // Supplying the fixture secret would hide a marker-matching bug.
            redact_excerpt_with_secrets(input.as_bytes(), &[], 2048),
        ),
        ("untrusted_display", untrusted.to_string()),
        (
            "untrusted_serialize",
            serde_json::to_string(&untrusted).expect("fixture_serialize"),
        ),
        ("forged_display", forged.to_string()),
        (
            "forged_serialize",
            serde_json::to_string(&forged).expect("fixture_serialize"),
        ),
        (
            "oauth_http",
            OAuthError::Http {
                status: 400,
                body: input.to_owned(),
            }
            .to_string(),
        ),
        (
            "capability_log",
            csq_core::capability_layer::logging::redact_log_line(input),
        ),
        (
            "operator_display",
            csq_core::cli_deps::sanitize::redact_display(input),
        ),
    ];

    // Real writer publication and resume, entirely below a caller-owned root.
    // There is no raw-content serializer substituted for the production store.
    let root = tempfile::tempdir().expect("fixture_root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("fixture_permissions");
    }
    let store = SessionStore::open(root.path(), 8192).expect("fixture_store");
    let mut writer = store.create(ID).expect("fixture_writer");
    writer
        .append(ChatMessage {
            role: input.to_owned(),
            content: input.to_owned(),
        })
        .expect("fixture_append");
    let published = std::fs::read(
        root.path()
            .join("chat-sessions")
            .join(format!("{ID}.jsonl")),
    )
    .expect("fixture_published");
    outputs.push((
        "chat_published",
        String::from_utf8(published).expect("fixture_utf8"),
    ));
    drop(writer);
    drop(store);
    let reopened = SessionStore::open(root.path(), 8192).expect("fixture_reopen");
    let resumed = reopened.resume(ID).expect("fixture_resume");
    assert!(resumed.entries().len() == 1, "fixture_entry_count");
    outputs.push(("chat_resumed_role", resumed.entries()[0].role.clone()));
    outputs.push(("chat_resumed_content", resumed.entries()[0].content.clone()));
    outputs
}

fn report(shape: &'static str, sink: &'static str, control: &'static str, ok: bool) -> bool {
    // Fixed vocabulary only: never print fixture input, output or error bodies.
    let verdict = if ok { "PASS" } else { "FAIL" };
    println!("redaction_gap {shape} {sink} {control} {verdict}");
    ok
}

fn shape(name: &'static str, input: &str, secrets: &[&str], benign: &str, preserved: &[&str]) {
    let secret_outputs = outputs(input);
    let benign_outputs = outputs(benign);
    let mut all_ok = true;
    // Evaluate every boundary and both controls even when the base is RED.
    for (sink, output) in secret_outputs {
        let masked = !output.is_empty() && secrets.iter().all(|secret| !output.contains(secret));
        all_ok &= report(name, sink, "secret", masked);
    }
    for (sink, output) in benign_outputs {
        let visible = preserved.iter().all(|text| output.contains(text));
        all_ok &= report(name, sink, "benign", visible);
    }
    assert!(all_ok, "redaction_boundary_regression");
}

#[test]
fn cyrillic_api_key_marker_is_redacted_at_current_boundaries() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "cyrillic_api_key",
        "аpi_key=FAKETEST_ApiValue",
        &["FAKETEST_ApiValue"],
        "api_version=public-v1",
        &["api_version=public-v1"],
    );
}

#[test]
fn fullwidth_bearer_marker_is_redacted_at_current_boundaries() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "fullwidth_bearer",
        "Ｂｅａｒｅｒ FAKETEST_BearerValue",
        &["FAKETEST_BearerValue"],
        "bearer_count=2",
        &["bearer_count=2"],
    );
}

#[test]
fn provider_token_suffixes_are_redacted_but_public_token_is_visible() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "provider_suffix",
        "GITHUB_TOKEN=FAKETEST_GithubValue\nHF_TOKEN=FAKETEST_HfValue",
        &["FAKETEST_GithubValue", "FAKETEST_HfValue"],
        "public_TOKEN=ready",
        &["public_TOKEN=ready"],
    );
}

#[test]
fn key_and_secret_suffixes_are_redacted_without_masking_counts() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "key_secret_suffix",
        "DEPLOY_KEY=FAKETEST_DeployValue\nSERVICE_SECRET=FAKETEST_ServiceValue",
        &["FAKETEST_DeployValue", "FAKETEST_ServiceValue"],
        "key_count=2 secret_count=3",
        &["key_count=2", "secret_count=3"],
    );
}

#[test]
fn password_space_flag_is_redacted_without_masking_password_file() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "password_flag",
        "--password FAKETEST_PasswordValue",
        &["FAKETEST_PasswordValue"],
        "--password-file FAKETESTpublicFilename",
        &["--password-file FAKETESTpublicFilename"],
    );
}

#[test]
fn client_secret_space_flag_is_redacted_without_masking_client_name() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "client_secret_flag",
        "--client-secret FAKETEST_ClientFlagValue",
        &["FAKETEST_ClientFlagValue"],
        "--client-name public",
        &["--client-name public"],
    );
}

#[test]
fn cookie_tail_value_is_redacted_without_masking_cookie_count() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "cookie_tail",
        "Cookie: a=1; sid=FAKETEST_CookieValue; theme=light",
        &["FAKETEST_CookieValue"],
        "cookie_count=2",
        &["cookie_count=2"],
    );
}

#[test]
fn camelcase_access_token_is_redacted_without_masking_count() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "camel_access",
        "accessToken=FAKETEST_AccessValue",
        &["FAKETEST_AccessValue"],
        "accessTokenCount=2",
        &["accessTokenCount=2"],
    );
}

#[test]
fn camelcase_refresh_token_is_redacted_without_masking_count() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "camel_refresh",
        "refreshToken=FAKETEST_RefreshValue",
        &["FAKETEST_RefreshValue"],
        "refreshTokenCount=2",
        &["refreshTokenCount=2"],
    );
}

#[test]
fn camelcase_client_secret_is_redacted_without_masking_name() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "camel_client",
        "clientSecret=FAKETEST_ClientValue",
        &["FAKETEST_ClientValue"],
        "clientSecretName=FAKETESTpublicName",
        &["clientSecretName=FAKETESTpublicName"],
    );
}

#[test]
fn npm_auth_token_is_redacted_without_masking_auth_token_name() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "npm_auth_token",
        ":_authToken=FAKETEST_NpmValue",
        &["FAKETEST_NpmValue"],
        ":_authToken_name=FAKETESTpublicName",
        &[":_authToken_name=FAKETESTpublicName"],
    );
}

#[test]
fn quoted_word_after_empty_password_is_redacted_but_unquoted_tail_stays_visible() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "empty_quoted_assignment",
        "password='' 'FAKETEST_QuotedValue'",
        &["FAKETEST_QuotedValue"],
        "password='' tail",
        &["tail"],
    );
}

#[test]
fn split_authorization_with_delimiter_is_redacted_without_masking_prose() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "split_authorization",
        "Authoriz ation: FAKETEST_SplitSpace\nAuthoriz\tation: FAKETEST_SplitTab",
        &["FAKETEST_SplitSpace", "FAKETEST_SplitTab"],
        "Authoriz ation requested; secret: permission denied",
        &["Authoriz ation requested", "secret: permission denied"],
    );
}

#[test]
fn numeric_credential_space_flags_are_redacted_without_masking_password_file() {
    let _env = csq_core::platform::test_env::lock();
    // FAKETEST numeric fixture: generated digits are intentionally shapeless.
    let numeric = "1".repeat(9);
    let input = format!("--password {numeric}\n--client-secret {numeric}");
    shape(
        "numeric_credential_flags",
        &input,
        &[numeric.as_str()],
        "--password-file FAKETESTfilename",
        &["--password-file FAKETESTfilename"],
    );
}

#[test]
fn numeric_token_key_secret_assignments_are_redacted_without_masking_public_metadata() {
    let _env = csq_core::platform::test_env::lock();
    // FAKETEST numeric fixture: strong credential labels must bind numeric values.
    let numeric = "1".repeat(9);
    let input = format!("GITHUB_TOKEN={numeric}\nDEPLOY_KEY={numeric}\nSERVICE_SECRET={numeric}");
    let count = format!("retry_count={numeric}");
    let benign = format!("public_TOKEN=ready {count}");
    shape(
        "numeric_credential_assignments",
        &input,
        &[numeric.as_str()],
        &benign,
        &["public_TOKEN=ready", count.as_str()],
    );
}

#[test]
fn db_password_suffix_flag_is_redacted_without_masking_password_file() {
    let _env = csq_core::platform::test_env::lock();
    shape(
        "db_password_flag",
        "--db-password FAKETEST_DbPasswordValue",
        &["FAKETEST_DbPasswordValue"],
        "--password-file FAKETESTfilename",
        &["--password-file FAKETESTfilename"],
    );
}

#[test]
fn short_numeric_credentials_are_redacted_at_current_boundaries() {
    let _env = csq_core::platform::test_env::lock();
    // FAKETEST eight-digit credentials must not depend on a shape prefix.
    let numeric = "1".repeat(8);
    let input = format!("--password {numeric}\nSERVICE_TOKEN={numeric}\nSERVICE_KEY={numeric}");
    shape(
        "short_numeric_credentials",
        &input,
        &[numeric.as_str()],
        "sort_order=42",
        &["sort_order=42"],
    );
}
