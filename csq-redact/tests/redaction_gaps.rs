//! Reopened credential-context regressions: synthetic fixtures, both public profiles.
use csq_redact::{redact_chat, redact_tokens};

/// Run every positive/control through both profiles before reporting a failure.
/// Failure output contains only fixed labels and booleans, never source values.
fn profiles(cases: &[(&str, &str, &str)]) {
    let mut diagnostic = true;
    let mut chat = true;
    let mut idempotent = true;
    for &(input, expected_diagnostic, expected_chat) in cases {
        let diagnostic_output = redact_tokens(input);
        let chat_output = redact_chat(input);
        diagnostic &= diagnostic_output == expected_diagnostic;
        chat &= chat_output == expected_chat;
        idempotent &= redact_tokens(&diagnostic_output) == diagnostic_output;
        idempotent &= redact_chat(&chat_output) == chat_output;
    }
    assert!(
        diagnostic && chat && idempotent,
        "redaction mismatch: diagnostic={diagnostic}, chat={chat}, idempotent={idempotent}"
    );
}

#[test]
fn issue1773_cyrillic_a_marker_preserves_original_offsets() {
    profiles(&[
        (
            "é雪🦀 аpi_key=FAKETESTopaqueValue1 tail",
            "é雪🦀 аpi_key=[REDACTED] tail",
            "é雪🦀 аpi_key=[REDACTED] tail",
        ),
        (
            "аpi_keyed=FAKETESTpublicValue1",
            "аpi_keyed=FAKETESTpublicValue1",
            "аpi_keyed=FAKETESTpublicValue1",
        ),
    ]);
}

#[test]
fn issue1773_fullwidth_bearer_marker_preserves_spelling() {
    profiles(&[
        (
            "雪 Ｂｅａｒｅｒ FAKETESTopaqueValue2 tail",
            "雪 Ｂｅａｒｅｒ [REDACTED] tail",
            "雪 Ｂｅａｒｅｒ [REDACTED] tail",
        ),
        (
            "Ｂｅａｒｅｒ none",
            "Ｂｅａｒｅｒ none",
            "Ｂｅａｒｅｒ none",
        ),
        (
            "Ｂｅａｒｅｒ_count=42",
            "Ｂｅａｒｅｒ_count=42",
            "Ｂｅａｒｅｒ_count=42",
        ),
    ]);
}

#[test]
fn issue1773_nfkc_field_markers_leave_public_values_unfolded() {
    profiles(&[
        (
            "é ａｐｉ＿ｋｅｙ: FAKETESTopaqueValue3",
            "é ａｐｉ＿ｋｅｙ: [REDACTED]",
            "é ａｐｉ＿ｋｅｙ: [REDACTED]",
        ),
        (
            "label=ＦＡＫＥＴＥＳＴpublicValue3",
            "label=ＦＡＫＥＴＥＳＴpublicValue3",
            "label=ＦＡＫＥＴＥＳＴpublicValue3",
        ),
        (
            "ａｐｉ＿ｋｅｙ_name=FAKETESTpublicValue3",
            "ａｐｉ＿ｋｅｙ_name=FAKETESTpublicValue3",
            "ａｐｉ＿ｋｅｙ_name=FAKETESTpublicValue3",
        ),
    ]);
}

#[test]
fn issue1764_token_suffix_has_exact_known_public_control() {
    profiles(&[
        (
            "GITHUB_TOKEN=FAKETESTopaqueToken1",
            "GITHUB_TOKEN=[REDACTED]",
            "GITHUB_TOKEN=[REDACTED]",
        ),
        (
            "HF_TOKEN=FAKETESTopaqueToken2",
            "HF_TOKEN=[REDACTED]",
            "HF_TOKEN=[REDACTED]",
        ),
        (
            "public_TOKEN=ready",
            "public_TOKEN=ready",
            "public_TOKEN=ready",
        ),
        (
            "REPUBLIC_TOKEN=FAKETESTopaqueToken3",
            "REPUBLIC_TOKEN=[REDACTED]",
            "REPUBLIC_TOKEN=[REDACTED]",
        ),
        ("token_count=42", "token_count=42", "token_count=42"),
    ]);
}

#[test]
fn issue1764_secret_suffix_keeps_metadata_readable() {
    profiles(&[
        (
            "SERVICE_SECRET=FAKETESTopaqueSecret1",
            "SERVICE_SECRET=[REDACTED]",
            "SERVICE_SECRET=[REDACTED]",
        ),
        (
            "SECRET_NAME=FAKETESTpublicName1",
            "SECRET_NAME=FAKETESTpublicName1",
            "SECRET_NAME=FAKETESTpublicName1",
        ),
        (
            "SECRET_TYPE=string",
            "SECRET_TYPE=string",
            "SECRET_TYPE=string",
        ),
    ]);
}

#[test]
fn issue1764_key_suffix_keeps_metadata_readable() {
    profiles(&[
        (
            "DEPLOY_KEY=FAKETESTopaqueKey1",
            "DEPLOY_KEY=[REDACTED]",
            "DEPLOY_KEY=[REDACTED]",
        ),
        (
            "KEY_NAME=FAKETESTpublicName2",
            "KEY_NAME=FAKETESTpublicName2",
            "KEY_NAME=FAKETESTpublicName2",
        ),
        ("key_count=42", "key_count=42", "key_count=42"),
    ]);
}

#[test]
fn issue1764_npm_auth_token_assignment_keeps_field_name() {
    profiles(&[
        (
            ":_authToken=FAKETESTopaqueNpm1",
            ":_authToken=[REDACTED]",
            ":_authToken=[REDACTED]",
        ),
        (
            "_authToken_name=FAKETESTpublicName3",
            "_authToken_name=FAKETESTpublicName3",
            "_authToken_name=FAKETESTpublicName3",
        ),
    ]);
}

#[test]
fn issue1764_password_flag_space_value_is_sensitive() {
    profiles(&[
        (
            "run --password FAKETESTopaquePassword1 --verbose",
            "run --password [REDACTED] --verbose",
            "run --password [REDACTED] --verbose",
        ),
        (
            "run --password-file FAKETESTpublicFilename1",
            "run --password-file FAKETESTpublicFilename1",
            "run --password-file FAKETESTpublicFilename1",
        ),
    ]);
}

#[test]
fn issue1764_client_secret_flag_space_value_is_sensitive() {
    profiles(&[
        (
            "run --client-secret FAKETESTopaqueClient1 --verbose",
            "run --client-secret [REDACTED] --verbose",
            "run --client-secret [REDACTED] --verbose",
        ),
        (
            "run --client-secret-file FAKETESTpublicFilename2",
            "run --client-secret-file FAKETESTpublicFilename2",
            "run --client-secret-file FAKETESTpublicFilename2",
        ),
    ]);
}

#[test]
fn issue1764_cookie_header_masks_all_members_and_stops_at_newline() {
    profiles(&[
        ("Cookie: first=FAKETESTcookie1; sid=FAKETESTcookie2; last=FAKETESTcookie3\nstatus=ready", "Cookie: [REDACTED]\nstatus=ready", "Cookie: [REDACTED]\nstatus=ready"),
        ("Cookie_name=FAKETESTpublicCookieName", "Cookie_name=FAKETESTpublicCookieName", "Cookie_name=FAKETESTpublicCookieName"),
    ]);
}

#[test]
fn issue1764_camel_case_credentials_preserve_metadata_fields() {
    profiles(&[
        (
            "accessToken=FAKETESTopaqueAccess1",
            "accessToken=[REDACTED]",
            "accessToken=[REDACTED]",
        ),
        (
            "refreshToken=FAKETESTopaqueRefresh1",
            "refreshToken=[REDACTED]",
            "refreshToken=[REDACTED]",
        ),
        (
            "clientSecret=FAKETESTopaqueClient2",
            "clientSecret=[REDACTED]",
            "clientSecret=[REDACTED]",
        ),
        (
            "accessTokenType=FAKETESTpublicType",
            "accessTokenType=FAKETESTpublicType",
            "accessTokenType=FAKETESTpublicType",
        ),
        (
            "refreshTokenCount=42",
            "refreshTokenCount=42",
            "refreshTokenCount=42",
        ),
        (
            "clientSecretName=FAKETESTpublicName4",
            "clientSecretName=FAKETESTpublicName4",
            "clientSecretName=FAKETESTpublicName4",
        ),
    ]);
}

#[test]
fn issue1764_secret_permission_prose_survives_explicit_assignment_still_masks() {
    profiles(&[
        (
            "secret: permission denied",
            "secret: permission denied",
            "secret: permission denied",
        ),
        (
            "secret: FAKETESTopaqueSecret2",
            "secret: FAKETESTopaqueSecret2",
            "secret: [REDACTED]",
        ),
        (
            "secret_name: FAKETESTpublicName5",
            "secret_name: FAKETESTpublicName5",
            "secret_name: FAKETESTpublicName5",
        ),
    ]);
}

#[test]
fn issue1764_split_authorization_needs_explicit_delimiter() {
    profiles(&[
        (
            "Authoriz ation: FAKETESTopaqueAuth1 tail",
            "Authoriz ation: [REDACTED] tail",
            "Authoriz ation: [REDACTED] tail",
        ),
        (
            "Authoriz\tation=FAKETESTopaqueAuth2 tail",
            "Authoriz\tation=[REDACTED] tail",
            "Authoriz\tation=[REDACTED] tail",
        ),
        (
            "Authoriz ation FAKETESTpublicDiscussion",
            "Authoriz ation FAKETESTpublicDiscussion",
            "Authoriz ation FAKETESTpublicDiscussion",
        ),
        (
            "Authoriz ation_id=FAKETESTpublicIdentifier",
            "Authoriz ation_id=FAKETESTpublicIdentifier",
            "Authoriz ation_id=FAKETESTpublicIdentifier",
        ),
    ]);
}

#[test]
fn issue1776_empty_quoted_assignment_masks_only_quoted_continuation() {
    profiles(&[
        (
            "password='' 'FAKETESTquotedPassword1' tail",
            "password='' '[REDACTED]' tail",
            "password='' '[REDACTED]' tail",
        ),
        (
            "password=\"\" \"FAKETESTquotedPassword2\" tail",
            "password=\"\" \"[REDACTED]\" tail",
            "password=\"\" \"[REDACTED]\" tail",
        ),
        ("password='' tail", "password='' tail", "password='' tail"),
        (
            "password=\"\" tail",
            "password=\"\" tail",
            "password=\"\" tail",
        ),
        (
            "password=''\n'FAKETESTpublicNextLine'",
            "password=''\n'FAKETESTpublicNextLine'",
            "password=''\n'FAKETESTpublicNextLine'",
        ),
    ]);
}

#[test]
fn context_scan_reaches_late_marker_without_folding_public_body() {
    // A long near-marker corpus is a deterministic scan/UTF-8 control, not a timing claim.
    let public = "雪 аpi_keyed=ＦＡＫＥＴＥＳＴpublicMarker\n".repeat(512);
    let input = format!("{public}é Ｂｅａｒｅｒ FAKETESTopaqueLate1 tail");
    let expected = format!("{public}é Ｂｅａｒｅｒ [REDACTED] tail");
    profiles(&[(&input, &expected, &expected), (&public, &public, &public)]);
}

#[test]
fn diagnostic_legacy_marker_floor_and_chat_profile_remain_distinct() {
    profiles(&[
        ("Bearer FAKETEST", "Bearer FAKETEST", "Bearer [REDACTED]"),
        ("Bearer FAKETESTX", "Bearer [REDACTED]", "Bearer [REDACTED]"),
        ("Bearer none", "Bearer none", "Bearer none"),
        (
            "api_keyed=FAKETESTpublicBoundary",
            "api_keyed=FAKETESTpublicBoundary",
            "api_keyed=FAKETESTpublicBoundary",
        ),
        (
            "authorization_id=FAKETESTpublicMetadata",
            "authorization_id=FAKETESTpublicMetadata",
            "authorization_id=FAKETESTpublicMetadata",
        ),
    ]);
}
