//! Synthetic FAKETEST regressions for paired R1 findings. No credential I/O.
use csq_redact::{redact_chat, redact_tokens};

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
fn strong_password_flags_mask_synthetic_numeric_credentials() {
    // FAKETEST numeric credential: a prefix would destroy the all-numeric falsifier.
    let numeric = "1".repeat(9);
    let password = format!("run --password {numeric} --verbose");
    let client_secret = format!("run --client-secret {numeric} --verbose");
    profiles(&[
        (
            &password,
            "run --password [REDACTED] --verbose",
            "run --password [REDACTED] --verbose",
        ),
        (
            &client_secret,
            "run --client-secret [REDACTED] --verbose",
            "run --client-secret [REDACTED] --verbose",
        ),
        (
            "run --password-file FAKETESTpublicFile",
            "run --password-file FAKETESTpublicFile",
            "run --password-file FAKETESTpublicFile",
        ),
        (
            "run --client-secret-file FAKETESTpublicFile",
            "run --client-secret-file FAKETESTpublicFile",
            "run --client-secret-file FAKETESTpublicFile",
        ),
    ]);
}

#[test]
fn strong_credential_suffixes_mask_synthetic_numeric_values_not_counts() {
    // FAKETEST numeric credential, generated without a shape-recognisable prefix.
    let numeric = "1".repeat(9);
    let token = format!("SERVICE_TOKEN={numeric}");
    let secret = format!("SERVICE_SECRET={numeric}");
    let key = format!("SERVICE_KEY={numeric}");
    profiles(&[
        (
            &token,
            "SERVICE_TOKEN=[REDACTED]",
            "SERVICE_TOKEN=[REDACTED]",
        ),
        (
            &secret,
            "SERVICE_SECRET=[REDACTED]",
            "SERVICE_SECRET=[REDACTED]",
        ),
        (&key, "SERVICE_KEY=[REDACTED]", "SERVICE_KEY=[REDACTED]"),
        (
            "token_count=111111111",
            "token_count=111111111",
            "token_count=111111111",
        ),
        (
            "SECRET_COUNT=111111111",
            "SECRET_COUNT=111111111",
            "SECRET_COUNT=111111111",
        ),
        (
            "KEY_SIZE=111111111",
            "KEY_SIZE=111111111",
            "KEY_SIZE=111111111",
        ),
        (
            "public_TOKEN=ready",
            "public_TOKEN=ready",
            "public_TOKEN=ready",
        ),
        (
            "GOOGLE_APPLICATION_CREDENTIALS=/path",
            "GOOGLE_APPLICATION_CREDENTIALS=/path",
            "GOOGLE_APPLICATION_CREDENTIALS=/path",
        ),
    ]);
}

#[test]
fn suffix_password_flag_keeps_existing_chat_custody() {
    profiles(&[
        (
            "run --db-password FAKETESTopaquePass1 --verbose",
            "run --db-password [REDACTED] --verbose",
            "run --db-password [REDACTED] --verbose",
        ),
        (
            "run --db-password-file FAKETESTpublicFile",
            "run --db-password-file FAKETESTpublicFile",
            "run --db-password-file FAKETESTpublicFile",
        ),
        ("password: string", "password: string", "password: string"),
    ]);
}
