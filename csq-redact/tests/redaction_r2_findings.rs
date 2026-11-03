//! Synthetic FAKETEST controls for the final review's residual findings.
use csq_redact::{redact_chat, redact_tokens};

#[test]
fn explicit_numeric_credentials_keep_each_profiles_floor() {
    let mut diagnostic = true;
    let mut chat = true;
    // A FAKETEST prefix would invalidate these synthetic numeric credentials.
    for length in [1, 3, 4, 8, 9] {
        let numeric = "1".repeat(length);
        for (prefix, suffix) in [
            ("run --password ", " --verbose"),
            ("run --client-secret ", " --verbose"),
            ("SERVICE_TOKEN=", ""),
            ("SERVICE_SECRET=", ""),
            ("SERVICE_KEY=", ""),
        ] {
            let input = format!("{prefix}{numeric}{suffix}");
            let masked = format!("{prefix}[REDACTED]{suffix}");
            let expected_diagnostic = if length >= 4 {
                masked.as_str()
            } else {
                input.as_str()
            };
            diagnostic &= redact_tokens(&input) == expected_diagnostic;
            chat &= redact_chat(&input) == masked;
        }
    }
    for public in [
        "KEY_SIZE=12345678",
        "port=8080",
        "year=2026",
        "pid=1234",
        "count=1234",
    ] {
        diagnostic &= redact_tokens(public) == public;
        chat &= redact_chat(public) == public;
    }
    assert!(
        diagnostic && chat,
        "numeric_context_boundary: diagnostic={diagnostic}, chat={chat}"
    );
}

#[test]
fn raw_authorization_never_preserves_the_credential_for_a_punctuation_tail() {
    for redact in [redact_tokens, redact_chat] {
        let output = redact("Authoriz ation: FAKETESTOpaqueCredential9 failed:permission");
        assert!(
            !output.contains("FAKETESTOpaqueCredential9"),
            "authorization_punctuation_credential"
        );
        assert_eq!(redact("authorization_id=public"), "authorization_id=public");
    }
}

#[test]
fn raw_authorization_never_preserves_the_credential_for_an_alphabetic_tail() {
    for redact in [redact_tokens, redact_chat] {
        let output = redact("Authoriz ation: FAKETESTOpaqueCredential9 unavailable");
        assert!(
            !output.contains("FAKETESTOpaqueCredential9"),
            "authorization_alphabetic_credential"
        );
        assert_eq!(
            redact("Authoriz ation requested"),
            "Authoriz ation requested"
        );
    }
}

#[test]
fn authorization_placeholders_remain_idempotent() {
    let mut stable = true;
    for scheme in ["Basic", "token", "Bearer", "Custom-Scheme"] {
        let input = format!("Authorization: {scheme} FAKETESTOpaqueCredential9");
        let once = redact_chat(&input);
        stable &= !once.contains("FAKETESTOpaqueCredential9");
        stable &= redact_chat(&once) == once;
    }
    assert!(stable, "authorization_placeholder_changed_on_resume");
}
