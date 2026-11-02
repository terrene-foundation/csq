//! FAKETEST controls for the owner's post-R2 public-name narrowing.
use csq_redact::{redact_chat, redact_tokens};

#[test]
fn key_metadata_values_follow_each_credential_profiles_floor() {
    let mut profiles = true;
    // FAKETEST numeric controls follow the existing Diagnostic floor. Chat
    // conservatively masks values under a credential-bearing key name.
    for (input, diagnostic, chat) in [
        (
            "primary_key: 42",
            "primary_key: 42",
            "primary_key: [REDACTED]",
        ),
        ("sort_key=42", "sort_key=42", "sort_key=[REDACTED]"),
        (
            "sort_key: created_at",
            "sort_key: [REDACTED]",
            "sort_key: [REDACTED]",
        ),
        (
            "primary_key=12345678",
            "primary_key=[REDACTED]",
            "primary_key=[REDACTED]",
        ),
    ] {
        profiles &= redact_tokens(input) == diagnostic;
        profiles &= redact_chat(input) == chat;
    }
    assert!(profiles, "key_metadata_profile_floor_changed");
}

#[test]
fn public_key_names_do_not_exempt_opaque_or_long_mixed_values() {
    let mut masked = true;
    let mut stable = true;
    for secret in [
        format!("FAKETEST{}", "aB3dE4fG".repeat(4)),
        format!("FAKETEST{}", "aB3!dE4@".repeat(4)),
    ] {
        assert_eq!(secret.len(), 40, "synthetic_fixture_width");
        for name in ["primary_key", "sort_key"] {
            for separator in [": ", "="] {
                for quoted in [false, true] {
                    let value = if quoted {
                        format!("\"{secret}\"")
                    } else {
                        secret.clone()
                    };
                    let input = format!("{name}{separator}{value}");
                    for redact in [redact_tokens, redact_chat] {
                        let once = redact(&input);
                        masked &= !once.contains(&secret);
                        stable &= redact(&once) == once;
                    }
                }
            }
        }
    }
    assert!(masked && stable, "public_name_secret_or_idempotence_leak");
}
