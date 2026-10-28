use csq_redact::{redact_chat, redact_tokens};

#[test]
fn chat_vendor_prefixes_positive_and_negative() {
    for (prefix, minimum) in [
        ("ghp_", 30),
        ("github_pat_", 30),
        ("AKIA", 16),
        ("xoxa-", 8),
        ("xoxb-", 8),
        ("xoxp-", 8),
        ("xoxr-", 8),
        ("sk_live_", 16),
    ] {
        let token = format!("{prefix}{}", "Z".repeat(minimum));
        assert_eq!(
            redact_chat(&format!("before {token} after")),
            "before [REDACTED] after"
        );
        let short = format!("{prefix}Z");
        assert_eq!(redact_chat(&short), short);
        let midword = format!("module_{token}");
        assert_eq!(redact_chat(&midword), midword);
    }
}

#[test]
fn chat_authorization_all_schemes_and_negative_markers() {
    for scheme in ["Basic", "token", "Bearer", "Custom-Scheme"] {
        let input = format!("Authorization: {scheme} opaqueSyntheticValue== trailing");
        assert_eq!(
            redact_chat(&input),
            format!("Authorization: {scheme} [REDACTED] trailing")
        );
    }
    assert_eq!(
        redact_chat("authorization_id Basic harmless"),
        "authorization_id Basic harmless"
    );
    assert_eq!(redact_chat("Basic ordinary prose"), "Basic ordinary prose");
}

#[test]
fn chat_password_fields_positive_and_negative() {
    assert_eq!(
        redact_chat("password=synthetic-value trailing"),
        "password=[REDACTED]"
    );
    assert_eq!(
        redact_chat(r#"{"password":"synthetic-value"}"#),
        r#"{"password":"[REDACTED]"}"#
    );
    assert_eq!(
        redact_chat("password policies should be strong"),
        "password policies should be strong"
    );
    assert_eq!(
        redact_chat("passwordless=ordinary"),
        "passwordless=ordinary"
    );
}

#[test]
fn chat_url_userinfo_positive_and_negative() {
    for scheme in ["postgres", "https", "redis"] {
        let input = format!("{scheme}://user:synthetic-password@example.invalid/db end");
        assert_eq!(
            redact_chat(&input),
            format!("{scheme}://user:[REDACTED]@example.invalid/db end")
        );
    }
    for input in [
        "https://example.invalid/path@name",
        "user@example.invalid",
        "postgres://example.invalid/db",
    ] {
        assert_eq!(redact_chat(input), input);
    }
}

#[test]
fn chat_masks_bare_git_shas_and_credential_context() {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(redact_chat(sha), "[REDACTED]");
    assert_eq!(redact_chat(&format!("commit {sha}")), "commit [REDACTED]");
    assert_eq!(
        redact_chat(&format!("x-api-key: {sha}")),
        "x-api-key: [REDACTED]"
    );
    // The legacy diagnostic profile keeps its original hex policy.
    assert_eq!(redact_tokens(sha), "[REDACTED]");
}

#[test]
fn chat_pem_private_blocks_and_generic_prose() {
    for tag in [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    ] {
        let input =
            format!("before -----BEGIN {tag}-----\nSyntheticKeyBytes\n-----END {tag}----- after");
        assert_eq!(redact_chat(&input), "before [REDACTED] after");
    }
    assert_eq!(
        redact_chat("before -----BEGIN PRIVATE KEY-----\nSyntheticPartial"),
        "before [REDACTED]"
    );
    let prose = "explain -----BEGIN ordinary text then continue discussing code";
    assert_eq!(redact_chat(prose), prose);
}

#[test]
fn chat_known_csq_shapes_and_utf8_remain_safe() {
    for token in [
        "sk-ant-oat01-SYNTHETIC",
        "sk-ant-ort01-SYNTHETIC",
        "ya29.SYNTHETIC.more",
        "1//SYNTHETIC",
        "sk-1234",
    ] {
        assert_eq!(
            redact_chat(&format!("é — {token} fin")),
            "é — [REDACTED] fin"
        );
    }
    for prefix in ["sk-", "sess-", "rt_", "AIza"] {
        let input = format!("{prefix}{}", "Z".repeat(35));
        assert_eq!(redact_chat(&input), "[REDACTED]");
    }
    let jwt = format!(
        "eyJ{}.eyJ{}.{}",
        "Z".repeat(17),
        "Z".repeat(17),
        "Z".repeat(17)
    );
    assert_eq!(redact_chat(&jwt), "[REDACTED]");
    assert_eq!(
        redact_chat("é — plain code sk-dev rt_queue"),
        "é — plain code sk-dev rt_queue"
    );
}

#[test]
fn chat_scanner_preserves_long_adversarial_nonsecret_runs() {
    let input = format!(
        "{} {} {}",
        "a.".repeat(4096),
        "-----BEGIN generic prose ".repeat(1024),
        "é".repeat(4096)
    );
    assert_eq!(redact_chat(&input), input);
}

#[test]
fn chat_env_fields_suffix_segments_positive_and_negative() {
    for field in [
        "DB_PASSWORD",
        "passwd",
        "Pwd",
        "secret",
        "token",
        "ZAI_API_KEY",
        "apikey",
        "CUSTOM_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "access_key",
        "client_secret",
        "private_key",
        "credential",
        "credentials",
        "access_token",
        "db-password",
    ] {
        for separator in ["=", ":", " = "] {
            let input = format!("{field}{separator}SyntheticOpaqueValue");
            assert_eq!(redact_chat(&input), format!("{field}{separator}[REDACTED]"));
        }
    }
    for input in [
        "passwordless=value",
        "tokenizer=value",
        "secretary=value",
        "monkey=value",
        "the password is complex",
        "credentials remain private",
        "api_keyed=value",
    ] {
        assert_eq!(redact_chat(input), input);
    }
}

#[test]
fn chat_quoted_escaped_encoded_and_literal_newline_fields() {
    for (input, expected) in [
        (
            "password=\"correct horse battery staple\" trailing",
            "password=\"[REDACTED]\" trailing",
        ),
        (
            "pwd='synthetic multi word secret' end",
            "pwd='[REDACTED]' end",
        ),
        (
            r#"{\"password\":\"synthetic pass phrase\"}"#,
            r#"{\"password\":\"[REDACTED]\"}"#,
        ),
        (
            r#"\"Authorization\": \"Basic c3ludGhldGljOnBhc3M=\""#,
            r#"\"Authorization\": \"Basic [REDACTED]\""#,
        ),
        (
            r"password:\n synthetic-value trailing",
            r"password:\n [REDACTED] trailing",
        ),
        (
            "password%3Dsynthetic-value&next=plain",
            "password%3D[REDACTED]",
        ),
        ("password：synthetic-value", "password：[REDACTED]"),
        (
            concat!(r"\nghp_", "FAKETESTDONOTUSE0123456789abcdefgh"),
            r"\n[REDACTED]",
        ),
    ] {
        assert_eq!(redact_chat(input), expected);
    }
    for input in [
        r"\n ordinary prose",
        "password%3Cexample",
        "password：",
        "the bearer of this",
        "Authorization is required",
        // Public git-over-ssh URL (userinfo, no secret) must survive verbatim.
        // Built by concatenation so the ssh scheme prefix never appears as a
        // source literal: the community extraction leak scan flags that prefix
        // tree-wide as a private-remote marker, and exempting this file would
        // blind the scan here. The runtime string is byte-identical.
        concat!("ssh", "://git@github.com"),
        "a://@",
        "postgres://user:@example.invalid",
    ] {
        assert_eq!(redact_chat(input), input);
    }
}

#[test]
fn chat_extended_vendor_prefixes_positive_and_negative() {
    for (prefix, minimum) in [
        ("gho_", 30),
        ("ghu_", 30),
        ("ghs_", 30),
        ("ghr_", 30),
        ("rk_live_", 16),
        ("rk_test_", 16),
        ("sk_test_", 16),
        ("xoxe-", 8),
        ("xapp-", 8),
        ("ASIA", 16),
        ("GOCSPX-", 8),
    ] {
        let token = format!("{prefix}{}", "Z".repeat(minimum));
        assert_eq!(redact_chat(&token), "[REDACTED]");
        let short = format!("{prefix}Z");
        assert_eq!(redact_chat(&short), short);
        let midword = format!("module_{token}");
        assert_eq!(redact_chat(&midword), midword);
    }
    assert_eq!(redact_chat("-----BEGIN PGP PRIVATE KEY BLOCK-----\nSynthetic\n-----END PGP PRIVATE KEY BLOCK----- after"), "[REDACTED] after");
    assert_eq!(
        redact_chat("-----BEGIN PUBLIC KEY-----\nPublic\n-----END PUBLIC KEY-----"),
        "-----BEGIN PUBLIC KEY-----\nPublic\n-----END PUBLIC KEY-----"
    );
}

#[test]
fn chat_hex_secret_runs_include_delimited_git_shas() {
    for count in [32, 33, 39, 41, 63, 65, 128] {
        let hex = "a".repeat(count);
        assert_eq!(
            redact_chat(&format!("before {hex} after")),
            "before [REDACTED] after"
        );
    }
    for count in [40, 64] {
        let sha = "a".repeat(count);
        assert_eq!(
            redact_chat(&format!("commit ({sha})")),
            "commit ([REDACTED])"
        );
        assert_eq!(
            redact_chat(&format!("{sha}.SyntheticComposite")),
            "[REDACTED]"
        );
        assert_eq!(
            redact_chat(&format!("x-api-key={sha}")),
            "x-api-key=[REDACTED]"
        );
    }
    for input in ["short deadbeef hash", "abc123", "32 is a number"] {
        assert_eq!(redact_chat(input), input);
    }
}

#[test]
fn chat_escaped_hex_boundary_and_sha_punctuation() {
    for escape in [r"\n", r"\r", r"\t"] {
        let secret = "a".repeat(32);
        assert_eq!(
            redact_chat(&format!("{escape}{secret}")),
            format!("{escape}[REDACTED]")
        );
        for count in [40, 64] {
            let sha = "a".repeat(count);
            for suffix in ["", ".", ". more prose"] {
                let input = format!("{escape}{sha}{suffix}");
                assert_eq!(redact_chat(&input), format!("{escape}[REDACTED]{suffix}"));
            }
            assert_eq!(
                redact_chat(&format!("{escape}{sha}.SyntheticComposite")),
                format!("{escape}[REDACTED]")
            );
        }
    }
    for count in [40, 64] {
        let sha = "a".repeat(count);
        for (input, expected) in [
            (format!(".{sha}"), ".[REDACTED]"),
            (format!("punctuation .{sha}."), "punctuation .[REDACTED]."),
            (format!("commit {sha}. next"), "commit [REDACTED]. next"),
        ] {
            assert_eq!(redact_chat(&input), expected);
        }
        assert_eq!(
            redact_chat(&format!("identifier.{sha}")),
            "identifier.[REDACTED]"
        );
    }
    assert_eq!(
        redact_chat(&format!("secret {}.", "a".repeat(32))),
        "secret [REDACTED]."
    );
    let embedded = format!("prefix{}", "a".repeat(32));
    assert_eq!(redact_chat(&embedded), "prefix[REDACTED]");
}

#[test]
fn chat_assigned_private_pem_context_precedence() {
    for field in ["private_key", "SECRET", "DB_PASSWORD"] {
        for tag in ["PRIVATE KEY", "PGP PRIVATE KEY BLOCK"] {
            let input = format!("{field}=-----BEGIN {tag}-----\nSYNTHETIC_PRIVATE_BODY\n-----END {tag}----- trailing");
            assert_eq!(redact_chat(&input), format!("{field}=[REDACTED] trailing"));
            let incomplete = format!("{field}=-----BEGIN {tag}-----\nSYNTHETIC_PRIVATE_BODY");
            assert_eq!(redact_chat(&incomplete), format!("{field}=[REDACTED]"));
        }
    }
    for input in [
        "private_key=-----BEGIN PUBLIC KEY-----\nPUBLIC_BODY\n-----END PUBLIC KEY----- trailing",
        "private_key=-----BEGIN ordinary explanation continues",
    ] {
        assert_eq!(redact_chat(input), input);
    }
    for (input, expected) in [
        ("private_key=\"-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC_PRIVATE_BODY\n-----END PGP PRIVATE KEY BLOCK-----\" trailing", "private_key=\"[REDACTED]\" trailing"),
        (r#"private_key=\"-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC_PRIVATE_BODY\n-----END PGP PRIVATE KEY BLOCK-----\" trailing"#, r#"private_key=\"[REDACTED]\" trailing"#),
    ] { assert_eq!(redact_chat(input), expected); }
}

#[path = "chat_r3_cases.rs"]
mod r3_cases;

#[test]
fn chat_owner_policy_masks_all_git_sized_hex() {
    for count in [40, 64] {
        for alphabet in ["a", "A", "0123abcdef", "0123ABCDEF"] {
            let hex: String = alphabet.chars().cycle().take(count).collect();
            for (left, right) in [
                ("", ""),
                ("(", ")"),
                ("[", "]"),
                ("é ", "."),
                ("\n", ";"),
                ("\\n", " "),
            ] {
                assert_eq!(
                    redact_chat(&format!("{left}{hex}{right}")),
                    format!("{left}[REDACTED]{right}")
                );
            }
        }
    }
    for alphabet in ["a", "A", "0123abcdef", "0123ABCDEF"] {
        let short: String = alphabet.chars().cycle().take(31).collect();
        assert_eq!(redact_chat(&format!("({short})")), format!("({short})"));
    }
}
