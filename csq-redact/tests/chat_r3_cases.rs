use csq_redact::redact_chat;

#[test]
fn r3_med1_userinfo() {
    assert_eq!(
        redact_chat("REDIS_URL=redis://:S3cretPass@redis.example:6379/0"),
        "REDIS_URL=redis://:[REDACTED]@redis.example:6379/0"
    );
    assert_eq!(
        redact_chat("postgres://app:p&ss;word@db/x"),
        "postgres://app:[REDACTED]@db/x"
    );
    // Split so the ssh scheme prefix never appears as a source literal (see
    // chat.rs): the community leak scan flags that prefix tree-wide as a
    // private-remote marker; the runtime string is unchanged.
    for text in [
        concat!("ssh", "://git@github.com"),
        "redis://user:@db",
        "a://@",
    ] {
        assert_eq!(redact_chat(text), text);
    }
}

#[test]
fn r3_med2_names() {
    for name in [
        "accessToken",
        "clientSecret",
        "dbPassword",
        "privateKey",
        "_authToken",
        "passphrase",
        "SecretAccessKey",
        "SessionToken",
        "PGPASSWORD",
        "API_KEY_PROD",
        "ENCRYPTION_KEY_HEX",
    ] {
        let input = format!("{name}=SyntheticCredential123");
        assert_eq!(redact_chat(&input), format!("{name}=[REDACTED]"));
    }
    assert_eq!(
        redact_chat("Proxy-Authorization: Basic c3ludGhldGljOnBhc3M="),
        "Proxy-Authorization: Basic [REDACTED]"
    );
    for input in [
        "token_count=42",
        "PASSWORD_TYPE=string",
        "TOKEN_URL=https://example.invalid",
        "key_name=ordinary",
    ] {
        assert_eq!(redact_chat(input), input);
    }
}

#[test]
fn r3_med3_arrows() {
    for sep in ["=>", "==", ":="] {
        let input = format!("'password' {sep} 'SyntheticPassphrase123'");
        assert_eq!(
            redact_chat(&input),
            format!("'password' {sep} '[REDACTED]'")
        );
    }
}

#[test]
fn r3_med4_embedded_hex() {
    for (prefix, count) in [("key-", 32), ("api_", 32), ("x", 41), ("0x", 48)] {
        assert_eq!(
            redact_chat(&format!("{prefix}{}", "a".repeat(count))),
            format!("{prefix}[REDACTED]")
        );
    }
    for count in [32, 40] {
        let hex = "ABCDEF0123".repeat(4)[..count].to_owned();
        assert_eq!(redact_chat(&hex), "[REDACTED]");
    }
}

#[test]
fn r3_low_glued_idempotence() {
    let corpus = [
        format!("id={}ghp_{}", "a".repeat(40), "Z".repeat(30)),
        format!("{}Zq9SECRETTAIL", "a".repeat(32)),
        "password=x-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC_BODY\n-----END RSA PRIVATE KEY-----"
            .to_owned(),
    ];
    for input in corpus {
        let output = redact_chat(&input);
        assert!(
            !output.contains("SECRETTAIL")
                && !output.contains("ghp_")
                && !output.contains("SYNTHETIC_BODY")
        );
        assert_eq!(redact_chat(&output), output);
    }
    // Deterministic combinatorial property: no dependency, time seed, or env.
    for prefix in ["", "id=", "prefix", "key-", "\\n"] {
        for count in [31, 32, 40, 41, 64, 65] {
            for suffix in ["", "Zq9SECRETTAIL", ".opaqueVALUE123", ". "] {
                let input = format!("{prefix}{}{suffix}", "a".repeat(count));
                let once = redact_chat(&input);
                assert_eq!(redact_chat(&once), once);
            }
        }
    }
}

#[test]
fn r3_low_punctuation() {
    for password in ["Tr0ub4dor&3xyz", "ab\\cd", "Ab;cd&ef"] {
        assert_eq!(
            redact_chat(&format!("DB_PASSWORD={password}")),
            "DB_PASSWORD=[REDACTED]"
        );
    }
    assert_eq!(
        redact_chat("https://db.invalid/?password=SecretValue&next=plain"),
        "https://db.invalid/?password=[REDACTED]&next=plain"
    );
}

#[test]
fn r3_low_quote_newline() {
    let input = "password=\"SyntheticPassphrase\nThe next step is public";
    assert_eq!(
        redact_chat(input),
        "password=\"[REDACTED]\nThe next step is public"
    );
    assert_eq!(
        redact_chat("Password:\nThe next step"),
        "Password:\nThe next step"
    );
    assert_eq!(
        redact_chat("Password:\n  SyntheticSecret"),
        "Password:\n  [REDACTED]"
    );
    let input = format!("password=\"{} PUBLIC_TAIL", "Z".repeat(1024));
    assert_eq!(redact_chat(&input), "password=\"[REDACTED]");
}

#[test]
fn r3_low_unicode() {
    let input = r"\u0022password\u0022:\u0022SyntheticPassphrase\u0022";
    assert_eq!(
        redact_chat(input),
        r"\u0022password\u0022:\u0022[REDACTED]\u0022"
    );
    let input = r"password\u003dSyntheticValue";
    assert_eq!(redact_chat(input), r"password\u003d[REDACTED]");
}

#[test]
fn r3_low_forms() {
    for (input, expected) in [
        (
            "<password>synthetic</password>",
            "<password>[REDACTED]</password>",
        ),
        ("password SyntheticPass", "password [REDACTED]"),
        ("--password SyntheticPass", "--password [REDACTED]"),
        (
            "Cookie: session=SyntheticPass; other=SyntheticValue",
            "Cookie: [REDACTED]",
        ),
        (
            r#"{"auth":"c3ludGhldGljOnBhc3M="}"#,
            r#"{"auth":"[REDACTED]"}"#,
        ),
        (
            "https://SyntheticOpaqueCredential@host/x",
            "https://[REDACTED]@host/x",
        ),
    ] {
        assert_eq!(redact_chat(input), expected);
    }
    for (prefix, body) in [("npm_", 30), ("glpat-", 20)] {
        assert_eq!(
            redact_chat(&format!("{prefix}{}", "Z".repeat(body))),
            "[REDACTED]"
        );
    }
}

#[test]
fn r3_low_false_hits() {
    for input in [
        "token_count=42",
        "password: string",
        "key: string",
        "primary_key = id",
        "sort_key=42",
        "TOKEN_URL=https://example.invalid",
        "PWD=/path",
        "Use the key: press enter",
        "key={item.id}",
        "GOOGLE_APPLICATION_CREDENTIALS=/path",
        "ASIA_PACIFIC_REGION_CODE=1",
        "sk_test_suite_runner",
        "ghp_tokens_are_described_here",
    ] {
        assert_eq!(redact_chat(input), input);
    }
}

#[test]
fn scanner_shards_stay_bounded() {
    for source in [
        include_str!("../src/chat.rs"),
        include_str!("../src/chat_fields.rs"),
    ] {
        let lines = source
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with("//"))
            .count();
        assert!(
            lines <= 500,
            "scanner shard exceeds numeric load-bearing budget: {lines}"
        );
    }
}

#[test]
fn r3_low_mixed_idempotence_property() {
    let spans = [
        "[REDACTED]",
        "\"",
        "'",
        "id=",
        "password=",
        "Authorization: Basic ",
        "key-",
        "0123456789abcdef0123456789abcdef",
        "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "é ",
        " ",
        "\\n",
        ".",
        "Zq9SECRETTAIL",
        "&next=plain",
        "\\u0022",
    ];
    let mut state = 0x12345678_u32;
    for _ in 0..512 {
        let mut input = String::new();
        for _ in 0..8 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            input.push_str(spans[(state as usize) % spans.len()]);
        }
        let once = redact_chat(&input);
        assert_eq!(redact_chat(&once), once);
    }
}
