use super::*;

#[test]
fn chat_credentials_are_redacted_in_actual_temp_disk_and_resumed_entries() {
    let root = base();
    let store = SessionStore::open(root.path(), 8192).unwrap();
    let mut writer = store.create(ID).unwrap();
    let secrets = [
        "ghp_FAKETESTTOKENDONOTUSE0000000000000004567",
        "github_pat_0123456789abcdef0123456789abcdef01234567",
        "AKIA0123456789ABCDEF",
        "xoxb-0123456789abcdef0123456789abcdef",
        "sk_live_0123456789abcdef0123456789abcdef",
        "alice:fixture-password",
        "assigned-fixture-secret",
        "Zml4dHVyZTpwYXNzd29yZA==",
        "R3redisSyntheticPassword9",
        "R3accessTokenSyntheticValue9",
        "R3databaseSyntheticPassword9",
        "R3awsSyntheticSecretAccessKey9",
        "R3productionSyntheticApiKey9",
        "R3syntheticPassphraseValue9",
        "UjNwcm94eTpzeW50aGV0aWMtc2VjcmV0",
        "R3arrowSyntheticPassword9",
        "R3equalsSyntheticPassword9",
        "R3colonSyntheticPassword9",
        "ABCDEF0123456789ABCDEF0123456789AB",
        "0123456789abcdef0123456789abcdef0123456789a",
        "gho_FAKETESTTOKENDONOTUSE0000000000000004567",
        "ghu_FAKETESTTOKENDONOTUSE0000000000000004567",
        "ghs_FAKETESTTOKENDONOTUSE0000000000000004567",
        "ghr_FAKETESTTOKENDONOTUSE0000000000000004567",
        "rk_live_0123456789abcdef0123456789abcdef",
        "rk_test_0123456789abcdef0123456789abcdef",
        "sk_test_0123456789abcdef0123456789abcdef",
        "xoxe-0123456789abcdef0123456789abcdef",
        "xapp-0123456789abcdef0123456789abcdef",
        "GOCSPX-0123456789abcdef0123456789abcdef",
        "ASIA0123456789ABCDEF",
    ];
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let hex_values = [
        sha.to_owned(),
        "a".repeat(64),
        "A".repeat(40),
        "ABCDEF01".repeat(8),
    ];
    // Synthetic credential contexts from R3, passed through real temp publication.
    // One assignment per line reflects dotenv/CLI output and prevents a test-only
    // concatenation from changing the credential parser's value boundaries.
    let mut content = format!("{} {} {} {} {} postgres://{}@db.example/test password={} Authorization: Basic {}\nsha={sha}\n-----BEGIN ordinary prose\n", secrets[0], secrets[1], secrets[2], secrets[3], secrets[4], secrets[5], secrets[6], secrets[7]);
    for hex in &hex_values {
        content.push_str(&format!("unlabelled ({hex})\n"));
    }
    content.push_str(&format!(
        "REDIS_URL=redis://:{}@redis.example:6379/0\n",
        secrets[8]
    ));
    content.push_str(&format!("{{\"accessToken\":\"{}\"}}\n", secrets[9]));
    for (field, index) in [
        ("DB_PASSWORD", 10),
        ("AWS_SECRET_ACCESS_KEY", 11),
        ("API_KEY_PROD", 12),
        ("passphrase", 13),
    ] {
        content.push_str(&format!("{field}={}\n", secrets[index]));
    }
    content.push_str(&format!("ProxyAuthorization: Basic {}\n", secrets[14]));
    for (separator, index) in [("=>", 15), ("==", 16), (":=", 17)] {
        content.push_str(&format!("'password' {separator} '{}'\n", secrets[index]));
    }
    content.push_str(&format!(
        "nonsha {}\nmailgun key-{}\nembedded x{}\n",
        secrets[18], secrets[18], secrets[19]
    ));
    for secret in &secrets[20..] {
        content.push_str(secret);
        content.push('\n');
    }
    let candidate = ChatMessage {
        role: secrets[0].into(),
        content,
    };
    let mut published = Vec::new();
    writer
        .append_with_hooks(candidate, sync_directory, |temporary| {
            published = fs::read(temporary)?;
            let text = std::str::from_utf8(&published).unwrap();
            for secret in secrets {
                assert!(
                    !text.contains(secret),
                    "synthetic secret reached actual temp"
                );
            }
            for hex in &hex_values {
                assert!(!text.contains(hex), "git-sized hex reached actual temp");
            }
            assert!(text.contains("-----BEGIN ordinary prose"));
            assert_eq!(
                serde_json::from_slice::<ChatMessage>(&published)
                    .unwrap()
                    .role,
                "[REDACTED]"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(bytes(root.path()), published);
    let disk = String::from_utf8(bytes(root.path())).unwrap();
    for hex in &hex_values {
        assert!(!disk.contains(hex), "git-sized hex reached published disk");
    }
    let expected = writer.entries().to_vec();
    drop(writer);
    let resumed = store.resume(ID).unwrap();
    assert_eq!(resumed.entries(), expected);
    for entry in resumed.entries() {
        for secret in secrets {
            assert!(
                !entry.role.contains(secret) && !entry.content.contains(secret),
                "synthetic secret reached resumed entries"
            );
        }
        for hex in &hex_values {
            assert!(
                !entry.role.contains(hex) && !entry.content.contains(hex),
                "git-sized hex reached resumed entries"
            );
        }
    }
}
