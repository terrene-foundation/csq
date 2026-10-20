use super::*;
use tempfile::TempDir;

struct GitFixture {
    temp: TempDir,
    primary: PathBuf,
    home: PathBuf,
}

impl GitFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let fixture = Self {
            temp,
            primary,
            home,
        };
        fixture.git(fixture.temp.path(), &["init", "primary"]);
        fixture.git(
            &fixture.primary,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "fixture",
            ],
        );
        fixture
    }

    fn clean_command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command.env_clear();
        for key in [
            "PATH",
            "LANG",
            "LC_ALL",
            "TERM",
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("TMPDIR", self.temp.path())
            .env("TMP", self.temp.path())
            .env("TEMP", self.temp.path())
            .env("CSQ_FENCE_MANAGED_FIXTURE", self.home.join("managed"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.home.join("no-config"));
        command
    }

    fn git(&self, cwd: &Path, args: &[&str]) {
        let output = csq_core::platform::test_git::command(cwd, &self.home)
            .expect("sandbox Git command")
            .args(args)
            .output()
            .expect("actual Git is required");
        assert!(
            output.status.success(),
            "Git fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn worktree(&self, path: &Path) {
        let output = csq_core::platform::test_git::command(&self.primary, &self.home)
            .expect("sandbox Git command")
            .args(["worktree", "add", "--detach"])
            .arg(path)
            .arg("HEAD")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Git worktree fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn primary_root_and_nested_directory_refuse() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let nested = fixture.primary.join("src/nested");
    std::fs::create_dir_all(&nested).unwrap();
    for cwd in [&fixture.primary, &nested] {
        let error = admit_provider_session_workdir(cwd).unwrap_err().to_string();
        assert!(error.contains("cannot start inside a primary checkout"));
        assert!(error.contains("does not restrict filesystem access"));
        assert!(!error.contains(fixture.temp.path().to_str().unwrap()));
    }
}

#[cfg(unix)]
#[test]
fn primary_symlink_alias_refuses() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let alias = fixture.temp.path().join("alias");
    std::os::unix::fs::symlink(&fixture.primary, &alias).unwrap();
    assert!(admit_provider_session_workdir(&alias).is_err());
}

#[test]
fn registered_linked_worktree_and_nonrepository_admit() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let linked = fixture.temp.path().join("linked");
    fixture.worktree(&linked);
    let nested = linked.join("src/nested");
    std::fs::create_dir_all(&nested).unwrap();
    admit_provider_session_workdir(&linked).unwrap();
    admit_provider_session_workdir(&nested).unwrap();
    admit_provider_session_workdir(&fixture.home).unwrap();
}

#[test]
fn linked_worktree_enclosed_by_primary_refuses() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let linked = fixture.primary.join("nested-worktree");
    fixture.worktree(&linked);
    assert!(admit_provider_session_workdir(&linked).is_err());
}

#[test]
fn missing_cwd_malformed_metadata_and_broken_registration_refuse() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    assert!(admit_provider_session_workdir(&fixture.temp.path().join("missing")).is_err());
    let ambiguous = fixture.home.join(".git");
    for value in [
        "invalid\n",
        "gitdir: absent\n",
        "gitdir: absent\nsecond-line\n",
    ] {
        std::fs::write(&ambiguous, value).unwrap();
        assert!(admit_provider_session_workdir(&fixture.home).is_err());
    }
    std::fs::remove_file(&ambiguous).unwrap();
    let linked = fixture.temp.path().join("linked");
    fixture.worktree(&linked);
    let marker = std::fs::read_to_string(linked.join(".git")).unwrap();
    let gitdir = PathBuf::from(marker.trim().strip_prefix("gitdir: ").unwrap());
    std::fs::write(
        gitdir.join("gitdir"),
        fixture.primary.join(".git").to_str().unwrap(),
    )
    .unwrap();
    assert!(admit_provider_session_workdir(&linked).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_repository_marker_refuses() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    std::os::unix::fs::symlink(fixture.primary.join(".git"), fixture.home.join(".git")).unwrap();
    assert!(admit_provider_session_workdir(&fixture.home).is_err());
}

#[test]
fn separate_gitdir_primary_refuses_and_missing_worktree_metadata_refuses() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let separate = fixture.temp.path().join("separate");
    let admin = fixture.temp.path().join("separate-admin");
    let output = csq_core::platform::test_git::command(fixture.temp.path(), &fixture.home)
        .expect("sandbox Git command")
        .arg("init")
        .arg("--separate-git-dir")
        .arg(&admin)
        .arg(&separate)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(admit_provider_session_workdir(&separate).is_err());
    let linked = fixture.temp.path().join("linked");
    fixture.worktree(&linked);
    let marker = std::fs::read_to_string(linked.join(".git")).unwrap();
    let gitdir = PathBuf::from(marker.trim().strip_prefix("gitdir: ").unwrap());
    std::fs::remove_file(gitdir.join("commondir")).unwrap();
    assert!(admit_provider_session_workdir(&linked).is_err());
}

fn write_policy(path: &Path, policy: serde_json::Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({"provider_session": policy})).unwrap(),
    )
    .unwrap();
}

#[test]
fn owner_postures_classify_origin_not_model_or_provider_label() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let policy = base.join("provider-session-policy.json");
    let remote = "https://api.deepseek.com/anthropic";
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, remote)
            .unwrap()
            .is_none()
    );
    for posture in ["allow", "warn", "refuse"] {
        write_policy(&policy, serde_json::json!({"primary_checkout":posture}));
        let result = provider_session_policy::evaluate(&base, &fixture.primary, remote);
        match posture {
            "allow" => assert!(result.unwrap().is_none()),
            "warn" => assert!(result
                .unwrap()
                .unwrap()
                .contains("provider_session.primary_checkout=warn")),
            _ => assert!(result
                .unwrap_err()
                .to_string()
                .contains("https://api.deepseek.com")),
        }
        for local in [
            "http://localhost:11434",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "https://api.anthropic.com/v1",
        ] {
            assert!(
                provider_session_policy::evaluate(&base, &fixture.primary, local)
                    .unwrap()
                    .is_none()
            );
        }
    }
    for spoof in [
        "https://localhost.evil.invalid",
        "https://api.anthropic.com.evil.invalid",
        "http://api.anthropic.com",
        "https://api.anthropic.com:8443",
    ] {
        assert!(provider_session_policy::evaluate(&base, &fixture.primary, spoof).is_err());
    }
}

#[test]
fn fieldwise_inheritance_and_trusted_list_replacement_are_explicit() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let global = base.join("provider-session-policy.json");
    let repo = fixture.primary.join(".coc/csq.json");
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse", "trusted_endpoints":["https://private.example:8443"]}),
    );
    assert!(provider_session_policy::evaluate(
        &base,
        &fixture.primary,
        "https://PRIVATE.example:8443/anthropic"
    )
    .unwrap()
    .is_none());
    for endpoint in [
        "http://private.example:8443",
        "https://private.example",
        "https://private.example.evil.invalid:8443",
    ] {
        assert!(provider_session_policy::evaluate(&base, &fixture.primary, endpoint).is_err());
    }
    write_policy(&repo, serde_json::json!({"trusted_endpoints":[]}));
    assert!(provider_session_policy::evaluate(
        &base,
        &fixture.primary,
        "https://private.example:8443"
    )
    .is_err());
    write_policy(&repo, serde_json::json!({"primary_checkout":"allow"}));
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
            .is_err()
    );
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse", "trusted_endpoints":["https://private.example:8443"], "allow_repo_relax":true}),
    );
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
            .unwrap()
            .is_none()
    );
    write_policy(
        &repo,
        serde_json::json!({"trusted_endpoints":["https://other-private.example"]}),
    );
    assert!(provider_session_policy::evaluate(
        &base,
        &fixture.primary,
        "https://other-private.example:443/task"
    )
    .unwrap()
    .is_none());
    assert!(provider_session_policy::evaluate(
        &base,
        &fixture.primary,
        "https://private.example:8443"
    )
    .is_err());
}

#[test]
fn malformed_present_policy_refuses_and_diagnostics_never_echo_secrets() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let policy = base.join("provider-session-policy.json");
    write_policy(&policy, serde_json::json!({"primary_checkout":"refuse"}));
    let error = provider_session_policy::evaluate(&base, &fixture.primary, "https://user:password-canary@api.deepseek.com/anthropic?token=query-canary#fragment-canary").unwrap_err().to_string();
    assert!(error.contains("https://api.deepseek.com"));
    for secret in ["user", "password-canary", "query-canary", "fragment-canary"] {
        assert!(!error.contains(secret));
    }
    for malformed in [
        serde_json::json!({"primary_checkout":"refues"}),
        serde_json::json!({"unknown_key":"secret-canary"}),
        serde_json::json!({"trusted_endpoints":["https://name:secret-canary@private.example"]}),
        serde_json::json!({"trusted_endpoints":["https://private.example/path?secret-canary"]}),
    ] {
        write_policy(&policy, malformed);
        let error =
            provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
                .unwrap_err()
                .to_string();
        assert!(error.contains("provider_session.primary_checkout"));
        assert!(!error.contains("secret-canary"));
    }
    std::fs::write(&policy, vec![b' '; 65_537]).unwrap();
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn policy_symlink_and_nonregular_configuration_refuse_without_following() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    std::fs::create_dir_all(&base).unwrap();
    let policy = base.join("provider-session-policy.json");
    let target = fixture.temp.path().join("external-policy.json");
    write_policy(&target, serde_json::json!({"primary_checkout":"allow"}));
    std::os::unix::fs::symlink(&target, &policy).unwrap();
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
            .is_err()
    );
    std::fs::remove_file(&policy).unwrap();
    std::fs::create_dir(&policy).unwrap();
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
            .is_err()
    );
}

#[test]
fn default_allow_preserves_behavior_when_destination_or_git_is_uncertain() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let policy = base.join("provider-session-policy.json");
    std::fs::write(fixture.home.join(".git"), "malformed").unwrap();
    assert!(
        provider_session_policy::evaluate(&base, &fixture.home, "malformed-secret-url\n")
            .unwrap()
            .is_none()
    );
    assert!(provider_session_policy::evaluate(
        &base,
        &fixture.temp.path().join("missing"),
        "malformed-secret-url\n"
    )
    .unwrap()
    .is_none());
    write_policy(&policy, serde_json::json!({"primary_checkout":"warn"}));
    assert!(
        provider_session_policy::evaluate(&base, &fixture.home, "https://remote.invalid")
            .unwrap()
            .unwrap()
            .contains("unresolved")
    );
    write_policy(&policy, serde_json::json!({"primary_checkout":"refuse"}));
    assert!(
        provider_session_policy::evaluate(&base, &fixture.home, "https://remote.invalid").is_err()
    );
}

#[test]
fn caller_admission_smoke_uses_private_home_and_actual_git_root() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let config = base.join("config-7");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("settings.json"), br#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_AUTH_TOKEN":"fixture-bearer-canary","ANTHROPIC_MODEL":"private-server-model"}}"#).unwrap();
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    for mode in [
        "handle",
        "third-party",
        "unknown",
        "override",
        "exec-refuse",
    ] {
        let output = fixture
            .clean_command(std::env::current_exe().unwrap())
            .current_dir(&fixture.primary)
            .env("PATH", &fixture.home)
            .env("CSQ_BASE_DIR", &base)
            .env("CSQ_FENCE_CHILD", mode)
            .args([
                "--exact",
                "cli::commands::run::provider_session_fence_tests::caller_admission_child",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "caller smoke failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.contains("fixture-bearer-canary"));
        assert!(!output.contains(fixture.temp.path().to_str().unwrap()));
    }
    assert!(
        !config.join(".current-account").exists(),
        "admission must precede marker writes"
    );
    assert!(!base.join(format!("term-{}", std::process::id())).exists());
}

#[test]
fn caller_checks_private_server_and_global_uuid_precedence() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/anthropic", listener.local_addr().unwrap());
    let base = fixture.temp.path().join("accounts");
    let config = base.join("config-7");
    std::fs::create_dir_all(&config).unwrap();
    let global = fixture.home.join(".claude/settings.json");
    std::fs::create_dir_all(global.parent().unwrap()).unwrap();
    std::fs::write(
        &global,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://global-remote.invalid"}}"#,
    )
    .unwrap();
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    std::fs::write(config.join("settings.json"), serde_json::to_vec(&serde_json::json!({"env":{"ANTHROPIC_BASE_URL":endpoint,"ANTHROPIC_MODEL":"deepseek-model-name"}})).unwrap()).unwrap();
    let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
    let uuid = csq_core::accounts::identity_store::IdentityId::new_v4();
    profiles.by_slot.insert("7".to_string(), uuid);
    csq_core::accounts::profiles::save(&base.join("profiles.json"), &profiles).unwrap();
    let uuid_settings = csq_core::accounts::identity_store::settings_path_for(&base, uuid);
    std::fs::create_dir_all(uuid_settings.parent().unwrap()).unwrap();
    for (settings, expected) in [
        (
            serde_json::json!({"env":{"ANTHROPIC_BASE_URL":"https://uuid-remote.invalid"}}),
            "checker-refuse",
        ),
        (
            serde_json::json!({"env":{"ANTHROPIC_BASE_URL":endpoint}}),
            "checker-pass",
        ),
    ] {
        std::fs::write(&uuid_settings, serde_json::to_vec(&settings).unwrap()).unwrap();
        let output = fixture
            .clean_command(std::env::current_exe().unwrap())
            .current_dir(&fixture.primary)
            .env("PATH", &fixture.home)
            .env("CSQ_BASE_DIR", &base)
            .env("CSQ_FENCE_CHILD", expected)
            .args([
                "--exact",
                "cli::commands::run::provider_session_fence_tests::caller_admission_child",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "caller precedence check failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn caller_admission_child() {
    let _env = csq_core::platform::test_env::lock();
    let Ok(mode) = std::env::var("CSQ_FENCE_CHILD") else {
        return;
    };
    let base = PathBuf::from(std::env::var_os("CSQ_BASE_DIR").unwrap());
    let home = PathBuf::from(std::env::var_os("HOME").unwrap()).join(".claude");
    let account = AccountNum::try_from(7_u16).unwrap();
    if mode == "directory-refuse" {
        let target = std::env::var("CSQ_FENCE_TARGET").unwrap();
        for arguments in [
            vec!["-C".to_string(), target.clone()],
            vec![format!("--cd={target}")],
            vec!["--work-dir".to_string(), target.clone()],
            vec!["--cwd".to_string(), target.clone()],
            vec!["--directory".to_string(), target.clone()],
        ] {
            assert!(
                provider_session_policy::check_unknown_launch_with_args(&base, &arguments).is_err()
            );
            assert!(provider_session_policy::check_claude_launch(
                &base, &home, account, None, &arguments
            )
            .is_err());
        }
        assert!(provider_session_policy::check_unknown_launch(&base)
            .unwrap()
            .is_none());
        return;
    }
    if mode == "warn-settings" {
        let warning =
            provider_session_policy::check_claude_launch(&base, &home, account, None, &[])
                .unwrap()
                .unwrap();
        assert!(warning.contains("unresolved/untrusted"));
        assert!(!warning.contains("settings-secret-canary"));
        return;
    }
    if mode == "floor-refuse" {
        assert!(
            provider_session_policy::check_claude_launch(&base, &home, account, None, &[]).is_err()
        );
        assert!(provider_session_policy::check_unknown_launch(&base).is_err());
        assert!(provider_session_policy::check_exec_vendor_launch(
            &base,
            &std::env::current_dir().unwrap()
        )
        .is_err());
        assert!(!base.join(format!("term-{}", std::process::id())).exists());
        return;
    }
    if mode == "checker-pass" || mode == "checker-refuse" {
        let result = provider_session_policy::check_claude_launch(&base, &home, account, None, &[]);
        if mode == "checker-pass" {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.is_err());
        }
        assert!(!base.join(format!("term-{}", std::process::id())).exists());
        return;
    }
    if mode == "alias-pass" {
        let alias = std::env::var("CSQ_FENCE_TARGET").unwrap();
        assert!(provider_session_policy::check_claude_launch(
            &base,
            &home,
            account,
            None,
            &[format!("--cd={alias}")]
        )
        .unwrap()
        .is_none());
        return;
    }
    let mut audit = crate::cli::audit_emit::AuditEmitter::disabled();
    if mode == "exec-refuse" {
        let error =
            super::super::exec::provider_session_test_run_exec(&base, &home, 7).unwrap_err();
        assert_eq!(error.code, csq_core::sdk::SdkErrorCode::SpawnFailed);
        assert!(serde_json::to_value(&error).unwrap()["message"]
            .as_str()
            .unwrap()
            .starts_with("provider-session fence:"));
        assert!(!base.join(format!("term-{}", std::process::id())).exists());
        return;
    }
    if mode == "swap-trusted" {
        let handle = base.join(format!("term-{}", std::process::id()));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join("settings.json"),
            br#"{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}"#,
        )
        .unwrap();
        // This is the same helper used at the actual swap exec boundary. Its
        // settings-file join is part of the admission path under test.
        super::super::swap::admit_materialized_claude_swap(&base, account, &handle).unwrap();
        return;
    }
    if mode == "metadata-invalid" {
        let cwd = std::env::current_dir().unwrap();
        assert!(provider_session_repository(&cwd).is_err());
        // The compatibility default must return promptly despite ambiguous Git.
        assert!(
            provider_session_policy::evaluate(&base, &cwd, "https://remote.invalid")
                .unwrap()
                .is_none()
        );
        return;
    }
    if mode == "swap-refuse" {
        let source = base.join("source-handle");
        for surface in [
            Surface::ClaudeCode,
            Surface::Codex,
            Surface::Gemini,
            Surface::Kimi,
            Surface::Grok,
        ] {
            let error = super::super::swap::provider_session_test_exec_replace(
                &base,
                source.clone(),
                account,
                surface,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.starts_with("provider-session fence:"),
                "unexpected swap admission: {error}"
            );
            assert_eq!(
                std::fs::read(source.join("still-live")).unwrap(),
                b"source-canary"
            );
        }
        #[cfg(unix)]
        {
            let error = validate_codex_relaunch_target(
                &base,
                7,
                false,
                false,
                &CapabilityLayerToggles::default(),
                false,
                true,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.starts_with("provider-session fence:"),
                "unexpected relaunch admission: {error}"
            );
        }
        return;
    }
    if mode == "allow-override" {
        assert!(provider_session_policy::check_claude_launch(
            &base,
            &home,
            account,
            None,
            &["--settings=unresolved".to_string()]
        )
        .unwrap()
        .is_none());
        return;
    }
    if mode == "allow-unknown" {
        assert!(provider_session_policy::check_unknown_launch(&base)
            .unwrap()
            .is_none());
        return;
    }
    if mode == "warn-third-party" {
        let error = launch_third_party(&base, &home, account, &[], &mut audit)
            .unwrap_err()
            .to_string();
        assert!(
            !error.starts_with("provider-session fence:"),
            "warn must admit the launch"
        );
        return;
    }
    if mode == "checker-pass" {
        assert!(
            provider_session_policy::check_claude_launch(&base, &home, account, None, &[])
                .unwrap()
                .is_none()
        );
        return;
    }
    let result = match mode.as_str() {
        "handle" => handle(
            &base,
            Some(account),
            None,
            crate::cli::LayerIntent::ForcedOff,
            false,
            None,
            false,
            true,
            true,
            false,
            true,
            &[],
        ),
        "third-party" => launch_third_party(&base, &home, account, &[], &mut audit),
        "checker-refuse" => {
            provider_session_policy::check_claude_launch(&base, &home, account, None, &[])
                .map(|_| ())
        }
        "unknown" => provider_session_policy::check_unknown_launch(&base).map(|_| ()),
        "override" => provider_session_policy::check_claude_launch(
            &base,
            &home,
            account,
            None,
            &["--settings=unresolved".to_string()],
        )
        .map(|_| ()),
        _ => panic!("unknown fixture mode"),
    };
    let error = result.unwrap_err().to_string();
    assert!(
        error.starts_with("provider-session fence:"),
        "unexpected caller outcome: {error}"
    );
    assert!(error.contains("provider_session.primary_checkout"));
}

#[test]
fn project_transport_override_without_base_url_refuses() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    let local = fixture.primary.join(".claude/settings.local.json");
    std::fs::create_dir_all(local.parent().unwrap()).unwrap();
    std::fs::write(&local, br#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1"}}"#).unwrap();
    let output = fixture
        .clean_command(std::env::current_exe().unwrap())
        .current_dir(&fixture.primary)
        .env("PATH", &fixture.home)
        .env("CSQ_BASE_DIR", &base)
        .env("CSQ_FENCE_CHILD", "checker-refuse")
        .args([
            "--exact",
            "cli::commands::run::provider_session_fence_tests::caller_admission_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "project transport override bypassed refusal: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn nested_coc_cannot_downgrade_git_checkout_owner() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let nested = fixture.primary.join("src/deep");
    write_policy(
        &fixture.primary.join(".coc/csq.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    write_policy(
        &nested.join(".coc/csq.json"),
        serde_json::json!({"primary_checkout":"allow"}),
    );
    assert!(provider_session_policy::evaluate(&base, &nested, "https://remote.invalid").is_err());
    // A nested checkout cannot replace the outermost primary owner's policy.
    fixture.git(&nested, &["init"]);
    assert!(provider_session_policy::evaluate(&base, &nested, "https://remote.invalid").is_err());
}

#[test]
fn swap_and_supervised_relaunch_refuse_before_source_teardown() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let source = base.join("source-handle");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("still-live"), b"source-canary").unwrap();
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    let config = base.join("config-7");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("settings.json"),
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://remote.invalid"}}"#,
    )
    .unwrap();
    let output = fixture
        .clean_command(std::env::current_exe().unwrap())
        .current_dir(&fixture.primary)
        .env("PATH", &fixture.home)
        .env("CSQ_BASE_DIR", &base)
        .env("CSQ_FENCE_CHILD", "swap-refuse")
        .args([
            "--exact",
            "cli::commands::run::provider_session_fence_tests::caller_admission_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "swap refused after source damage: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(source.join("still-live")).unwrap(),
        b"source-canary"
    );
    assert_eq!(
        std::fs::read_dir(&base).unwrap().count(),
        3,
        "admission wrote target state"
    );
}

#[cfg(unix)]
#[test]
fn trusted_materialized_claude_swap_clears_actual_admission() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    let output = fixture
        .clean_command(std::env::current_exe().unwrap())
        .current_dir(&fixture.primary)
        .env("PATH", &fixture.home)
        .env("CSQ_BASE_DIR", &base)
        .env("CSQ_FENCE_CHILD", "swap-trusted")
        .args([
            "--exact",
            "cli::commands::run::provider_session_fence_tests::caller_admission_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "trusted actual swap caller failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn administrative_metadata_symlink_is_not_a_registered_worktree() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let worktree = fixture.temp.path().join("linked");
    fixture.worktree(&worktree);
    let marker = std::fs::read_to_string(worktree.join(".git")).unwrap();
    let gitdir = PathBuf::from(marker.trim().strip_prefix("gitdir: ").unwrap());
    let commondir = gitdir.join("commondir");
    let regular = gitdir.join("commondir-real");
    std::fs::rename(&commondir, &regular).unwrap();
    std::os::unix::fs::symlink(&regular, &commondir).unwrap();
    assert!(provider_session_repository(&worktree).is_err());
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    assert!(provider_session_policy::evaluate(&base, &worktree, "https://remote.invalid").is_err());
}

#[cfg(unix)]
#[test]
fn administrative_fifo_is_bounded_and_symlink_is_ambiguous() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let worktree = fixture.temp.path().join("linked");
    fixture.worktree(&worktree);
    let marker = std::fs::read_to_string(worktree.join(".git")).unwrap();
    let gitdir = PathBuf::from(marker.trim().strip_prefix("gitdir: ").unwrap());
    let commondir = gitdir.join("commondir");
    let regular = gitdir.join("commondir-real");
    std::fs::rename(&commondir, &regular).unwrap();
    let fifo = std::ffi::CString::new(commondir.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated private-fixture path is passed to mkfifo.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let base = fixture.temp.path().join("accounts");
    let mut child = fixture
        .clean_command(std::env::current_exe().unwrap())
        .current_dir(&worktree)
        .env("PATH", &fixture.home)
        .env("CSQ_BASE_DIR", &base)
        .env("CSQ_FENCE_CHILD", "metadata-invalid")
        .args([
            "--exact",
            "cli::commands::run::provider_session_fence_tests::caller_admission_child",
            "--nocapture",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Env custody is done: this test mutates no process-global env and the
    // child inherited its environment at `spawn()` above (explicit `.env()`
    // overrides included). Release the shared lock before the wait so a
    // sibling is not delayed by this test's deadline.
    drop(_env);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let finished = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    if !finished {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        finished,
        "Git FIFO blocked admission; bounded child was killed"
    );
    assert!(
        output.status.success(),
        "metadata child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_file(&commondir).unwrap();
    std::os::unix::fs::symlink(&regular, &commondir).unwrap();
    assert!(provider_session_repository(&worktree).is_err());
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    assert!(provider_session_policy::evaluate(&base, &worktree, "https://remote.invalid").is_err());
}

#[test]
fn actual_caller_default_allow_admits_overrides_and_warn_emits_once() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let config = base.join("config-7");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("settings.json"), br#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_AUTH_TOKEN":"fixture-only-token"}}"#).unwrap();
    for mode in ["allow-override", "allow-unknown", "warn-third-party"] {
        if mode == "warn-third-party" {
            write_policy(
                &base.join("provider-session-policy.json"),
                serde_json::json!({"primary_checkout":"warn"}),
            );
        }
        let output = fixture
            .clean_command(std::env::current_exe().unwrap())
            .current_dir(&fixture.primary)
            .env("PATH", &fixture.home)
            .env("CSQ_BASE_DIR", &base)
            .env("CSQ_FENCE_CHILD", mode)
            .args([
                "--exact",
                "cli::commands::run::provider_session_fence_tests::caller_admission_child",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "caller allow/warn check failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let count = String::from_utf8_lossy(&output.stderr)
            .matches("csq: warning: provider-session fence:")
            .count();
        assert_eq!(count, usize::from(mode == "warn-third-party"));
    }
}

fn revision_child(fixture: &GitFixture, base: &Path, cwd: &Path, mode: &str, target: &Path) {
    let output = fixture
        .clean_command(std::env::current_exe().unwrap())
        .current_dir(cwd)
        .env("PATH", &fixture.home)
        .env("CSQ_BASE_DIR", base)
        .env("CSQ_FENCE_CHILD", mode)
        .env("CSQ_FENCE_TARGET", target)
        .args([
            "--exact",
            "cli::commands::run::provider_session_fence_tests::caller_admission_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "private revision caller failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn f2_start_directory_arguments_use_target_owner_policy() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &fixture.primary.join(".coc/csq.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    let config = base.join("config-7/settings.json");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        config,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://remote.invalid"}}"#,
    )
    .unwrap();
    revision_child(
        &fixture,
        &base,
        &fixture.home,
        "directory-refuse",
        &fixture.primary,
    );
}

#[test]
fn f3_loopback_default_is_removable_and_requires_explicit_restore() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let global = base.join("provider-session-policy.json");
    let endpoint = "http://127.0.0.1:11434/anthropic";
    write_policy(&global, serde_json::json!({"primary_checkout":"refuse"}));
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, endpoint)
            .unwrap()
            .is_none()
    );
    for extra in [
        serde_json::json!({"primary_checkout":"refuse","trust_loopback":false}),
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":[]}),
    ] {
        write_policy(&global, extra);
        assert!(provider_session_policy::evaluate(&base, &fixture.primary, endpoint).is_err());
    }
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":[],"trust_loopback":true}),
    );
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, endpoint)
            .unwrap()
            .is_none()
    );
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse","trust_loopback":false,"trusted_endpoints":["http://127.0.0.1:11434"]}),
    );
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, endpoint)
            .unwrap()
            .is_none()
    );
}

#[test]
fn f4_trusted_project_candidates_admit() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://private.invalid","https://second-private.invalid"]}),
    );
    let project = fixture.primary.join(".claude/settings.json");
    let local = fixture.primary.join(".claude/settings.local.json");
    std::fs::create_dir_all(project.parent().unwrap()).unwrap();
    std::fs::write(
        &project,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://private.invalid/anthropic"}}"#,
    )
    .unwrap();
    std::fs::write(
        &local,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://second-private.invalid/anthropic"}}"#,
    )
    .unwrap();
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-pass",
        &fixture.primary,
    );
    std::fs::write(
        &local,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://untrusted.invalid/anthropic"}}"#,
    )
    .unwrap();
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-refuse",
        &fixture.primary,
    );
    // Cloud resolution remains unknown until its separately reviewed fix.
    std::fs::write(&local, br#"{"env":{"ANTHROPIC_BASE_URL":"https://private.invalid/anthropic","CLAUDE_CODE_USE_BEDROCK":"1"}}"#).unwrap();
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-refuse",
        &fixture.primary,
    );
}

#[test]
fn f5_launch_parse_failures_follow_warn_and_refuse_postures() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let global = base.join("provider-session-policy.json");
    let config = base.join("config-7/settings.json");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    for bad in [
        br#"{"env":{"ANTHROPIC_BASE_URL":123}}"#.as_slice(),
        b"settings-secret-canary not json".as_slice(),
        br#"{"env":false}"#.as_slice(),
        br#"{"env":{"ANTHROPIC_BASE_URL":"file:///settings-secret-canary"}}"#.as_slice(),
    ] {
        std::fs::write(&config, bad).unwrap();
        write_policy(&global, serde_json::json!({"primary_checkout":"warn"}));
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "warn-settings",
            &fixture.primary,
        );
        assert!(provider_session_policy::evaluate(
            &base,
            &fixture.primary,
            "settings-secret-canary\n"
        )
        .unwrap()
        .is_some());
        write_policy(&global, serde_json::json!({"primary_checkout":"refuse"}));
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "checker-refuse",
            &fixture.primary,
        );
    }
}

#[test]
fn f6_global_privacy_floor_applies_to_all_repository_exemptions() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let global = base.join("provider-session-policy.json");
    let repo = fixture.primary.join(".coc/csq.json");
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse","trust_loopback":false,"trusted_endpoints":["https://owner.invalid"]}),
    );
    write_policy(
        &repo,
        serde_json::json!({"primary_checkout":"allow","trust_loopback":true,"trusted_endpoints":["https://repo.invalid","http://localhost:11434"]}),
    );
    for endpoint in [
        "https://repo.invalid",
        "http://localhost:11434",
        "https://remote.invalid",
    ] {
        assert!(provider_session_policy::evaluate(&base, &fixture.primary, endpoint).is_err());
    }
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse","allow_repo_relax":true,"trust_loopback":false}),
    );
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://repo.invalid")
            .unwrap()
            .is_none()
    );
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"allow","trust_loopback":false}),
    );
    write_policy(
        &repo,
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://repo.invalid"]}),
    );
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://repo.invalid")
            .unwrap()
            .is_none()
    );
    assert!(
        provider_session_policy::evaluate(&base, &fixture.primary, "https://remote.invalid")
            .is_err()
    );
    let linked = fixture.temp.path().join("linked");
    fixture.worktree(&linked);
    write_policy(
        &linked.join(".coc/csq.json"),
        serde_json::json!({"primary_checkout":"refuse","invalid-policy":true}),
    );
    assert!(
        provider_session_policy::evaluate(&base, &linked, "https://remote.invalid")
            .unwrap()
            .is_none()
    );
}

#[test]
fn f6_invalid_inner_git_cannot_hide_outer_owner_refusal() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &fixture.primary.join(".coc/csq.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    let nested = fixture.primary.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    for marker in ["malformed", "gitdir: ../.git/modules/missing"] {
        std::fs::write(nested.join(".git"), marker).unwrap();
        assert!(provider_session_repository(&nested).is_err());
        revision_child(&fixture, &base, &nested, "checker-refuse", &nested);
        let error = provider_session_policy::evaluate(&base, &nested, "https://remote.invalid")
            .unwrap_err()
            .to_string();
        assert!(error.contains("repository location is unresolved"));
    }
}

#[test]
fn f6_actual_callers_enforce_each_global_privacy_floor() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let global = base.join("provider-session-policy.json");
    let repo = fixture.primary.join(".coc/csq.json");
    let slot = base.join("config-7/settings.json");
    std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse","trust_loopback":false,"trusted_endpoints":["https://owner.invalid"]}),
    );
    for (repository, endpoint) in [
        (
            serde_json::json!({"primary_checkout":"allow"}),
            "https://remote.invalid",
        ),
        (
            serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://repo.invalid"]}),
            "https://repo.invalid",
        ),
        (
            serde_json::json!({"primary_checkout":"refuse","trust_loopback":true}),
            "http://127.0.0.1:11434",
        ),
    ] {
        write_policy(&repo, repository);
        std::fs::write(
            &slot,
            serde_json::to_vec(&serde_json::json!({"env":{"ANTHROPIC_BASE_URL":endpoint}}))
                .unwrap(),
        )
        .unwrap();
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "floor-refuse",
            &fixture.primary,
        );
    }
    write_policy(
        &repo,
        serde_json::json!({"primary_checkout":"allow","allow_repo_relax":true}),
    );
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "floor-refuse",
        &fixture.primary,
    );
    write_policy(
        &repo,
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://owner.invalid"]}),
    );
    std::fs::write(
        &slot,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://owner.invalid/anthropic"}}"#,
    )
    .unwrap();
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-pass",
        &fixture.primary,
    );
    // An explicit global grant permits a repo relaxation; the default grant is absent.
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"refuse","allow_repo_relax":true,"trust_loopback":false}),
    );
    write_policy(&repo, serde_json::json!({"primary_checkout":"allow"}));
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-pass",
        &fixture.primary,
    );
    write_policy(
        &global,
        serde_json::json!({"primary_checkout":"allow","trust_loopback":false}),
    );
    write_policy(
        &repo,
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://repo.invalid"]}),
    );
    std::fs::write(
        &slot,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://repo.invalid/anthropic"}}"#,
    )
    .unwrap();
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-pass",
        &fixture.primary,
    );
}

#[test]
fn f5_invalid_endpoint_url_follows_actual_caller_warn_policy() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    let global = base.join("provider-session-policy.json");
    let slot = base.join("config-7/settings.json");
    std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
    std::fs::write(
        &slot,
        br#"{"env":{"ANTHROPIC_BASE_URL":"file:///settings-secret-canary"}}"#,
    )
    .unwrap();
    write_policy(&global, serde_json::json!({"primary_checkout":"warn"}));
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "warn-settings",
        &fixture.primary,
    );
    write_policy(&global, serde_json::json!({"primary_checkout":"refuse"}));
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-refuse",
        &fixture.primary,
    );
    // Compatibility allow admits the same unresolved settings without decoding them.
    write_policy(&global, serde_json::json!({"primary_checkout":"allow"}));
    revision_child(
        &fixture,
        &base,
        &fixture.primary,
        "checker-pass",
        &fixture.primary,
    );
}

#[test]
fn f7_managed_file_and_fragments_are_admitted_before_launch() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    for file in [
        "managed-settings.json",
        "managed-settings.d/20-routing.json",
    ] {
        let path = fixture.home.join("managed").join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            br#"{"env":{"ANTHROPIC_BASE_URL":"https://managed-untrusted.invalid"}}"#,
        )
        .unwrap();
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "checker-refuse",
            &fixture.primary,
        );
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn f8_project_walk_stops_at_canonical_root_for_alias() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse"}),
    );
    let outside = fixture.temp.path().join(".claude/settings.json");
    std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
    std::fs::write(
        outside,
        br#"{"env":{"ANTHROPIC_BASE_URL":"https://outside-owner.invalid"}}"#,
    )
    .unwrap();
    let alias = fixture.temp.path().join("alias");
    std::os::unix::fs::symlink(&fixture.primary, &alias).unwrap();
    revision_child(&fixture, &base, &fixture.home, "alias-pass", &alias);
}

#[test]
fn f9_explicit_cloud_endpoint_origins_can_be_trusted() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://private-cloud.invalid:8443"]}),
    );
    let path = base.join("config-7/settings.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for (flag, key) in [
        ("CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_BEDROCK_BASE_URL"),
        ("CLAUDE_CODE_USE_VERTEX", "ANTHROPIC_VERTEX_BASE_URL"),
        ("CLAUDE_CODE_USE_FOUNDRY", "ANTHROPIC_FOUNDRY_BASE_URL"),
    ] {
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"env":{flag:"1",key:"https://private-cloud.invalid:8443/route"}})).unwrap()).unwrap();
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "checker-pass",
            &fixture.primary,
        );
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"env":{flag:"1",key:"https://private-cloud.invalid:8444/route"}})).unwrap()).unwrap();
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "checker-refuse",
            &fixture.primary,
        );
    }
}

#[test]
fn split_cloud_flag_and_endpoint_are_evaluated_cumulatively() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://trusted-cloud.invalid"]}),
    );
    for directory in [
        fixture.primary.join(".claude"),
        fixture.home.join("managed/managed-settings.d"),
    ] {
        std::fs::create_dir_all(&directory).unwrap();
        let filenames = if directory.ends_with(".claude") {
            ["settings.json", "settings.local.json"]
        } else {
            ["10-cloud.json", "20-endpoint.json"]
        };
        let first = directory.join(filenames[0]);
        let second = directory.join(filenames[1]);
        std::fs::write(&first, br#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1","ANTHROPIC_BEDROCK_BASE_URL":"https://trusted-cloud.invalid"}}"#).unwrap();
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "checker-pass",
            &fixture.primary,
        );
        std::fs::write(
            &second,
            br#"{"env":{"ANTHROPIC_BEDROCK_BASE_URL":"https://untrusted-cloud.invalid"}}"#,
        )
        .unwrap();
        revision_child(
            &fixture,
            &base,
            &fixture.primary,
            "checker-refuse",
            &fixture.primary,
        );
        std::fs::remove_file(first).unwrap();
        std::fs::remove_file(second).unwrap();
    }
}

#[test]
fn nearer_project_endpoint_overrides_outer_cloud_selection() {
    let _env = csq_core::platform::test_env::lock();
    let fixture = GitFixture::new();
    let base = fixture.temp.path().join("accounts");
    write_policy(
        &base.join("provider-session-policy.json"),
        serde_json::json!({"primary_checkout":"refuse","trusted_endpoints":["https://trusted-cloud.invalid"]}),
    );
    let outer = fixture.primary.join(".claude/settings.json");
    let nested = fixture.primary.join("nested");
    let nearer = nested.join(".claude/settings.local.json");
    std::fs::create_dir_all(outer.parent().unwrap()).unwrap();
    std::fs::create_dir_all(nearer.parent().unwrap()).unwrap();
    std::fs::write(&outer, br#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1","ANTHROPIC_BEDROCK_BASE_URL":"https://trusted-cloud.invalid"}}"#).unwrap();
    revision_child(&fixture, &base, &nested, "checker-pass", &nested);
    std::fs::write(
        &nearer,
        br#"{"env":{"ANTHROPIC_BEDROCK_BASE_URL":"https://untrusted-cloud.invalid"}}"#,
    )
    .unwrap();
    revision_child(&fixture, &base, &nested, "checker-refuse", &nested);
}
