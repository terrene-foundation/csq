//! Linux binary smoke: both public diagnostic formats share token-free snapshot
//! coverage. macOS needs a disposable OS user for native keychain isolation;
//! changing HOME alone would not isolate that platform's login keychain.
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

struct Fixture {
    temp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("home/.claude/accounts")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        let security = root.join("bin/security");
        fs::write(
            &security,
            b"#!/bin/sh\nprintf 'security-called\\n' >> \"$CSQ_FIXTURE_SECURITY_LOG\"\nexit 44\n",
        )
        .unwrap();
        fs::set_permissions(&security, fs::Permissions::from_mode(0o755)).unwrap();
        Self { temp }
    }

    fn base(&self) -> std::path::PathBuf {
        self.temp.path().join("home/.claude/accounts")
    }

    fn run(&self, verb: &str, json_output: bool) -> Vec<u8> {
        let root = self.temp.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_csq"));
        command
            .env_clear()
            .env("HOME", root.join("home"))
            .env("CSQ_HOME", root.join("home"))
            .env("CLAUDE_HOME", root.join("home"))
            .env("CSQ_BASE_DIR", self.base())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("bin").display()),
            )
            .env("LANG", "C")
            .env("TERM", "dumb")
            .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
            .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
            .env("CSQ_FIXTURE_SECURITY_LOG", root.join("security-calls"))
            .current_dir(root);
        if json_output {
            command.arg("--json");
        }
        let output = command.arg(verb).output().unwrap();
        assert!(
            output.status.success(),
            "{verb}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!root.join("security-calls").exists());
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(root.to_str().unwrap()), "{text}");
            assert!(!text.contains("fixture-secret-canary"), "{text}");
        }
        output.stdout
    }
}

#[test]
fn session_login_binary_missing_snapshot_is_unknown_on_both_surfaces() {
    let fixture = Fixture::new();
    for verb in ["status", "doctor"] {
        let report: Value = serde_json::from_slice(&fixture.run(verb, true)).unwrap();
        assert_eq!(report["sessions_undetermined"], true);
        assert_eq!(
            report["schema"],
            if verb == "status" {
                "csq.status.v2"
            } else {
                "csq.doctor.v35"
            }
        );
        assert!(report.get("keychain_mirror").is_none());
        let text = String::from_utf8(fixture.run(verb, false)).unwrap();
        assert!(text.contains("snapshot age=unknown"), "{text}");
        assert!(text.contains("sessions_undetermined=true"), "{text}");
    }
}

#[test]
fn session_login_binary_session_started_after_snapshot_is_visible_on_both_surfaces() {
    let fixture = Fixture::new();
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let base = fixture.base();
    fs::write(
        base.join(".keychain-mirror-sync.json"),
        serde_json::to_vec(&json!({
            "updated_at_unix_ms": now,
            "synced": 0, "skipped": 0, "failed": 0, "lock_timed_out": 0,
            "lock_failed": 0, "deferred": 0, "malformed": 0, "pending": 0,
            "sessions": [], "sessions_undetermined": false
        }))
        .unwrap(),
    )
    .unwrap();
    let pid = std::process::id();
    let handle = base.join(format!("term-{pid}"));
    fs::create_dir(&handle).unwrap();
    fs::write(handle.join(".live-pid"), pid.to_string()).unwrap();
    for verb in ["status", "doctor"] {
        let report: Value = serde_json::from_slice(&fixture.run(verb, true)).unwrap();
        assert_eq!(report["sessions_undetermined"], true);
        let rows = report["session_logins"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["handle_pid"], pid);
        assert_eq!(rows[0]["evidence"]["state"], "undetermined");
        assert_eq!(rows[0]["evidence"]["reason"], "not_in_snapshot");
        assert!(rows[0].get("account").is_none());
        assert!(rows[0]["evidence"].get("remedy").is_none());
        assert!(report["keychain_mirror_age_secs"].is_number());
        let text = String::from_utf8(fixture.run(verb, false)).unwrap();
        assert!(text.contains("session login evidence is unknown"), "{text}");
        assert!(text.contains("sessions_undetermined=true"), "{text}");
    }
}
