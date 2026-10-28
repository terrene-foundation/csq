//! Exercises actual doctor dispatch -> build_report -> source settings collector.
#![cfg(unix)]

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const UUID: &str = "11111111-1111-4111-8111-111111111111";
// Matches doctor.rs::warn(), which currently returns ANSI bytes unconditionally.
const WARN_MARKER: &str = "\u{001b}[33m⚠\u{001b}[0m";

fn put(base: &Path, location: &str, bytes: &[u8]) -> PathBuf {
    let path = base.join(location);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

fn doctor(home: &Path, base: &Path, json: bool) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_csq"));
    cmd.current_dir(home)
        .stdin(std::process::Stdio::null())
        .env_clear()
        .env("HOME", home)
        .env("CSQ_HOME", home)
        .env("CLAUDE_HOME", home.join(".claude"))
        .env("CLAUDE_CONFIG_DIR", base.join("config-1"))
        .env("CSQ_BASE_DIR", base)
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("TMPDIR", home.join("tmp"))
        .env("PATH", "/usr/bin:/bin")
        .env("USER", "fixture-user")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
        .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
        .arg("doctor");
    if json {
        cmd.arg("--json");
    }
    let output = cmd.output().expect("run Cargo-built csq binary");
    assert!(output.status.success(), "doctor process failed");
    output
}

#[test]
fn claude_autocompact_doctor_collects_real_source_settings_and_warns() {
    let home = TempDir::new().unwrap();
    let base = home.path().join(".claude/accounts");
    std::fs::create_dir_all(&base).unwrap();
    for name in ["runtime", "config", "tmp"] {
        std::fs::create_dir(home.path().join(name)).unwrap();
    }
    // Fresh cache suppresses update transport; no daemon, audit chain or credentials exist.
    put(&base, ".csq-update-check", b"");
    let cases = [
        ("config-1/settings.json".to_string(), br#"{"autoCompactWindow":"SOURCE_VALUE_CANARY_219"}"#.to_vec()),
        (format!("identities/{UUID}/settings.json"), br#"{"modelSettings":{"MODEL_CANARY_918":{"autoCompactWindow":7}},"env":{"CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":"83"}}"#.to_vec()),
        ("config-2/settings.json".to_string(), b"{malformed".to_vec()),
        ("term-123/settings.json".to_string(), br#"{"autoCompactWindow":"TERM_CANARY_711"}"#.to_vec()),
    ];
    let paths: Vec<_> = cases
        .iter()
        .map(|(location, bytes)| put(&base, location, bytes))
        .collect();
    let global = put(
        home.path(),
        ".claude/settings.json",
        br#"{"env":{"CLAUDE_AUTOCOMPACT_PCT_OVERRIDE":"71"}}"#,
    );
    let global_before = std::fs::read(&global).unwrap();
    let output = doctor(home.path(), &base, true);
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let status = &report["claude_autocompact_status"];
    assert_eq!(
        status["findings"],
        json!([
            {"location":"config-1/settings.json","root":true,"per_model":false,"pct_override":false,"provider_window":false},
            {"location":format!("identities/{UUID}/settings.json"),"root":false,"per_model":true,"pct_override":true,"provider_window":false}
        ])
    );
    assert_eq!(status["unreadable"], json!(["config-2/settings.json"]));
    let guidance = csq_core::session::settings_diagnostics::AUTO_COMPACT_GUIDANCE;
    assert_eq!(status["guidance"], guidance);
    let output_text = doctor(home.path(), &base, false);
    let text = String::from_utf8(output_text.stdout.clone()).unwrap();
    let rows: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("  Claude auto-compact:"))
        .collect();
    assert_eq!(rows, vec![
        format!("  Claude auto-compact: {WARN_MARKER} config-1/settings.json carries autoCompactWindow; {guidance}"),
        format!("  Claude auto-compact: {WARN_MARKER} identities/{UUID}/settings.json carries modelSettings.*.autoCompactWindow and env.CLAUDE_AUTOCOMPACT_PCT_OVERRIDE; {guidance}"),
        format!("  Claude auto-compact: {WARN_MARKER} config-2/settings.json unreadable; settings status unknown"),
    ]);
    for bytes in [
        &output.stdout,
        &output.stderr,
        &output_text.stdout,
        &output_text.stderr,
    ] {
        let rendered = String::from_utf8_lossy(bytes);
        for private in [
            "SOURCE_VALUE_CANARY_219",
            "MODEL_CANARY_918",
            "TERM_CANARY_711",
            home.path().to_str().unwrap(),
        ] {
            assert!(!rendered.contains(private), "private fixture data leaked");
        }
    }
    for ((_, before), path) in cases.iter().zip(paths) {
        assert_eq!(std::fs::read(path).unwrap(), *before);
    }
    assert_eq!(std::fs::read(global).unwrap(), global_before);
}
