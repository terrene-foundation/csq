//! Binary smoke for gate status and doctor's shared read-only diagnosis.
//! Unix private-pin support only; no credential, model, hook or provider execution.
#![cfg(unix)]

use csq_core::gate::pin::{Pin, MANIFEST_FILE};
use csq_core::gate::registry::Registry;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const MANIFEST: &str = r###"{"$id":"loom.hook-registry/v1","content_sha256":"48faf11bcc8eabb2d0730407f490f47ffcfef152717c49e35e7169172fe1c3e7","content_sha256_scheme":"RFC 8785 JCS","default_on_incomplete":{"PostToolUse":"continue","PreCompact":"continue","PreToolUse":"deny","SessionEnd":"continue","SessionStart":"continue","Stop":"continue","SubagentStop":"continue","UserPromptSubmit":"continue"},"generated_by":"authoring/.claude/bin/emit-hook-registry.mjs","hooks":[{"contract":{"cwd_scope":"payload","form":"legacy","idempotent":true,"may_rewrite_input":false,"payload_stdin":{"claude":"cc-hook-json"},"protocol":{"decision_fields":["hookSpecificOutput","permissionDecision"],"exit_codes":[0,2],"exit_codes_computed":false,"kind":"permission-decision","severity":"block"},"runtime":"node-subprocess","side_effects":{"declared_by":"author","fs_writes":[],"network":false,"spawns":[]}},"deps":[{"path":".claude/hooks/lib/row.js","sha256":"fb8c975e0505c9148882a4003aadfaa718dc245e8672ed07007d3794367084e2"}],"event":"PreToolUse","file":".claude/hooks/guard.js","file_sha256":"25502fd7704ffe419329cf9c6b1456b3dd8da425fbbc12e6bfd9a621c2e4c5d4","id":"hk_4477efbdd42a2304","matcher":"Bash","on_crash":"deny","on_incomplete":"deny","on_timeout":"deny","order":10,"pool":"repo","source":"repo-local","surfaces":["claude"],"timeout":30}],"precedence":"deny > conflicting-rewrite refusal > single rewrite; advise never downgrades a deny","runtimes":[{"deps":[{"path":".claude/hooks/lib/runtime.js","sha256":"7040e14d6cf9a9d923a4f36eea6a79fe4fbd18748b02a2f03aae842f42736a8c"}],"entry":".claude/hooks/runtime.js","entry_sha256":"082acffad8fd484430d169b858a6250758a22fcfd50057d759855a444753f347"}],"source_sha":"ffffffffffffffffffffffffffffffffffffffff","unknown_major_policy":"fail-closed","version":"1.0.0"}"###;
const SOURCE: &[u8] = b"fixture hook bytes; never executed";

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    base: PathBuf,
    repo: PathBuf,
    pin: PathBuf,
    settings: Vec<(PathBuf, Vec<u8>)>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("private-home-canary");
        let base = home.join(".claude/accounts");
        let repo = temp.path().join("private-repo-canary");
        let handle = temp.path().join("private-handle-canary");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(repo.join(".claude/hooks/lib")).unwrap();
        fs::create_dir(&handle).unwrap();
        // Independent fixed manifest vector is validated through production parsing.
        Registry::parse(MANIFEST.as_bytes()).unwrap();
        fs::write(repo.join(MANIFEST_FILE), MANIFEST).unwrap();
        fs::write(repo.join(".claude/hooks/guard.js"), SOURCE).unwrap();
        fs::write(
            repo.join(".claude/hooks/runtime.js"),
            b"trusted runtime fixture",
        )
        .unwrap();
        fs::write(repo.join(".claude/hooks/lib/row.js"), b"row dependency").unwrap();
        fs::write(
            repo.join(".claude/hooks/lib/runtime.js"),
            b"runtime dependency",
        )
        .unwrap();
        let pin = handle.join("pin.json");
        Pin::capture_operator(&repo)
            .unwrap()
            .write_private(&pin)
            .unwrap();
        let settings = [
            home.join(".claude/settings.json"),
            repo.join(".claude/settings.json"),
            repo.join(".claude/settings.local.json"),
        ]
        .into_iter()
        .map(|path| {
            let bytes = br#"{"permissions":{"deny":["Bash(touch sentinel)"]}}"#.to_vec();
            fs::write(&path, &bytes).unwrap();
            (path, bytes)
        })
        .collect();
        Self {
            _temp: temp,
            home,
            base,
            repo,
            pin,
            settings,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_csq"));
        cmd.env_clear()
            .env("HOME", &self.home)
            .env("CSQ_HOME", &self.home)
            .env("CLAUDE_HOME", &self.home)
            .env("CSQ_BASE_DIR", &self.base)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("TERM", "dumb")
            .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
            .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
            .current_dir(&self.repo);
        cmd
    }

    fn run(&self, doctor: bool, json: bool) -> Output {
        let before_pin = fs::read(&self.pin).ok();
        let before_manifest = fs::read(self.repo.join(MANIFEST_FILE)).unwrap();
        let before_hook = fs::read(self.repo.join(".claude/hooks/guard.js")).unwrap();
        let mut cmd = self.command();
        if json {
            cmd.arg("--json");
        }
        if doctor {
            cmd.args(["doctor", "--gate-repo"])
                .arg(&self.repo)
                .arg("--gate-pin")
                .arg(&self.pin);
        } else {
            cmd.args(["gate", "status", "--repo"])
                .arg(&self.repo)
                .arg("--pin")
                .arg(&self.pin);
        }
        let output = cmd.output().unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("private-home-canary"), "{text}");
            assert!(!text.contains("private-repo-canary"), "{text}");
            assert!(!text.contains("private-handle-canary"), "{text}");
            assert!(
                !text.contains(self._temp.path().to_str().unwrap()),
                "{text}"
            );
        }
        assert_eq!(fs::read(&self.pin).ok(), before_pin);
        assert_eq!(
            fs::read(self.repo.join(MANIFEST_FILE)).unwrap(),
            before_manifest
        );
        assert_eq!(
            fs::read(self.repo.join(".claude/hooks/guard.js")).unwrap(),
            before_hook
        );
        for (path, bytes) in &self.settings {
            assert_eq!(fs::read(path).unwrap(), *bytes);
        }
        assert!(!self.base.join(".csq-update-check").exists());
        output
    }

    fn mutate_pin(&self, field: &str, value: Value) {
        let mut pin: Value = serde_json::from_slice(&fs::read(&self.pin).unwrap()).unwrap();
        pin[field] = value;
        fs::write(&self.pin, serde_json::to_vec(&pin).unwrap()).unwrap();
    }
}

fn check_pair(f: &Fixture, health: &str, code: i32) {
    let gate = f.run(false, true);
    assert_eq!(
        gate.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&gate.stderr)
    );
    let report: Value = serde_json::from_slice(&gate.stdout).unwrap();
    assert_eq!(report["health"], health);
    assert_eq!(report["activation"], "unknown");
    let doctor = f.run(true, true);
    assert_eq!(
        doctor.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    // Parsing the full stdout discriminates a single doctor object from double output.
    let doctor_report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    // Pin the current Doctor contract (spec 13 §9: v33 Codex hook-trust carry diagnostics + v34 keychain_orphans).
    assert_eq!(doctor_report["schema_version"], 34);
    assert_eq!(doctor_report["gate_status"], report);
    for is_doctor in [false, true] {
        let text = f.run(is_doctor, false);
        assert_eq!(text.status.code(), Some(code));
        let stdout = String::from_utf8(text.stdout).unwrap();
        assert!(stdout.contains("Activation: UNKNOWN"));
        assert!(stdout.contains(if code == 0 {
            "Gate integrity: Green"
        } else {
            "Gate integrity: Red"
        }));
    }
}

#[test]
fn admitted_pin_is_green_but_does_not_assert_activation_or_mutate_settings() {
    check_pair(&Fixture::new(), "green", 0);
}

#[test]
fn pin_manifest_content_source_and_subject_tampering_is_red_on_both_surfaces() {
    for (field, value) in [
        ("manifest_sha256", Value::from("0".repeat(64))),
        ("content_sha256", Value::from("0".repeat(64))),
        ("source_sha", Value::from("0".repeat(40))),
        ("version", Value::from("1.9.0")),
    ] {
        let f = Fixture::new();
        f.mutate_pin(field, value);
        assert!(Pin::read_private(&f.pin).is_ok());
        check_pair(&f, "red", 1);
    }
    let f = Fixture::new();
    let other = f._temp.path().join("other-repo");
    fs::create_dir(&other).unwrap();
    f.mutate_pin("repo", other.to_str().unwrap().into());
    assert!(Pin::read_private(&f.pin).is_ok());
    check_pair(&f, "red", 1);

    let f = Fixture::new();
    let value: Value = serde_json::from_slice(&fs::read(&f.pin).unwrap()).unwrap();
    let mut policies = value["event_policies"].clone();
    policies["PreToolUse"] = "continue".into();
    f.mutate_pin("event_policies", policies);
    assert!(Pin::read_private(&f.pin).is_ok());
    check_pair(&f, "red", 1);
}

#[test]
fn changed_manifest_and_changed_hook_each_report_red_without_repair() {
    let f = Fixture::new();
    fs::write(f.repo.join(MANIFEST_FILE), format!("{MANIFEST}\n")).unwrap();
    check_pair(&f, "red", 1);
    let f = Fixture::new();
    fs::write(f.repo.join(".claude/hooks/guard.js"), b"tampered bytes").unwrap();
    check_pair(&f, "red", 1);
}

#[test]
fn runtime_and_row_dependencies_report_red_on_both_surfaces() {
    for path in [
        ".claude/hooks/runtime.js",
        ".claude/hooks/lib/runtime.js",
        ".claude/hooks/lib/row.js",
    ] {
        let f = Fixture::new();
        fs::write(f.repo.join(path), b"tampered closure bytes").unwrap();
        check_pair(&f, "red", 1);
    }
}

#[test]
fn missing_and_malformed_pins_report_red_without_creation() {
    let f = Fixture::new();
    fs::remove_file(&f.pin).unwrap();
    check_pair(&f, "red", 1);
    assert!(!f.pin.exists());
    let f = Fixture::new();
    fs::write(&f.pin, b"malformed").unwrap();
    check_pair(&f, "red", 1);
}

#[test]
fn doctor_omits_gate_status_without_explicit_pair_and_rejects_incompatible_modes() {
    let f = Fixture::new();
    let output = f.command().args(["doctor", "--json"]).output().unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.get("gate_status").is_none());
    for mode in ["--slot", "--repair-identities", "--check-token-owners"] {
        let mut cmd = f.command();
        cmd.args(["doctor", "--gate-repo"])
            .arg(&f.repo)
            .arg("--gate-pin")
            .arg(&f.pin)
            .arg(mode);
        if mode == "--slot" {
            cmd.arg("1");
        }
        assert!(!cmd.output().unwrap().status.success());
    }
    for one_flag in ["--gate-repo", "--gate-pin"] {
        assert!(!f
            .command()
            .args(["doctor", one_flag])
            .arg(&f.repo)
            .output()
            .unwrap()
            .status
            .success());
    }
}
