//! Explicit pool clock recovery reaches the ledger adapter without credentials.
//! Each command has a clean environment and no pool or native-secret fixture.

use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct ClockFixture {
    sandbox: TempDir,
}

impl ClockFixture {
    fn new() -> Self {
        let sandbox = TempDir::new().unwrap();
        for directory in ["home", "base", "bin", "tmp"] {
            std::fs::create_dir(sandbox.path().join(directory)).unwrap();
        }
        Self { sandbox }
    }

    fn run(&self, args: &[&str]) -> Output {
        let root = self.sandbox.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_csq"));
        command
            .env_clear()
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("APPDATA", root.join("home"))
            .env("LOCALAPPDATA", root.join("home"))
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("PATH", root.join("bin"))
            .env("TMPDIR", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TERM", "dumb")
            .env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1")
            .env("CSQ_CLI_DEPS_PROBE_DISABLE", "1")
            .current_dir(root)
            .stdin(Stdio::null());
        for name in [
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.args(args).output().unwrap()
    }
}

#[test]
fn pool_rebaseline_clock_without_configuration_reaches_core_failure_without_secret_access() {
    let fixture = ClockFixture::new();
    for json in [false, true] {
        let args: &[&str] = if json {
            &["--json", "pool", "rebaseline-clock"]
        } else {
            &["pool", "rebaseline-clock"]
        };
        let output = fixture.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // An unknown command fails this assertion. A routing no-op also fails:
        // it would emit success instead of the core's absent-config refusal.
        assert!(
            stderr.contains("pool_unavailable"),
            "clock recovery must reach the core refusal, status={:?}, stdout={stdout:?}, stderr={stderr:?}",
            output.status.code(),
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout.is_empty());
        assert!(!stderr.contains("Usage:"));
        assert!(!stderr.contains(root_path(&fixture)));
        assert!(!fixture
            .sandbox
            .path()
            .join("base/pool/execution-ledger.sqlite3")
            .exists());
    }
}

fn root_path(fixture: &ClockFixture) -> &str {
    fixture.sandbox.path().to_str().unwrap()
}

#[test]
fn pool_rebaseline_clock_is_discoverable_with_conservative_recovery_help() {
    let fixture = ClockFixture::new();
    let output = fixture.run(&["pool", "--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("rebaseline-clock"));

    let output = fixture.run(&["pool", "rebaseline-clock", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("without refunding"), "{help}");
}
