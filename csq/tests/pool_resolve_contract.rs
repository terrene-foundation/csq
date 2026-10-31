//! Operator resolution is an explicit pool command with fixed diagnostics.
//! Admission failures below use no keys, native secret storage, or HTTP.

use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct ResolveFixture {
    sandbox: TempDir,
}

impl ResolveFixture {
    fn new() -> Self {
        let sandbox = TempDir::new().unwrap();
        for directory in ["home", "base", "bin", "tmp"] {
            std::fs::create_dir(sandbox.path().join(directory)).unwrap();
        }
        Self { sandbox }
    }

    fn resolve(&self, name: &str, json: bool) -> Output {
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
        if json {
            command.arg("--json");
        }
        command.args(["pool", "resolve", name]).output().unwrap()
    }
}

#[test]
fn pool_resolve_rejects_invalid_name_with_fixed_diagnostic_before_custody() {
    let fixture = ResolveFixture::new();
    for json in [false, true] {
        let output = fixture.resolve("synthetic/key-name", json);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("pool_invalid_name"),
            "resolve must reach validated operator admission, status={:?}, stdout={stdout:?}, stderr={stderr:?}",
            output.status.code(),
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout.is_empty());
        assert!(!stderr.contains("synthetic/key-name"));
        assert!(!stderr.contains("Usage:"));
        assert!(!stderr.contains(fixture.sandbox.path().to_str().unwrap()));
        assert!(!fixture
            .sandbox
            .path()
            .join("base/pool/execution-ledger.sqlite3")
            .exists());
    }
}

#[test]
fn pool_resolve_without_configuration_fails_closed_without_echoing_the_name() {
    let fixture = ResolveFixture::new();
    for json in [false, true] {
        let output = fixture.resolve("synthetic-pool-entry", json);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("pool_unavailable"),
            "absent configuration must fail closed, stdout={stdout:?}, stderr={stderr:?}",
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout.is_empty());
        assert!(!stderr.contains("synthetic-pool-entry"));
        assert!(!stderr.contains("Usage:"));
        assert!(!stderr.contains(fixture.sandbox.path().to_str().unwrap()));
        assert!(!fixture
            .sandbox
            .path()
            .join("base/pool/execution-ledger.sqlite3")
            .exists());
    }
}
