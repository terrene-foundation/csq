//! Built-binary startup boundary: no operator HOME, keys, daemon, or accounts.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Server {
    child: Child,
    dir: TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    fn start(args: &[&str], env: &[(&str, &str)]) -> Self {
        let dir = TempDir::new().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_csq-ledger"));
        cmd.env_clear();
        for key in [
            "PATH",
            "LANG",
            "LC_ALL",
            "TERM",
            "USER",
            "TMPDIR",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        cmd.env("HOME", dir.path())
            .env("CSQ_BASE_DIR", dir.path().join("csq-base"))
            .env("NO_COLOR", "1")
            .envs(env.iter().copied())
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .args(["--port", "0", "--authority-port", "0"])
            .args(args)
            .stdout(Stdio::from(
                File::create(dir.path().join("stdout")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(dir.path().join("stderr")).unwrap(),
            ));
        let child = cmd.spawn().unwrap();
        Self { child, dir }
    }
    fn output(&self) -> String {
        format!(
            "{}{}",
            fs::read_to_string(self.dir.path().join("stdout")).unwrap(),
            fs::read_to_string(self.dir.path().join("stderr")).unwrap()
        )
    }
    fn assert_refused(&mut self, code: i32, detail: &str) {
        self.assert_exit(code, detail);
        assert!(
            !self.dir.path().join("data").exists(),
            "refusal must precede storage/key creation"
        );
    }
    fn assert_exit(&mut self, code: i32, detail: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(code), "{}", self.output());
                assert!(self.output().contains(detail), "{}", self.output());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "server accepted forbidden config: {}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn assert_serving(&mut self, expected_ip: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let output = loop {
            let output = self.output();
            assert!(self.child.try_wait().unwrap().is_none(), "{output}");
            if output.contains("csq-ledger authority listener") {
                break output;
            }
            assert!(
                Instant::now() < deadline,
                "listeners never became ready: {output}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let line = output
            .lines()
            .find(|line| line.contains("csq-ledger read/write listener"))
            .unwrap();
        let addr: SocketAddr = line
            .split("addr=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(addr.ip().to_string(), expected_ip);
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
}

#[test]
fn startup_refuses_non_loopback_read_bind_before_side_effects() {
    for ip in [
        "0.0.0.0",
        "10.0.0.5",
        "192.168.1.2",
        "8.8.8.8",
        "::",
        "fc00::1",
        "::ffff:127.0.0.1",
    ] {
        Server::start(&["--bind", ip], &[]).assert_refused(78, "--bind");
    }
}

#[test]
fn startup_refuses_non_loopback_authority_bind_before_side_effects() {
    for ip in [
        "0.0.0.0",
        "10.0.0.5",
        "8.8.8.8",
        "::",
        "fc00::1",
        "::ffff:127.0.0.1",
    ] {
        Server::start(&["--authority-bind", ip], &[]).assert_refused(78, "--authority-bind");
    }
}

#[test]
fn startup_rejects_hostnames_and_invalid_ip_even_with_acknowledgement() {
    for flag in ["--bind", "--authority-bind"] {
        for ip in [
            "localhost",
            "example.invalid",
            "127.0.0.1:8080",
            "[::1]",
            "127.1",
            "",
        ] {
            Server::start(&[flag, ip, "--allow-public-bind"], &[])
                .assert_refused(2, "invalid value");
        }
    }
}

#[test]
fn startup_default_loopback_serves_health() {
    Server::start(&[], &[]).assert_serving("127.0.0.1");
}

#[test]
fn startup_ipv6_loopback_serves_health() {
    Server::start(&["--bind", "::1", "--authority-bind", "::1"], &[]).assert_serving("::1");
}

#[test]
fn startup_explicit_acknowledgement_allows_loopback() {
    Server::start(&["--allow-public-bind"], &[]).assert_serving("127.0.0.1");
}

#[test]
fn startup_environment_cannot_bypass_either_bind_guard() {
    for env in ["CSQ_LEDGER_BIND", "CSQ_LEDGER_AUTHORITY_BIND"] {
        Server::start(&[], &[(env, "0.0.0.0")]).assert_refused(78, "--allow-public-bind");
        Server::start(
            &[],
            &[(env, "0.0.0.0"), ("CSQ_LEDGER_ALLOW_PUBLIC_BIND", "false")],
        )
        .assert_refused(78, "--allow-public-bind");
    }
}

#[test]
fn startup_environment_acknowledgement_allows_loopback() {
    Server::start(&[], &[("CSQ_LEDGER_ALLOW_PUBLIC_BIND", "true")]).assert_serving("127.0.0.1");
}

#[test]
fn startup_bind_validation_precedes_signing_key_configuration() {
    for flag in ["--bind", "--authority-bind"] {
        // Empty explicit key path deterministically fails key loading if the
        // startup guard is bypassed, before either socket can be opened. This
        // is also the safe mutation target: never expose a wildcard test server.
        Server::start(&[flag, "0.0.0.0"], &[("CSQ_LEDGER_SIGNING_KEY_PATH", "")])
            .assert_refused(78, flag);
    }
}

#[test]
fn startup_acknowledged_non_loopback_reaches_key_configuration_without_listening() {
    for flag in ["--bind", "--authority-bind"] {
        // Prove the real CLI and env acknowledgement wiring with public binds,
        // but deliberately fail key loading before ANY socket can be bound.
        Server::start(
            &[flag, "0.0.0.0", "--allow-public-bind"],
            &[("CSQ_LEDGER_SIGNING_KEY_PATH", "")],
        )
        .assert_exit(74, "read operator-provisioned key");
        Server::start(
            &[flag, "0.0.0.0"],
            &[
                ("CSQ_LEDGER_SIGNING_KEY_PATH", ""),
                ("CSQ_LEDGER_ALLOW_PUBLIC_BIND", "true"),
            ],
        )
        .assert_exit(74, "read operator-provisioned key");
    }
}
