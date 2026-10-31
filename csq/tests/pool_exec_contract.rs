//! Pool execution must preserve the public `csq.exec.v1` failure contract.
//!
//! These admission failures need no pool, credentials, native keychain, provider
//! CLI, or network. The child receives only an explicit sandbox environment.

use std::process::{Command, Stdio};

use serde_json::Value;
use tempfile::TempDir;

#[test]
fn unknown_pool_provider_returns_one_exec_failure_envelope() {
    // Arrange: every filesystem path belongs to this test, and no provider
    // executable is available through PATH. No process-global env is mutated.
    let sandbox = TempDir::new().expect("create pool exec sandbox");
    let root = sandbox.path();
    for directory in ["home", "base", "bin", "tmp"] {
        std::fs::create_dir(root.join(directory)).expect("create sandbox directory");
    }
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
    // Preserve only Windows loader essentials, never user or credential state.
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

    // Act: use the already-supported global --json position. The unsupported
    // provider must be rejected before consulting any account or pool custody.
    let output = command
        .args([
            "--json",
            "exec",
            "--pool",
            "unsupported-pool-provider",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "--timeout",
            "1",
            "--id",
            "pool-contract-request",
            "synthetic prompt",
        ])
        .output()
        .expect("launch built csq binary");

    // Assert: parsing flags is part of the API. A clap unknown-flag error has
    // empty stdout and must fail here, rather than count as an admission error.
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 exec stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected one exec envelope, status={:?}, stdout={stdout:?}, stderr={stderr:?}",
        output.status.code()
    );
    assert!(stdout.ends_with('\n'), "envelope must end with a newline");
    let envelope: Value = serde_json::from_str(lines[0]).expect("JSON exec envelope");
    assert_eq!(envelope["schema"], "csq.exec.v1");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["id"], "pool-contract-request");
    assert_eq!(envelope["error"]["code"], "provider_not_found");
    assert!(envelope["error"]["message"].is_string());
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !stderr.contains("Usage:") && !stderr.contains("unexpected argument"),
        "semantic rejection must not be a clap usage error: {stderr}"
    );
}

fn pool_admission_failure(args: &[&str], input: Option<&[u8]>) -> Value {
    use std::io::Write;

    let sandbox = TempDir::new().expect("create admission sandbox");
    let root = sandbox.path();
    for directory in ["home", "base", "bin", "tmp"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
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
        .args(["--json", "exec", "--id", "pool-admission-request"])
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let mut child = command.spawn().expect("launch built csq binary");
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "args={args:?}, stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(stdout.ends_with('\n'));
    let envelope: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(envelope["schema"], "csq.exec.v1");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["id"], "pool-admission-request");
    assert_eq!(output.status.code(), Some(1));
    assert!(!stderr.contains("Usage:") && !stderr.contains("unexpected argument"));
    for text in [stdout.as_str(), stderr.as_ref()] {
        assert!(
            !text.contains(root.to_str().unwrap()),
            "sandbox path leaked: {text}"
        );
        assert!(
            !text.contains("synthetic secret prompt"),
            "prompt leaked: {text}"
        );
    }
    envelope
}

#[test]
fn pool_requires_an_explicit_positive_completion_bound() {
    for extra in [vec![], vec!["--max-tokens", "0"]] {
        let mut args = vec![
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "synthetic secret prompt",
        ];
        args.extend(extra);
        let envelope = pool_admission_failure(&args, None);
        assert_eq!(envelope["error"]["code"], "invalid_input");
    }
}

#[test]
fn pool_rejects_legacy_slot_and_provider_selectors_in_envelopes() {
    for selector in [["--slot", "1"], ["--provider", "claude"]] {
        let mut args = vec![
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "synthetic secret prompt",
        ];
        args.extend(selector);
        assert_eq!(
            pool_admission_failure(&args, None)["error"]["code"],
            "invalid_input"
        );
    }
}

#[test]
fn pool_only_limits_are_rejected_without_pool_mode() {
    for limit in [["--max-tokens", "1"], ["--max-input-bytes", "10"]] {
        let mut args = vec!["--provider", "claude", "synthetic secret prompt"];
        args.extend(limit);
        assert_eq!(
            pool_admission_failure(&args, None)["error"]["code"],
            "invalid_input"
        );
    }
}

#[test]
fn pool_rejects_combined_utf8_system_and_prompt_bytes_before_custody() {
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "--max-input-bytes",
            "5",
            "--system",
            "é",
            "éé",
        ],
        None,
    );
    assert_eq!(envelope["error"]["code"], "invalid_input");
}

#[test]
fn pool_rejects_oversized_stdin_before_custody() {
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "--max-input-bytes",
            "5",
            "--system",
            "ab",
            "--stdin",
        ],
        Some(b"cdef"),
    );
    assert_eq!(envelope["error"]["code"], "invalid_input");
}

#[test]
fn pool_requires_positive_deadline_and_byte_limit() {
    for limit in [["--timeout", "0"], ["--max-input-bytes", "0"]] {
        let mut args = vec![
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "synthetic secret prompt",
        ];
        args.extend(limit);
        assert_eq!(
            pool_admission_failure(&args, None)["error"]["code"],
            "invalid_input"
        );
    }
}

#[test]
fn pool_requires_an_explicit_model() {
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "anthropic",
            "--max-tokens",
            "1",
            "synthetic secret prompt",
        ],
        None,
    );
    assert_eq!(envelope["error"]["code"], "invalid_input");
}

#[test]
fn unknown_pool_provider_is_rejected_before_model_validation() {
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "unsupported-pool-provider",
            "synthetic secret prompt",
        ],
        None,
    );
    assert_eq!(envelope["error"]["code"], "provider_not_found");
}

#[test]
fn pool_default_byte_limit_is_enforced_before_custody() {
    // The prompt alone fits the default budget; the one-byte system makes the
    // combined input exceed it. Stdin keeps the payload out of Windows argv.
    let prompt = vec![b'x'; 200_000];
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "--system",
            "y",
            "--stdin",
        ],
        Some(&prompt),
    );
    assert_eq!(envelope["error"]["code"], "invalid_input");
    assert_eq!(
        envelope["error"]["message"],
        "combined system and prompt UTF-8 bytes exceed --max-input-bytes"
    );
}

#[cfg(unix)]
#[test]
fn pool_default_byte_limit_is_enforced_before_custody_from_argv() {
    // Keep each argv entry below Linux's per-argument limit while exceeding the
    // combined default limit, so the API guard is the cause of rejection.
    let prompt = "x".repeat(100_000);
    let system = "y".repeat(100_001);
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "anthropic",
            "--model",
            "synthetic-model",
            "--max-tokens",
            "1",
            "--system",
            &system,
            &prompt,
        ],
        None,
    );
    assert_eq!(envelope["error"]["code"], "invalid_input");
    assert_eq!(
        envelope["error"]["message"],
        "combined system and prompt UTF-8 bytes exceed --max-input-bytes"
    );
}

#[test]
fn anthropic_pool_without_configuration_is_unavailable_not_a_missing_slot() {
    // Exact ID from the bundled Claude model manifest; no credentials are staged.
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "anthropic",
            "--model",
            "claude-haiku-4-5-20251001",
            "--max-tokens",
            "1",
            "synthetic secret prompt",
        ],
        None,
    );
    assert_eq!(envelope["error"]["code"], "pool_unavailable");
    assert_eq!(envelope["error"]["message"], "no_pool_configured");
}

#[test]
fn openai_pool_rejects_a_claude_model_without_resolving_a_slot() {
    let envelope = pool_admission_failure(
        &[
            "--pool",
            "openai",
            "--model",
            "claude-haiku-4-5-20251001",
            "--max-tokens",
            "1",
            "synthetic secret prompt",
        ],
        None,
    );
    assert_eq!(envelope["error"]["code"], "unsupported");
}
