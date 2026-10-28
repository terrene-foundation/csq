//! `sign-release` — Ed25519 signer for csq release binaries.
//!
//! Used in the GitHub Actions release workflow to sign each CLI
//! binary with the Foundation's release-signing private key. The
//! resulting `<binary>.sig` files are uploaded alongside the binaries
//! and verified by `csq update install` via
//! `csq_core::update::verify::verify_signature`.
//!
//! # Usage
//!
//! ```text
//! sign-release <input-file> [<input-file>...]
//! ```
//!
//! Set `CSQ_RELEASE_SIGNING_KEY` to the 64-character hex key (32 bytes).
//! For each input file the signer writes `<input>.sig` containing
//! the 64-byte raw Ed25519 signature.
//!
//! # Security
//!
//! - The key is accepted only through the environment, then removed before
//!   validation. Never pass it on argv, where process listings expose it.
//! - Linux disables process dumpability before reading the key, refusing to
//!   sign if that protection cannot be applied.
//! - Bare 64/66-character hex arguments, also with a `0x` prefix, are refused,
//!   including with a valid environment key. Prefix a hex-named input with `./`.
//! - Secret text and decoded seed buffers are zeroized on drop. Key errors
//!   use fixed messages and never echo the supplied value.
//! - On any failure the signer exits non-zero so the CI step fails
//!   loudly rather than producing unsigned artifacts.

use ed25519_dalek::{Signer, SigningKey};
use secrecy::{ExposeSecret, SecretString};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

const KEY_ENV: &str = "CSQ_RELEASE_SIGNING_KEY";

fn decode_signing_key(key_hex: &SecretString) -> Result<SigningKey, &'static str> {
    let key_hex = key_hex.expose_secret();
    if key_hex.len() != 64 {
        return Err("signing key must be 64 hex characters (32 bytes)");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(key_hex, seed.as_mut()).map_err(|_| "signing key must be hex-encoded")?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The signer is single-threaded: consume the environment before doing any
/// validation or file I/O. Even non-Unicode and malformed values are removed.
fn take_signing_key() -> Result<SigningKey, &'static str> {
    let raw = std::env::var_os(KEY_ENV);
    std::env::remove_var(KEY_ENV);
    let raw = raw.ok_or("CSQ_RELEASE_SIGNING_KEY is required")?;
    let bytes = Zeroizing::new(raw.into_encoded_bytes());
    let text = std::str::from_utf8(&bytes).map_err(|_| "signing key must be Unicode hex text")?;
    let key_hex = SecretString::from(text.to_owned());
    decode_signing_key(&key_hex)
}

fn validate_inputs(inputs: &[OsString]) -> Result<(), &'static str> {
    if inputs.is_empty() {
        return Err("at least one input file required; usage: sign-release <input> [<input>...]");
    }
    if inputs.iter().any(|input| {
        input.to_str().is_some_and(|value| {
            let value = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            matches!(value.len(), 64 | 66) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) {
        return Err("signing keys on argv are forbidden; use CSQ_RELEASE_SIGNING_KEY");
    }
    Ok(())
}

fn main() -> ExitCode {
    main_with_inputs(std::env::args_os().skip(1))
}

/// Shared production entry: apply process protection before reading any key.
/// The isolated child tests enter here too, never directly through `run`.
fn main_with_inputs(inputs: impl IntoIterator<Item = OsString>) -> ExitCode {
    if let Err(message) = secure_process() {
        eprintln!("error: {message}");
        return ExitCode::from(2);
    }
    run(inputs)
}

fn secure_process() -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl changes only this process's dumpability; the remaining
        // variadic arguments are unused for PR_SET_DUMPABLE and explicitly zero.
        if unsafe {
            libc::prctl(
                libc::PR_SET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        } != 0
        {
            return Err("could not disable signer process dumpability");
        }
    }
    Ok(())
}

fn run(inputs: impl IntoIterator<Item = OsString>) -> ExitCode {
    let signing_key = match take_signing_key() {
        Ok(key) => key,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let inputs: Vec<OsString> = inputs.into_iter().collect();
    if let Err(message) = validate_inputs(&inputs) {
        eprintln!("error: {message}");
        return ExitCode::from(2);
    }

    let mut had_error = false;
    for input in &inputs {
        let input = PathBuf::from(input);
        match std::fs::read(&input) {
            Ok(bytes) => {
                let signature = signing_key.sign(&bytes);
                let mut sig_path = input.as_os_str().to_os_string();
                sig_path.push(".sig");
                let sig_path = PathBuf::from(sig_path);
                if let Err(e) = std::fs::write(&sig_path, signature.to_bytes()) {
                    eprintln!("error: failed to write {}: {e}", sig_path.display());
                    had_error = true;
                } else {
                    eprintln!("signed: {} -> {}", input.display(), sig_path.display());
                }
            }
            Err(e) => {
                eprintln!("error: failed to read {}: {e}", input.display());
                had_error = true;
            }
        }
    }

    // Drop the signing key from memory before returning. Rust will
    // do this automatically when `signing_key` goes out of scope but
    // we make it explicit so a future refactor can't accidentally
    // hold a reference past this point.
    drop(signing_key);

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic synthetic seeds; never use Foundation release credentials.
    fn fixture_hex() -> String {
        hex::encode([7u8; 32])
    }

    #[test]
    fn sign_release_decodes_synthetic_key_and_rejects_invalid_material() {
        let key = decode_signing_key(&SecretString::from(fixture_hex())).unwrap();
        assert_eq!(
            key.verifying_key(),
            SigningKey::from_bytes(&[7u8; 32]).verifying_key()
        );
        for value in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "z".repeat(64),
        ] {
            assert!(decode_signing_key(&SecretString::from(value)).is_err());
        }
        assert!(decode_signing_key(&SecretString::from("AB".repeat(32))).is_ok());
    }

    #[test]
    fn sign_release_refuses_legacy_key_in_every_argument_position() {
        for key in [
            fixture_hex(),
            "AB".repeat(32),
            "ab".repeat(33),
            format!("0x{}", fixture_hex()),
            format!("0X{}", "AB".repeat(32)),
            format!("0x{}", "ab".repeat(33)),
        ] {
            for inputs in [
                vec![OsString::from(&key), "artifact".into()],
                vec!["first".into(), OsString::from(&key), "last".into()],
                vec!["artifact".into(), OsString::from(&key)],
                vec![OsString::from(&key)],
            ] {
                assert!(validate_inputs(&inputs).is_err());
            }
            assert!(validate_inputs(&[format!("./{key}").into()]).is_ok());
        }
        assert!(validate_inputs(&[]).is_err());
        assert!(validate_inputs(&["artifact one".into(), "artifact-two".into()]).is_ok());
        for input in ["a".repeat(63), "a".repeat(65), "z".repeat(66)] {
            assert!(validate_inputs(&[input.into()]).is_ok());
        }
    }

    // The library exposes the one shared env lock only under test-utils. Pure
    // decoding/argv regressions above remain in the default cargo test path.
    #[cfg(feature = "test-utils")]
    mod subprocess {
        use super::*;
        use ed25519_dalek::Signature;
        use std::ffi::OsStr;
        use std::process::{Command, Output};
        use tempfile::TempDir;

        const CHILD_ARGS: &str = "CSQ_SIGN_RELEASE_TEST_ARGS";

        fn invoke(dir: &TempDir, args: &[String], key: Option<&OsStr>) -> Output {
            invoke_child(
                dir,
                args,
                key,
                "tests::subprocess::sign_release_child_entry",
            )
        }

        fn invoke_child(
            dir: &TempDir,
            args: &[String],
            key: Option<&OsStr>,
            entry: &str,
        ) -> Output {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .env_clear()
                .current_dir(dir.path())
                .env("HOME", dir.path())
                .env("CSQ_BASE_DIR", dir.path().join("base"))
                .env("TMPDIR", dir.path())
                .env("TEMP", dir.path())
                .env("TMP", dir.path())
                .env("USERPROFILE", dir.path())
                .env("APPDATA", dir.path())
                .env("LOCALAPPDATA", dir.path())
                .env("LANG", "C")
                .env(CHILD_ARGS, serde_json::to_string(args).unwrap())
                .args([
                    "--exact",
                    entry,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ]);
            for name in ["SYSTEMROOT", "SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            if let Some(key) = key {
                command.env(KEY_ENV, key);
            }
            command
                .output()
                .expect("spawn isolated signer test process")
        }

        fn assert_redacted(output: &Output, values: &[&str]) {
            for value in values {
                assert!(!String::from_utf8_lossy(&output.stdout).contains(value));
                assert!(!String::from_utf8_lossy(&output.stderr).contains(value));
            }
        }

        fn assert_signature(dir: &TempDir, input: &str) {
            let bytes = std::fs::read(dir.path().join(input)).unwrap();
            let signature = std::fs::read(dir.path().join(format!("{input}.sig"))).unwrap();
            assert_eq!(signature.len(), 64);
            let signature = Signature::from_slice(&signature).unwrap();
            let public_key = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
            public_key.verify_strict(&bytes, &signature).unwrap();
            assert!(public_key
                .verify_strict(b"changed artifact", &signature)
                .is_err());
        }

        #[cfg(target_os = "linux")]
        fn dumpability() -> libc::c_int {
            // SAFETY: query this isolated child's own state; no pointers used.
            unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }
        }

        #[cfg(target_os = "linux")]
        fn start_dumpable_child() {
            // Start insecure so removing the production guard is detected,
            // even when the runner inherited dumpability zero.
            // SAFETY: callers are isolated child fixtures; only self is changed.
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1 as libc::c_ulong) },
                0
            );
            assert_eq!(dumpability(), 1);
        }

        #[cfg(target_os = "linux")]
        #[test]
        #[ignore = "subprocess fixture entry; invoke_child() runs it with --ignored"]
        fn sign_release_guard_failure_child_entry() {
            let _env_guard = csq_core::platform::test_env::lock();
            start_dumpable_child();
            // A child-local seccomp filter rejects only PR_SET_DUMPABLE. This
            // exercises a real kernel error without a production test override.
            let statement = |code, k| libc::sock_filter {
                code,
                jt: 0,
                jf: 0,
                k,
            };
            let mut filter = [
                statement((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 3,
                    k: libc::SYS_prctl as u32,
                },
                // seccomp_data.args[0] begins at byte 16. PR_SET_DUMPABLE
                // occupies the low word (the second word on big-endian Linux).
                statement(
                    (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    if cfg!(target_endian = "big") { 20 } else { 16 },
                ),
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::PR_SET_DUMPABLE as u32,
                },
                statement(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                ),
                statement(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ALLOW,
                ),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            // SAFETY: no-new-privileges applies only to this fixture child.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_SET_NO_NEW_PRIVS,
                        1 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                },
                0
            );
            // SAFETY: program points at initialized, live filter instructions;
            // the kernel copies them synchronously and confines this child.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                        &program as *const libc::sock_fprog,
                    )
                },
                0
            );
            assert_eq!(
                main_with_inputs([OsString::from("artifact")]),
                ExitCode::from(2)
            );
            assert_eq!(dumpability(), 1);
            // The guard failed before take_signing_key could consume the env.
            assert!(std::env::var_os(KEY_ENV).is_some());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn sign_release_subprocess_guard_failure_never_reads_key_or_signs() {
            let _env_guard = csq_core::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            std::fs::write(dir.path().join("artifact"), b"artifact").unwrap();
            let key = fixture_hex();
            let output = invoke_child(
                &dir,
                &["artifact".into()],
                Some(key.as_ref()),
                "tests::subprocess::sign_release_guard_failure_child_entry",
            );
            assert_eq!(output.status.code(), Some(0));
            assert!(!dir.path().join("artifact.sig").exists());
            assert_redacted(&output, &[&key]);
        }

        #[test]
        #[ignore = "subprocess fixture entry; invoke() runs it with --ignored and explicit test inputs"]
        fn sign_release_child_entry() {
            let _env_guard = csq_core::platform::test_env::lock();
            let inputs: Vec<String> =
                serde_json::from_str(&std::env::var(CHILD_ARGS).unwrap()).unwrap();
            #[cfg(target_os = "linux")]
            start_dumpable_child();
            let result = main_with_inputs(inputs.into_iter().map(OsString::from));
            #[cfg(target_os = "linux")]
            assert_eq!(dumpability(), 0);
            // Assert after every production return path, including malformed
            // and non-Unicode secrets, before returning the real exit code.
            assert!(std::env::var_os(KEY_ENV).is_none());
            std::process::exit(if result == ExitCode::SUCCESS {
                0
            } else if result == ExitCode::from(2) {
                2
            } else {
                1
            });
        }

        #[test]
        fn sign_release_subprocess_signs_multiple_files() {
            let _env_guard = csq_core::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            std::fs::write(dir.path().join("one"), b"first artifact").unwrap();
            std::fs::write(dir.path().join("two"), b"second artifact").unwrap();
            let key = fixture_hex();
            let output = invoke(&dir, &["one".into(), "two".into()], Some(key.as_ref()));
            assert_eq!(output.status.code(), Some(0));
            assert_signature(&dir, "one");
            assert_signature(&dir, "two");
            assert_redacted(&output, &[&key]);
        }

        #[test]
        fn sign_release_subprocess_legacy_argv_never_signs_even_with_env() {
            let _env_guard = csq_core::platform::test_env::lock();
            let env_key = fixture_hex();
            for argv_key in [
                hex::encode([8u8; 32]),
                "AB".repeat(33),
                format!("0x{}", hex::encode([8u8; 32])),
                format!("0X{}", "AB".repeat(32)),
            ] {
                for key in [None, Some(OsStr::new(&env_key))] {
                    for args in [
                        vec![argv_key.clone(), "artifact".into()],
                        vec!["artifact".into(), argv_key.clone(), "last".into()],
                        vec!["artifact".into(), argv_key.clone()],
                    ] {
                        let dir = TempDir::new().unwrap();
                        std::fs::write(dir.path().join("artifact"), b"artifact").unwrap();
                        // Even an existing hex-named file must be refused before
                        // any signature is written, regardless of arg position.
                        std::fs::write(dir.path().join(&argv_key), b"hex file").unwrap();
                        let output = invoke(&dir, &args, key);
                        assert_eq!(output.status.code(), Some(2));
                        assert!(!dir.path().join("artifact.sig").exists());
                        assert!(!dir.path().join(format!("{argv_key}.sig")).exists());
                        assert_redacted(&output, &[&env_key, &argv_key]);
                    }
                }
            }
        }

        #[test]
        fn sign_release_subprocess_invalid_and_missing_keys_fail_closed() {
            let _env_guard = csq_core::platform::test_env::lock();
            let invalid = [
                String::new(),
                "a".repeat(63),
                "a".repeat(65),
                "z".repeat(64),
            ];
            for key in std::iter::once(None).chain(invalid.iter().map(|key| Some(OsStr::new(key))))
            {
                let dir = TempDir::new().unwrap();
                std::fs::write(dir.path().join("artifact"), b"artifact").unwrap();
                let output = invoke(&dir, &["artifact".into()], key);
                assert_eq!(output.status.code(), Some(2));
                assert!(!dir.path().join("artifact.sig").exists());
                if let Some(key) = key.filter(|key| !key.is_empty()) {
                    assert_redacted(&output, &[key.to_str().unwrap()]);
                }
            }
        }

        #[cfg(unix)]
        #[test]
        fn sign_release_subprocess_non_unicode_key_is_removed_and_redacted() {
            use std::os::unix::ffi::OsStringExt;
            let _env_guard = csq_core::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            std::fs::write(dir.path().join("artifact"), b"artifact").unwrap();
            let key = OsString::from_vec(vec![0xff; 64]);
            let output = invoke(&dir, &["artifact".into()], Some(&key));
            assert_eq!(output.status.code(), Some(2));
            assert!(!dir.path().join("artifact.sig").exists());
            assert!(output.stderr.is_ascii());
        }

        #[test]
        fn sign_release_subprocess_no_inputs_consumes_key() {
            let _env_guard = csq_core::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            let key = fixture_hex();
            let output = invoke(&dir, &[], Some(key.as_ref()));
            assert_eq!(output.status.code(), Some(2));
            assert_redacted(&output, &[&key]);
        }

        #[test]
        fn sign_release_subprocess_io_errors_continue_other_inputs_and_fail() {
            let _env_guard = csq_core::platform::test_env::lock();
            for failed_input in ["missing", "unwritable"] {
                let dir = TempDir::new().unwrap();
                std::fs::write(dir.path().join("good"), b"good artifact").unwrap();
                if failed_input == "unwritable" {
                    std::fs::write(dir.path().join("unwritable"), b"artifact").unwrap();
                    std::fs::create_dir(dir.path().join("unwritable.sig")).unwrap();
                }
                let key = fixture_hex();
                let output = invoke(
                    &dir,
                    &[failed_input.into(), "good".into()],
                    Some(key.as_ref()),
                );
                assert_eq!(output.status.code(), Some(1));
                assert_signature(&dir, "good");
                assert_redacted(&output, &[&key]);
            }
        }
    }
}
