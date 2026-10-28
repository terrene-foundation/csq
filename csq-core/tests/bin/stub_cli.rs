//! Configurable test-fixture stub binary for cli_deps integration tests.
//!
//! Usage:
//!
//! ```text
//!   stub-cli --stdout <str> --exit-code <N> --hang-ms <N> --emit-bytes <N>
//!             --capture-argv <path>
//! ```
//!
//! All flags are optional and can be combined.
//!
//! ## Flags
//!
//! `--stdout <str>`        Print `str` to stdout (no trailing newline added unless `str` ends in `\n`).
//! `--stderr <str>`        Print `str` to stderr.
//! `--exit-code <N>`       Exit with code N (default 0).
//! `--hang-ms <N>`         Sleep for N milliseconds BEFORE doing anything else.
//! `--hang-after-ms <N>`   Sleep for N milliseconds AFTER writing stdout, while
//!                         holding the stdout pipe open. Use to model a CLI that
//!                         emits a partial line and then hangs: the reader must be
//!                         able to short-circuit on the byte cap without waiting.
//! `--emit-bytes <N>`      Write N bytes of `x` to stdout WITHOUT a trailing newline
//!                         (use for the 8 KiB cap test).
//! `--capture-argv <path>` Write all received argv (one per line, JSON-array format) to
//!                         the given file before any other action. Used by M4 install
//!                         integration tests to assert exact argv was passed to npm/brew.
//!
//! Stdout and emit-bytes are mutually exclusive in the test cases we write,
//! but both can be specified (stdout prints first, then emit-bytes).
//!
//! ## Design constraints
//!
//! - Uses existing libc/rusqlite dependencies for the private Unix R9 fixture; no new dependencies.
//! - Minimal: this stub is a test fixture, not a production tool.
//! - `test = false` / `doctest = false` so it is not run as a test binary.

use std::io::Write;
use std::time::Duration;

#[cfg(unix)]
fn run_r9_native_fixture() -> bool {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let executable = std::path::Path::new(&args[0]);
    if executable.file_name().and_then(|name| name.to_str()) != Some("r9-sqlite-fixture") {
        return false;
    }
    use std::os::unix::fs::MetadataExt;
    let base = executable
        .parent()
        .expect("private fixture parent")
        .canonicalize()
        .unwrap();
    let temporary_root = std::path::Path::new("/tmp").canonicalize().unwrap();
    assert_eq!(base.parent(), Some(temporary_root.as_path()));
    let name = base.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("cr-") || name.starts_with("cp-"));
    let metadata = std::fs::metadata(&base).unwrap();
    assert!(metadata.is_dir() && metadata.mode() & 0o077 == 0);
    // SAFETY: read the fixture child's own effective UID; no state is changed.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    let mode_metadata = std::fs::symlink_metadata(base.join("fixture-mode")).unwrap();
    assert!(mode_metadata.is_file() && mode_metadata.len() <= 16);
    let mode = std::fs::read_to_string(base.join("fixture-mode")).expect("private fixture mode");
    if mode.trim() == "hung-late-start" {
        // A child killed BEFORE its first scheduling (the CI race made
        // deterministic): the deadline fires while this sleeps, so the pid
        // file below can never exist. A reader must source the pid from the
        // runner's own spawn record, never from a file the child writes.
        std::thread::sleep(Duration::from_secs(2));
    }
    std::fs::write(base.join("owned-pid"), std::process::id().to_string()).unwrap();
    match mode.as_str() {
        "hung" | "hung-late-start" => std::thread::sleep(Duration::from_secs(10)),
        "forked" => {
            // A shell that forks a descendant holding its stdout/stderr, then
            // exits at once: the descendant's pid is recorded so the test can
            // prove the runner killed the whole process group.
            let descendant = std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .expect("fixture descendant");
            std::fs::write(base.join("descendant-pid"), descendant.id().to_string()).unwrap();
            std::process::exit(0);
        }
        "stdout" | "stderr" => {
            let mut output: Box<dyn Write> = if mode == "stdout" {
                Box::new(std::io::stdout().lock())
            } else {
                Box::new(std::io::stderr().lock())
            };
            let block = [0u8; 65536];
            while output.write_all(&block).is_ok() {}
        }
        "delayed" => {
            // A slow host, made deterministic: sleep the recorded milliseconds,
            // then become the real sqlite3 with the runner's own argv. The spec
            // is `<ms>\n<absolute sqlite3 path>` in `fixture-exec`.
            use std::os::unix::process::CommandExt;
            let exec_metadata =
                std::fs::symlink_metadata(base.join("fixture-exec")).expect("fixture-exec");
            assert!(exec_metadata.is_file() && exec_metadata.len() <= 4096);
            let spec = std::fs::read_to_string(base.join("fixture-exec")).expect("fixture-exec");
            let (millis, real) = spec.split_once('\n').expect("fixture-exec shape");
            // Absolute only: a relative name would resolve through PATH.
            assert!(std::path::Path::new(real.trim()).is_absolute());
            std::thread::sleep(Duration::from_millis(millis.parse().expect("delay ms")));
            let error = std::process::Command::new(real.trim())
                .args(&args[1..])
                .exec();
            panic!("exec of the real sqlite3 failed: {error}");
        }
        "commit" => {
            // Real SQLite COMMIT in the same owned PID; no detached child.
            // argv is `<flags...> <db>`: the runner sends the script on stdin,
            // one statement per line, and closes it once delivered.
            let database_at = {
                let mut at = 1;
                while args[at].to_str().is_some_and(|arg| arg.starts_with('-')) {
                    // `-init` takes a value; every other runner flag is bare.
                    at += if args[at] == "-init" { 2 } else { 1 };
                }
                at
            };
            assert_eq!(args.len(), database_at + 1, "no SQL may arrive in argv");
            let mut script = String::new();
            {
                use std::io::Read;
                std::io::stdin().read_to_string(&mut script).unwrap();
            }
            std::fs::write(base.join("commit.pid"), std::process::id().to_string()).unwrap();
            let connection = rusqlite::Connection::open({
                let database = std::path::Path::new(&args[database_at]);
                assert_eq!(database.parent().unwrap().canonicalize().unwrap(), base);
                assert!(std::fs::symlink_metadata(database).unwrap().is_file());
                database
            })
            .unwrap();
            connection.execute_batch(&script).unwrap();
            std::fs::write(base.join("committed"), b"committed\n").unwrap();
            // Withhold acknowledgement until the test (or the runner's hang
            // guard) ends this process.
            std::thread::sleep(Duration::from_secs(3600));
        }
        "argv-capture" => {
            // Record argv and the stdin script separately, then exit 0, so a
            // test can prove which channel carried the SQL.
            use std::io::Read;
            let argv = args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(base.join("captured-argv"), argv).unwrap();
            let mut script = String::new();
            std::io::stdin().read_to_string(&mut script).unwrap();
            // Like a shell that ran the whole script: print the writer's end
            // marker (its last statement, `SELECT '<marker>';`).
            if let Some(marker) = script
                .lines()
                .last()
                .and_then(|line| line.strip_prefix("SELECT '"))
                .and_then(|rest| rest.strip_suffix("';"))
            {
                println!("{marker}");
            }
            std::fs::write(base.join("captured-stdin"), script).unwrap();
        }
        "exit-early" => {
            // A shell that exits 0 without reading its script: the runner's
            // pipe writes all succeed (the script fits the pipe buffer), but
            // nothing ran.
            std::thread::sleep(Duration::from_millis(300));
        }
        "continue" => {
            // A sqlite3 that ignores `-bail`: feed every statement to the real
            // shell on stdin WITHOUT `-bail`, so it keeps executing past an
            // error. argv is `<flags...> <db> <statement>...`; with no
            // statement arguments the statements arrive on this process's stdin.
            use std::io::Read;
            let real = std::fs::read_to_string(base.join("real-sqlite3")).unwrap();
            let database_at = {
                let mut at = 1;
                while args[at].to_str().is_some_and(|arg| arg.starts_with('-')) {
                    at += if args[at] == "-init" { 2 } else { 1 };
                }
                at
            };
            let mut input = args[database_at + 1..]
                .iter()
                .map(|arg| arg.to_str().unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            if args.len() == database_at + 1 {
                std::io::stdin().read_to_string(&mut input).unwrap();
            }
            let mut child = std::process::Command::new(real.trim())
                .args(["-init", "/dev/null", "-batch", "-noheader", "-list"])
                .arg(&args[database_at])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            let status = child.wait().unwrap();
            std::process::exit(status.code().unwrap_or(1));
        }
        _ => panic!("invalid private fixture mode"),
    }
    true
}

fn main() {
    #[cfg(unix)]
    if run_r9_native_fixture() {
        return;
    }
    let args: Vec<String> = std::env::args().collect();

    let mut exit_code: i32 = 0;
    let mut stdout_str: Option<String> = None;
    let mut stderr_str: Option<String> = None;
    let mut hang_ms: u64 = 0;
    let mut hang_after_ms: u64 = 0;
    let mut emit_bytes: usize = 0;
    let mut capture_argv_path: Option<String> = None;

    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--exit-code" => {
                if let Some(val) = iter.next() {
                    exit_code = val.parse().unwrap_or(0);
                }
            }
            "--stdout" => {
                if let Some(val) = iter.next() {
                    stdout_str = Some(val.clone());
                }
            }
            "--stderr" => {
                if let Some(val) = iter.next() {
                    stderr_str = Some(val.clone());
                }
            }
            "--hang-ms" => {
                if let Some(val) = iter.next() {
                    hang_ms = val.parse().unwrap_or(0);
                }
            }
            "--hang-after-ms" => {
                if let Some(val) = iter.next() {
                    hang_after_ms = val.parse().unwrap_or(0);
                }
            }
            "--emit-bytes" => {
                if let Some(val) = iter.next() {
                    emit_bytes = val.parse().unwrap_or(0);
                }
            }
            "--capture-argv" => {
                if let Some(val) = iter.next() {
                    capture_argv_path = Some(val.clone());
                }
            }
            // Unknown flags are silently ignored.
            _ => {}
        }
    }

    // Capture argv BEFORE any other action (sleep, output).
    // Format: JSON array of strings, one argument per element.
    // Includes argv[0] (binary name) and all arguments.
    // The capture file is written atomically so tests can reliably read it.
    if let Some(ref path) = capture_argv_path {
        // Build a simple JSON array without any third-party crate.
        // Each element is a JSON-escaped string.
        let escaped: Vec<String> = args
            .iter()
            .map(|a| format!("\"{}\"", json_escape(a)))
            .collect();
        let content = format!("[{}]\n", escaped.join(", "));
        // Write to a temp path first, then rename for atomicity.
        // O_EXCL on tmp creation prevents parallel-test capture-file collision
        // (M8 finding). The tmp path is unique per invocation (PID-stamped).
        let tmp_path = format!("{path}.tmp.{}", std::process::id());
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;
            // Create with O_EXCL (fail if exists) and 0o600 mode.
            // This fixture writes argv which MUST NOT carry secrets; the
            // 0o600 mode is defense-in-depth, not a primary protection.
            if let Ok(mut f) = OpenOptions::new()
                .write(true)
                .create_new(true) // O_EXCL semantics
                .mode(0o600)
                .open(&tmp_path)
            {
                let _ = f.write_all(content.as_bytes());
                let _ = f.flush();
            }
        }
        #[cfg(not(unix))]
        {
            // Non-Unix: best-effort create_new (O_EXCL equivalent in std).
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
            {
                let _ = f.write_all(content.as_bytes());
                let _ = f.flush();
            }
        }
        let _ = std::fs::rename(&tmp_path, path);
    }

    // Sleep first (before any output) so the hang test reliably times out
    // without stdout confusing the partial-read logic.
    if hang_ms > 0 {
        std::thread::sleep(Duration::from_millis(hang_ms));
    }

    // Print to stdout.
    if let Some(ref s) = stdout_str {
        print!("{s}");
        // Flush before emit-bytes, which also writes stdout.
        let _ = std::io::stdout().flush();
    }

    // Emit a raw byte stream of `x` characters (no newline) for cap tests.
    if emit_bytes > 0 {
        let chunk = vec![b'x'; emit_bytes];
        let _ = std::io::stdout().write_all(&chunk);
        let _ = std::io::stdout().flush();
    }

    // Print to stderr.
    if let Some(ref s) = stderr_str {
        eprint!("{s}");
        let _ = std::io::stderr().flush();
    }

    // Sleep LAST, holding the stdout pipe open. This models a CLI that emits a
    // partial (newline-less) line and then hangs: a reader that short-circuits
    // on the byte cap returns immediately, while one that waits for EOF pays the
    // whole sleep. The two outcomes are only distinguishable if this sleep is
    // longer than the probe's own timeout — see the H-3 test.
    if hang_after_ms > 0 {
        std::thread::sleep(Duration::from_millis(hang_after_ms));
    }

    std::process::exit(exit_code);
}

/// Minimal JSON string escaping (no third-party crates).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Control character: emit \uXXXX
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
