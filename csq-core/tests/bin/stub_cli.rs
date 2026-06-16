//! Configurable test-fixture stub binary for cli_deps integration tests.
//!
//! Usage:
//!   stub-cli --stdout <str> --exit-code <N> --hang-ms <N> --emit-bytes <N>
//!             --capture-argv <path>
//!
//! All flags are optional and can be combined.
//!
//! ## Flags
//!
//! `--stdout <str>`        Print `str` to stdout (no trailing newline added unless `str` ends in `\n`).
//! `--stderr <str>`        Print `str` to stderr.
//! `--exit-code <N>`       Exit with code N (default 0).
//! `--hang-ms <N>`         Sleep for N milliseconds before doing anything else.
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
//! - stdlib only (no third-party crates).
//! - Minimal: this stub is a test fixture, not a production tool.
//! - `test = false` / `doctest = false` so it is not run as a test binary.

use std::io::Write;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut exit_code: i32 = 0;
    let mut stdout_str: Option<String> = None;
    let mut stderr_str: Option<String> = None;
    let mut hang_ms: u64 = 0;
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
