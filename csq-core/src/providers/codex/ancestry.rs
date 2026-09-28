//! Codex-ancestor detection — is this process running as a descendant
//! of a live `codex` process?
//!
//! `csq swap` in a Codex account-mismatch route must `exec()` a fresh
//! `codex` binary to pick up new credentials — codex-cli's own
//! auth-reload guard refuses an in-place account-id change (see
//! `swap.rs`'s module doc, `RouteKind::CodexAccountMismatchExecReplace`).
//! When `csq swap` runs as a subprocess of a live codex TUI (a `!cmd`
//! shell-out is the observed case), `exec()` replaces THAT descendant
//! process only — the codex TUI itself is untouched, its handle dir has
//! just been tombstoned out from under it, and nothing prints to the
//! screen the user is looking at. Detecting the live codex ancestor lets
//! the swap refuse BEFORE the tombstone rename (INV-P10) rather than
//! silently orphaning a session.
//!
//! Deliberately self-contained rather than built on
//! `crate::platform::process::find_cc_pid` — that module is out of this
//! change's touch scope (`providers/codex/**` only). The walk mirrors its
//! `imp::get_process_info` implementation on Unix; ~30 duplicated lines
//! was judged cheaper than widening the change's file scope.

/// Maximum depth when walking the parent process tree. Mirrors
/// `platform::process::MAX_PARENT_DEPTH`.
///
/// Only the unix `imp::find_live_codex_ancestor_pid` walk consumes this —
/// the non-unix `imp` (below) always returns `None` without walking
/// anything, so this is unix-only.
#[cfg(unix)]
const MAX_PARENT_DEPTH: usize = 20;

/// Returns the PID of the nearest ancestor whose reported command names
/// the codex CLI binary (`super::surface::CLI_BINARY`), or `None` if no
/// such ancestor exists within `MAX_PARENT_DEPTH` levels, or if process
/// introspection is unavailable on this platform (Windows: always
/// `None` — see the `imp` module below; this is a known gap, not a
/// claim of safety on that platform).
pub fn find_live_codex_ancestor_pid() -> Option<u32> {
    imp::find_live_codex_ancestor_pid()
}

/// Returns the parent pid of `pid`, or `None` when it cannot be determined
/// (process gone, permission denied, unsupported platform — same fail-open
/// posture as `find_live_codex_ancestor_pid`).
///
/// C-(g): S-F11's original design had `handoff_to_supervisor` verify a
/// supervisor record against the EXACT immediate parent via this function.
/// FM-13 replaced that exact-match check with [`ancestor_chain`] (a bounded
/// walk, needed once an npm-installed codex's launcher hop was accounted
/// for) — production `csq/src/cli/commands/swap.rs` calls `ancestor_chain`
/// exclusively now, never this function. This function is kept ONLY as a
/// fixture-invariant assertion inside that file's spawned-process tests
/// (confirming a spawned stand-in's parent is really the stand-in the test
/// intends), which is why it is gated to test builds — no production
/// caller remains (`doc-property-claims.md`: the earlier doc named a
/// production caller, which was true before FM-13 and is not true now).
#[cfg(any(test, feature = "test-utils"))]
pub fn parent_pid(pid: u32) -> Option<u32> {
    imp::get_process_info(pid).map(|(ppid, _cmd)| ppid)
}

/// FM-13: small bound on how many hops [`ancestor_chain`] walks when a
/// caller searches for a recorded supervisor pid above a detected codex
/// ancestor.
///
/// An npm-installed `codex` is a `#!/usr/bin/env node` launcher script
/// (`bin/codex` -> `codex.js`). The kernel resolves that shebang IN PLACE
/// (same pid, no fork) when the supervisor execs "codex" — but the
/// launcher's own JS then spawns the platform-specific native `codex`
/// binary via Node's `child_process.spawn(binaryPath, ...)`
/// (`@openai/codex`'s `bin/codex.js`, confirmed by reading that file
/// directly), which IS a genuine fork. That inserts one hop between the
/// pid a supervisor recorded (the pid it directly forked, which becomes
/// the node launcher after the shebang re-exec) and the nearest ancestor
/// `find_live_codex_ancestor_pid` can name (the native binary, whose comm
/// matches `codex`) — `parent_pid(ancestor_pid)` names the launcher, not
/// the supervisor, and a caller requiring an EXACT match refuses every
/// swap under an npm-installed codex.
///
/// A second, independently observed process tree on the same host
/// (2026-09-26; the standalone, non-npm install) already carries an
/// analogous extra hop — `codex` (pid 50534) is the parent of a further
/// `codex-code-mode-host` helper (pid 30584) — showing multi-level
/// descendant trees are the norm for this CLI family, not an npm-specific
/// exception. No LIVE npm-launched process was exercised to reproduce this
/// exact chain (per this change's operating constraints); the extra hop is
/// established by reading `codex.js`'s spawn call directly rather than by
/// running it.
///
/// Set to 4 for headroom beyond the one confirmed npm hop: a version-manager
/// shim (nvm/volta/asdf commonly interpose one more layer) or a further
/// codex-internal helper process, while still refusing an ancestor several
/// tree layers away that is genuinely unrelated.
pub const DEFAULT_ANCESTOR_CHAIN_BOUND: usize = 4;

/// Returns up to `max_hops` ancestor pids of `pid`, starting with its
/// immediate parent and walking upward. Stops early — returning fewer than
/// `max_hops` entries — at init, a detected cycle, or when introspection
/// fails (process gone, permission denied, unsupported platform: same
/// fail-open-on-absence posture as [`find_live_codex_ancestor_pid`]).
///
/// An incomplete or empty chain is NOT itself proof of anything; the
/// CALLER decides what "target pid absent from the chain" means for its
/// own security posture. `csq/src/cli/commands/swap.rs`'s
/// `handoff_to_supervisor_write_and_signal` treats absence as a refusal
/// (`guard-reader-writer-parity.md` MUST-2: a destructive-adjacent
/// operation fails CLOSED on ambiguity, not open).
pub fn ancestor_chain(pid: u32, max_hops: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(max_hops);
    let mut current = pid;
    for _ in 0..max_hops {
        let Some((ppid, _cmd)) = imp::get_process_info(current) else {
            break;
        };
        if ppid == 0 || ppid == 1 || ppid == current {
            // Reached init or a cycle.
            break;
        }
        out.push(ppid);
        current = ppid;
    }
    out
}

/// S-F1: counts how many ancestors, starting at `start_pid` ITSELF and
/// walking upward, are classified as a codex process by
/// `is_codex_command` — stopping the count (but not the walk) once
/// `stop_at_pid` is reached. `stop_at_pid` names the SUPERVISOR endpoint,
/// not an intermediate hop, so it is never itself counted.
///
/// Returns `None` when introspection fails, a cycle or init is reached, or
/// `stop_at_pid` is not found within `max_hops` — every one of those is
/// UNREADABLE, and the caller (`swap.rs`'s
/// `handoff_to_supervisor_write_and_signal`) MUST treat `None` as a
/// refusal, never as "zero codex processes found"
/// (`guard-reader-writer-parity.md` MUST-2: a destructive-adjacent
/// operation — this gates an involuntary relaunch of a live codex session
/// — fails CLOSED on ambiguity).
///
/// Exists to close a gap FM-13 opened: relaxing the exact-parent match to
/// "`stop_at_pid` anywhere within `max_hops`" (to tolerate an npm launcher's
/// extra hop) also, unintentionally, tolerates a SECOND live codex process
/// sitting between the caller and its supervisor — the shape produced by
/// running a plain `codex` inside a `!` shell-out of an ALREADY-supervised
/// codex session. `handoff_to_supervisor` would then relaunch the OUTER
/// (correctly supervised) session in response to a swap the user typed
/// inside the INNER, unsupervised one. Counting codex-classified hops (not
/// just checking reachability) distinguishes the two shapes: a direct
/// child, and an npm launcher's native-binary hop, both count exactly ONE
/// (the node launcher's `comm` does not match `codex`); a nested codex
/// counts TWO (the inner AND the outer both match). The caller refuses
/// when the count exceeds one.
pub fn count_codex_ancestors_before(
    start_pid: u32,
    stop_at_pid: u32,
    max_hops: usize,
) -> Option<usize> {
    let mut count = 0usize;
    let mut current = start_pid;
    for _ in 0..max_hops {
        let (ppid, cmd) = imp::get_process_info(current)?;
        if is_codex_command(&cmd) {
            count += 1;
        }
        if ppid == stop_at_pid {
            return Some(count);
        }
        if ppid == 0 || ppid == 1 || ppid == current {
            // Reached init or a cycle without finding stop_at_pid.
            return None;
        }
        current = ppid;
    }
    None
}

/// Matches the binary name (not arguments) against the codex CLI —
/// bare `codex`, or a path ending in `/codex` or `\codex` (with an
/// optional `.exe` suffix, for the rare cross-compiled case).
fn is_codex_command(cmd: &str) -> bool {
    let cmd_lower = cmd.to_lowercase();
    let stripped = cmd_lower.trim_end_matches(".exe");
    let bin = super::surface::CLI_BINARY;
    stripped == bin
        || stripped.ends_with(&format!("/{bin}"))
        || stripped.ends_with(&format!("\\{bin}"))
}

#[cfg(unix)]
mod imp {
    use super::*;

    pub fn find_live_codex_ancestor_pid() -> Option<u32> {
        let mut pid = std::process::id();
        for _ in 0..MAX_PARENT_DEPTH {
            let (ppid, cmd) = get_process_info(pid)?;
            if is_codex_command(&cmd) {
                return Some(pid);
            }
            if ppid == 0 || ppid == 1 || ppid == pid {
                // Reached init or a cycle.
                return None;
            }
            pid = ppid;
        }
        None
    }

    /// Returns `(parent_pid, command)` for `pid`, or `None` when it
    /// cannot be read (process gone, permission denied, unsupported
    /// platform).
    ///
    /// `pub(super)` rather than private so `parent_pid` (defined in the
    /// parent `ancestry` module, for S-F11) can call it without a second
    /// implementation.
    pub(super) fn get_process_info(pid: u32) -> Option<(u32, String)> {
        #[cfg(target_os = "linux")]
        {
            get_process_info_linux(pid)
        }
        #[cfg(target_os = "macos")]
        {
            get_process_info_macos(pid)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn get_process_info_linux(pid: u32) -> Option<(u32, String)> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let ppid = status
            .lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u32>().ok())?;
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let cmd = argv0_from_cmdline(&cmdline);
        Some((ppid, cmd))
    }

    /// Extracts argv[0] (the invoked binary path/name) from a raw
    /// `/proc/<pid>/cmdline` byte buffer — NUL-separated argv, with no
    /// trailing NUL guaranteed. Pulled out as a pure function so the
    /// parsing is unit-tested without `/proc` on any host.
    ///
    /// BUG FIX: the previous implementation joined the ENTIRE cmdline
    /// (argv0 + every argument) with spaces and matched
    /// `is_codex_command` against that whole string. A real invocation
    /// always carries arguments (`codex resume --last`, or this
    /// module's own test harness invoking
    /// `codex --ignored --exact ...`), so the joined string never ended
    /// in exactly `/codex` — `is_codex_command`'s suffix match always
    /// failed, and `find_live_codex_ancestor_pid` could never detect a
    /// live codex ancestor on Linux. argv[0] alone is the invoked
    /// binary; the trailing arguments are irrelevant to the name match.
    ///
    /// Not `cfg(target_os = "linux")`-gated (only its ONE production
    /// caller above is), and `pub(super)` rather than private, so the
    /// parsing logic can be unit-tested from `tests` on any host — dead
    /// code on non-Linux production builds, hence the `allow`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn argv0_from_cmdline(cmdline: &[u8]) -> String {
        let end = cmdline
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(cmdline.len());
        String::from_utf8_lossy(&cmdline[..end]).trim().to_string()
    }

    #[cfg(target_os = "macos")]
    fn get_process_info_macos(pid: u32) -> Option<(u32, String)> {
        // S-F10: absolute path + env_clear() + a minimal fixed env, so
        // this ancestry walk never hands the parent's full environment
        // (which may carry secrets from any caller up the stack) to a
        // spawned `ps`. Mirrors `session::shared_state::run_sqlite3_with`
        // and `thread_id`'s `lsof` invocation.
        let output = std::process::Command::new("/bin/ps")
            .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let line = String::from_utf8_lossy(&output.stdout);
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let ppid = parts.next()?.trim().parse::<u32>().ok()?;
        let cmd = parts.next()?.trim().to_string();
        Some((ppid, cmd))
    }
}

/// Windows: not yet implemented. Always returns `None`, matching the
/// PRE-existing (undetected) behaviour on that platform rather than
/// claiming a protection that has not been built — the swap-inside-codex
/// refusal this backs is therefore currently inert on Windows.
#[cfg(not(unix))]
mod imp {
    pub fn find_live_codex_ancestor_pid() -> Option<u32> {
        None
    }

    /// Matches the Unix `imp`'s signature so `parent_pid` compiles on
    /// every platform; always `None` here (same known gap as
    /// `find_live_codex_ancestor_pid` on this platform).
    pub(super) fn get_process_info(_pid: u32) -> Option<(u32, String)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_codex_command_matches_bare_and_paths() {
        assert!(is_codex_command("codex"));
        assert!(is_codex_command("CODEX"));
        assert!(is_codex_command("/usr/local/bin/codex"));
        assert!(is_codex_command("/opt/homebrew/bin/codex.exe"));
        assert!(is_codex_command(r"C:\tools\codex.exe"));
    }

    #[test]
    fn is_codex_command_rejects_non_codex() {
        assert!(!is_codex_command("claude"));
        assert!(!is_codex_command("codexx"));
        assert!(!is_codex_command("/usr/local/bin/codex-helper"));
        assert!(!is_codex_command("node /path/to/codex/cli.js"));
        assert!(!is_codex_command(""));
    }

    #[cfg(unix)]
    #[test]
    fn argv0_from_cmdline_strips_trailing_args() {
        // BUG (found while investigating a failing spawned-process test
        // on a Linux host): the pre-fix implementation joined the WHOLE
        // `/proc/<pid>/cmdline` (argv0 + every argument) with spaces, so
        // a real codex invocation's args defeated `is_codex_command`'s
        // suffix match. argv[0] alone is the invoked binary.
        let raw = b"/usr/local/bin/codex\0resume\0--last\0";
        assert_eq!(imp::argv0_from_cmdline(raw), "/usr/local/bin/codex");
    }

    #[cfg(unix)]
    #[test]
    fn argv0_from_cmdline_handles_no_trailing_nul() {
        let raw = b"codex";
        assert_eq!(imp::argv0_from_cmdline(raw), "codex");
    }

    #[cfg(unix)]
    #[test]
    fn argv0_from_cmdline_handles_empty_buffer() {
        assert_eq!(imp::argv0_from_cmdline(b""), "");
    }

    #[test]
    fn find_live_codex_ancestor_pid_does_not_error() {
        // Under `cargo test`/`cargo nextest` this process is not a
        // descendant of a real `codex` — must return None, not panic.
        // The positive case (a genuine codex ancestor) is exercised by
        // the spawned-process tests below, which are the falsifiable
        // half of this module.
        assert!(find_live_codex_ancestor_pid().is_none());
    }

    #[test]
    fn ancestor_chain_does_not_error_and_respects_the_bound() {
        // Under `cargo test`/`cargo nextest` this process has a REAL
        // parent (the test harness), so the chain need not be empty —
        // only bounded and non-panicking. The genuine multi-hop case (a
        // recorded pid two hops above a detected ancestor) is exercised
        // by `ancestor_chain_finds_the_supervisor_two_hops_up_and_excludes_an_unrelated_pid`
        // below, which is the falsifiable half of this helper.
        let chain = ancestor_chain(std::process::id(), DEFAULT_ANCESTOR_CHAIN_BOUND);
        assert!(chain.len() <= DEFAULT_ANCESTOR_CHAIN_BOUND);
    }

    #[test]
    fn ancestor_chain_zero_bound_is_always_empty() {
        assert_eq!(ancestor_chain(std::process::id(), 0), Vec::<u32>::new());
    }

    // ── Spawned-process tests (Unix only — mirrors
    // `platform::process::spawn_foreign_test_process`'s "copy the
    // running test binary, rename it, spawn it" pattern) ──────────────
    //
    // Positive case: a genuine live process named `codex`, and a CHILD
    // of that process calling `find_live_codex_ancestor_pid()`, must
    // detect it. Negative case: a live process with a DIFFERENT name
    // must NOT be detected as codex. Both run for real — no fixture
    // ever fabricates `/proc` or `ps` output — because introspection
    // is exactly what would be wrong if this file's OS-specific parsing
    // regressed.
    #[cfg(unix)]
    mod spawned {
        use super::*;
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        const RESULT_ENV: &str = "CSQ_TEST_CODEX_ANCESTRY_RESULT_FILE";
        const CHILD_EXE_ENV: &str = "CSQ_TEST_CODEX_ANCESTRY_CHILD_EXE";

        fn copy_self_to(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
            let src = std::env::current_exe().expect("current_exe for the running test binary");
            let dst = dir.join(name);
            std::fs::copy(&src, &dst).expect("copy running test binary to renamed path");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dst).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dst, perms).unwrap();
            }
            dst
        }

        fn wait_for_file(path: &std::path::Path, deadline: Instant) -> String {
            loop {
                if let Ok(s) = std::fs::read_to_string(path) {
                    if !s.is_empty() {
                        return s;
                    }
                }
                if Instant::now() >= deadline {
                    panic!(
                        "result file {} never became non-empty within the deadline",
                        path.display()
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// Ignored helper: spawns a CHILD running `ancestry_child_probe`,
        /// waits for it, then exits. The child runs a COPY named per
        /// `CSQ_TEST_CODEX_ANCESTRY_CHILD_EXE` — deliberately NOT this
        /// process's own name, so the walk is exercised against a real
        /// distinct ancestor rather than matching itself on the first
        /// step (the production shape: `csq swap`'s own binary is never
        /// named `codex`; only an ANCESTOR may be).
        #[test]
        #[ignore]
        fn ancestry_parent_helper() {
            let child_exe = std::env::var(CHILD_EXE_ENV).expect("child exe env var set");
            let status = Command::new(&child_exe)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::ancestry_child_probe",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn child probe");
            assert!(status.success(), "child probe exited non-zero: {status:?}");
        }

        /// Ignored helper: writes what `find_live_codex_ancestor_pid()`
        /// sees, from ITS OWN ancestry, to the file named by
        /// `CSQ_TEST_CODEX_ANCESTRY_RESULT_FILE`.
        #[test]
        #[ignore]
        fn ancestry_child_probe() {
            let out_path = std::env::var(RESULT_ENV).expect("result file env var set");
            let found = find_live_codex_ancestor_pid();
            let line = match found {
                Some(pid) => format!("found:{pid}\n"),
                None => "none\n".to_string(),
            };
            let mut f = std::fs::File::create(&out_path).expect("create result file");
            f.write_all(line.as_bytes()).expect("write result file");
        }

        #[test]
        fn detects_a_genuine_live_codex_ancestor() {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let result_path = dir.path().join("result.txt");
            let codex_bin = copy_self_to(dir.path(), "codex");
            // The CHILD is a distinct copy, deliberately NOT named `codex` —
            // it stands in for `csq swap`'s own binary, which is never named
            // `codex`. Only its PARENT (spawned above) carries that name.
            let child_bin = copy_self_to(dir.path(), "csq-test-child-probe");

            let mut parent = Command::new(&codex_bin)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::ancestry_parent_helper",
                ])
                .env(RESULT_ENV, &result_path)
                .env(CHILD_EXE_ENV, &child_bin)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn renamed-to-codex parent helper");
            let parent_pid = parent.id();

            let deadline = Instant::now() + Duration::from_secs(60);
            let content = wait_for_file(&result_path, deadline);
            let status = parent.wait().expect("wait on parent helper");
            assert!(
                status.success(),
                "parent helper exited non-zero: {status:?}"
            );

            assert_eq!(
                content.trim(),
                format!("found:{parent_pid}"),
                "child of a live `codex`-named process must detect that \
                 exact ancestor PID; got {content:?}"
            );
        }

        // ── FM-13 chain tests: supervisor -> launcher -> codex-native ──────
        //
        // Reproduces the npm-launcher shape one level deeper than the
        // pair above: a THIRD generation stands in for the recorded
        // supervisor pid, which sits two hops above the detected ancestor
        // (the launcher is one hop, the supervisor is two). Both real
        // processes, both spawned for real — no fixture fabricates
        // `/proc` or `ps` output.
        const CHAIN_RESULT_ENV: &str = "CSQ_TEST_ANCESTOR_CHAIN_RESULT_FILE";
        const CHAIN_PARENT_EXE_ENV: &str = "CSQ_TEST_ANCESTOR_CHAIN_PARENT_EXE";
        const CHAIN_CHILD_EXE_ENV: &str = "CSQ_TEST_ANCESTOR_CHAIN_CHILD_EXE";

        /// Ignored helper standing in for the SUPERVISOR: spawns the
        /// "launcher" stand-in as its own child, then waits.
        #[test]
        #[ignore]
        fn chain_grandparent_helper() {
            let parent_exe = std::env::var(CHAIN_PARENT_EXE_ENV).expect("parent exe env var set");
            let status = Command::new(&parent_exe)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::chain_parent_helper",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn chain parent helper");
            assert!(
                status.success(),
                "chain parent helper exited non-zero: {status:?}"
            );
        }

        /// Ignored helper standing in for the npm LAUNCHER (`node` running
        /// `codex.js`): spawns the "codex-native" stand-in as its own
        /// child, mirroring `child_process.spawn(binaryPath, ...)` in the
        /// real launcher — a genuine fork, not an in-place exec.
        #[test]
        #[ignore]
        fn chain_parent_helper() {
            let child_exe = std::env::var(CHAIN_CHILD_EXE_ENV).expect("child exe env var set");
            let status = Command::new(&child_exe)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::chain_child_probe",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn chain child probe");
            assert!(
                status.success(),
                "chain child probe exited non-zero: {status:?}"
            );
        }

        /// Ignored helper standing in for the native `codex` binary: writes
        /// its own `ancestor_chain` to the result file.
        #[test]
        #[ignore]
        fn chain_child_probe() {
            let out_path = std::env::var(CHAIN_RESULT_ENV).expect("result file env var set");
            let chain = ancestor_chain(std::process::id(), DEFAULT_ANCESTOR_CHAIN_BOUND);
            let line = chain
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut f = std::fs::File::create(&out_path).expect("create result file");
            f.write_all(format!("{line}\n").as_bytes())
                .expect("write result file");
        }

        #[test]
        fn ancestor_chain_finds_the_supervisor_two_hops_up_and_excludes_an_unrelated_pid() {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let result_path = dir.path().join("result.txt");
            let grandparent_bin = copy_self_to(dir.path(), "csq-test-chain-supervisor");
            let parent_bin = copy_self_to(dir.path(), "csq-test-chain-launcher");
            let child_bin = copy_self_to(dir.path(), "codex");

            // A genuinely unrelated, LIVE sibling process — not an
            // ancestor of the child at any depth — proves the chain
            // specifically EXCLUDES it, rather than merely "always
            // finding something".
            let mut unrelated = Command::new("sh")
                .arg("-c")
                .arg("sleep 30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn unrelated sibling process");
            let unrelated_pid = unrelated.id();

            let mut grandparent = Command::new(&grandparent_bin)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::chain_grandparent_helper",
                ])
                .env(CHAIN_RESULT_ENV, &result_path)
                .env(CHAIN_PARENT_EXE_ENV, &parent_bin)
                .env(CHAIN_CHILD_EXE_ENV, &child_bin)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn renamed supervisor stand-in");
            let grandparent_pid = grandparent.id();

            let deadline = Instant::now() + Duration::from_secs(60);
            let content = wait_for_file(&result_path, deadline);
            let status = grandparent.wait().expect("wait on grandparent helper");
            assert!(
                status.success(),
                "grandparent helper exited non-zero: {status:?}"
            );

            let _ = unrelated.kill();
            let _ = unrelated.wait();

            let chain: Vec<u32> = content
                .trim()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse().expect("chain entry parses as u32"))
                .collect();

            assert!(
                chain.contains(&grandparent_pid),
                "the supervisor stand-in (2 hops up: codex-native <- launcher <- \
                 supervisor) must appear in the native binary's ancestor chain \
                 within the bound; got chain {chain:?}, expected to contain \
                 {grandparent_pid}"
            );
            assert!(
                !chain.contains(&unrelated_pid),
                "a genuinely unrelated live pid must never appear in the chain; \
                 got chain {chain:?} containing unrelated pid {unrelated_pid}"
            );
        }

        #[test]
        fn does_not_detect_a_live_non_codex_ancestor() {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let result_path = dir.path().join("result.txt");
            // Same shape as the positive test, only the NAMES differ — neither
            // parent nor child is `codex`.
            let other_bin = copy_self_to(dir.path(), "not-codex-test-host");
            let child_bin = copy_self_to(dir.path(), "csq-test-child-probe-2");

            let mut parent = Command::new(&other_bin)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::ancestry_parent_helper",
                ])
                .env(RESULT_ENV, &result_path)
                .env(CHILD_EXE_ENV, &child_bin)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn renamed-to-non-codex parent helper");

            let deadline = Instant::now() + Duration::from_secs(60);
            let content = wait_for_file(&result_path, deadline);
            let status = parent.wait().expect("wait on parent helper");
            assert!(
                status.success(),
                "parent helper exited non-zero: {status:?}"
            );

            assert_eq!(
                content.trim(),
                "none",
                "a live ancestor named `not-codex-test-host` must NOT be \
                 misdetected as codex; got {content:?}"
            );
        }

        // ── S-F1: `count_codex_ancestors_before` across three real
        // process-tree shapes ───────────────────────────────────────────
        //
        // Plumbing note: the "supervisor" stand-in is the ONLY generation
        // that needs to know its own pid (a pid is only known after
        // `spawn()` returns, so the top-level test — which spawns the
        // supervisor stand-in, not its descendants — cannot supply it).
        // `sf1_supervisor_root` reads its own `std::process::id()` and
        // injects it as `SF1_STOP_PID_ENV` on the child it spawns; every
        // further descendant inherits that value unchanged, because none
        // of these helpers call `env_clear()`.
        const SF1_RESULT_ENV: &str = "CSQ_TEST_SF1_RESULT_FILE";
        const SF1_STOP_PID_ENV: &str = "CSQ_TEST_SF1_STOP_PID";
        const SF1_HOP1_EXE_ENV: &str = "CSQ_TEST_SF1_HOP1_EXE";
        const SF1_HOP1_TEST_ENV: &str = "CSQ_TEST_SF1_HOP1_TEST";
        const SF1_HOP2_EXE_ENV: &str = "CSQ_TEST_SF1_HOP2_EXE";
        const SF1_HOP2_TEST_ENV: &str = "CSQ_TEST_SF1_HOP2_TEST";
        const SF1_HOP3_EXE_ENV: &str = "CSQ_TEST_SF1_HOP3_EXE";
        const SF1_HOP3_TEST_ENV: &str = "CSQ_TEST_SF1_HOP3_TEST";

        /// Ignored: runs AS the supervisor stand-in. Spawns
        /// `SF1_HOP1_EXE_ENV` running `SF1_HOP1_TEST_ENV`, injecting its
        /// OWN pid as `SF1_STOP_PID_ENV`.
        #[test]
        #[ignore]
        fn sf1_supervisor_root() {
            let next_exe = std::env::var(SF1_HOP1_EXE_ENV).expect("hop1 exe env var set");
            let next_test = std::env::var(SF1_HOP1_TEST_ENV).expect("hop1 test env var set");
            let status = Command::new(&next_exe)
                .args(["--ignored", "--exact", &next_test])
                .env(SF1_STOP_PID_ENV, std::process::id().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn sf1 hop1 target");
            assert!(
                status.success(),
                "sf1 hop1 target exited non-zero: {status:?}"
            );
        }

        /// Ignored relay: spawns `SF1_HOP2_EXE_ENV` running `SF1_HOP2_TEST_ENV`.
        #[test]
        #[ignore]
        fn sf1_hop2_relay() {
            let next_exe = std::env::var(SF1_HOP2_EXE_ENV).expect("hop2 exe env var set");
            let next_test = std::env::var(SF1_HOP2_TEST_ENV).expect("hop2 test env var set");
            let status = Command::new(&next_exe)
                .args(["--ignored", "--exact", &next_test])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn sf1 hop2 target");
            assert!(
                status.success(),
                "sf1 hop2 target exited non-zero: {status:?}"
            );
        }

        /// Ignored relay: spawns `SF1_HOP3_EXE_ENV` running `SF1_HOP3_TEST_ENV`.
        #[test]
        #[ignore]
        fn sf1_hop3_relay() {
            let next_exe = std::env::var(SF1_HOP3_EXE_ENV).expect("hop3 exe env var set");
            let next_test = std::env::var(SF1_HOP3_TEST_ENV).expect("hop3 test env var set");
            let status = Command::new(&next_exe)
                .args(["--ignored", "--exact", &next_test])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn sf1 hop3 target");
            assert!(
                status.success(),
                "sf1 hop3 target exited non-zero: {status:?}"
            );
        }

        /// Ignored terminal probe: computes `count_codex_ancestors_before`
        /// from ITS OWN pid up to `SF1_STOP_PID_ENV`, writes the result to
        /// `SF1_RESULT_ENV`.
        #[test]
        #[ignore]
        fn sf1_probe() {
            let out_path = std::env::var(SF1_RESULT_ENV).expect("result file env var set");
            let stop_pid: u32 = std::env::var(SF1_STOP_PID_ENV)
                .expect("stop pid env var set")
                .parse()
                .expect("stop pid parses as u32");
            let result = count_codex_ancestors_before(
                std::process::id(),
                stop_pid,
                DEFAULT_ANCESTOR_CHAIN_BOUND,
            );
            let line = match result {
                Some(n) => format!("count:{n}\n"),
                None => "none\n".to_string(),
            };
            let mut f = std::fs::File::create(&out_path).expect("create result file");
            f.write_all(line.as_bytes()).expect("write result file");
        }

        #[test]
        fn supervised_codex_direct_child_counts_one_and_is_accepted() {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let result_path = dir.path().join("result.txt");
            let supervisor_bin = copy_self_to(dir.path(), "csq-test-sf1-supervisor-1");
            let codex_bin = copy_self_to(dir.path(), "codex");

            let mut supervisor = Command::new(&supervisor_bin)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::sf1_supervisor_root",
                ])
                .env(SF1_HOP1_EXE_ENV, &codex_bin)
                .env(
                    SF1_HOP1_TEST_ENV,
                    "providers::codex::ancestry::tests::spawned::sf1_probe",
                )
                .env(SF1_RESULT_ENV, &result_path)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn sf1 case-1 supervisor stand-in");

            let deadline = Instant::now() + Duration::from_secs(60);
            let content = wait_for_file(&result_path, deadline);
            let status = supervisor.wait().expect("wait on supervisor stand-in");
            assert!(
                status.success(),
                "supervisor stand-in exited non-zero: {status:?}"
            );

            assert_eq!(
                content.trim(),
                "count:1",
                "a codex process spawned DIRECTLY by its supervisor must \
                 count exactly ONE codex instance between caller and \
                 supervisor (itself); got {content:?}"
            );
        }

        #[test]
        fn npm_launcher_shape_counts_one_and_is_accepted() {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let result_path = dir.path().join("result.txt");
            let supervisor_bin = copy_self_to(dir.path(), "csq-test-sf1-supervisor-2");
            let launcher_bin = copy_self_to(dir.path(), "csq-test-sf1-node-launcher");
            let codex_native_bin = copy_self_to(dir.path(), "codex");

            let mut supervisor = Command::new(&supervisor_bin)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::sf1_supervisor_root",
                ])
                .env(SF1_HOP1_EXE_ENV, &launcher_bin)
                .env(
                    SF1_HOP1_TEST_ENV,
                    "providers::codex::ancestry::tests::spawned::sf1_hop2_relay",
                )
                .env(SF1_HOP2_EXE_ENV, &codex_native_bin)
                .env(
                    SF1_HOP2_TEST_ENV,
                    "providers::codex::ancestry::tests::spawned::sf1_probe",
                )
                .env(SF1_RESULT_ENV, &result_path)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn sf1 case-2 supervisor stand-in");

            let deadline = Instant::now() + Duration::from_secs(60);
            let content = wait_for_file(&result_path, deadline);
            let status = supervisor.wait().expect("wait on supervisor stand-in");
            assert!(
                status.success(),
                "supervisor stand-in exited non-zero: {status:?}"
            );

            assert_eq!(
                content.trim(),
                "count:1",
                "an npm-launcher-shaped codex (supervisor -> node launcher \
                 -> native codex) must count exactly ONE codex instance — \
                 the launcher's `node` name does not match; got {content:?}"
            );
        }

        #[test]
        fn nested_plain_codex_counts_two_and_is_refused() {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let result_path = dir.path().join("result.txt");
            let supervisor_bin = copy_self_to(dir.path(), "csq-test-sf1-supervisor-3");
            let outer_codex_bin = copy_self_to(dir.path(), "codex");
            let shell_bin = copy_self_to(dir.path(), "csq-test-sf1-shell");
            let inner_codex_bin_dir = dir.path().join("inner");
            std::fs::create_dir(&inner_codex_bin_dir).expect("create inner codex dir");
            let inner_codex_bin = copy_self_to(&inner_codex_bin_dir, "codex");

            let mut supervisor = Command::new(&supervisor_bin)
                .args([
                    "--ignored",
                    "--exact",
                    "providers::codex::ancestry::tests::spawned::sf1_supervisor_root",
                ])
                .env(SF1_HOP1_EXE_ENV, &outer_codex_bin)
                .env(
                    SF1_HOP1_TEST_ENV,
                    "providers::codex::ancestry::tests::spawned::sf1_hop2_relay",
                )
                .env(SF1_HOP2_EXE_ENV, &shell_bin)
                .env(
                    SF1_HOP2_TEST_ENV,
                    "providers::codex::ancestry::tests::spawned::sf1_hop3_relay",
                )
                .env(SF1_HOP3_EXE_ENV, &inner_codex_bin)
                .env(
                    SF1_HOP3_TEST_ENV,
                    "providers::codex::ancestry::tests::spawned::sf1_probe",
                )
                .env(SF1_RESULT_ENV, &result_path)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn sf1 case-3 supervisor stand-in");

            let deadline = Instant::now() + Duration::from_secs(60);
            let content = wait_for_file(&result_path, deadline);
            let status = supervisor.wait().expect("wait on supervisor stand-in");
            assert!(
                status.success(),
                "supervisor stand-in exited non-zero: {status:?}"
            );

            assert_eq!(
                content.trim(),
                "count:2",
                "a plain `codex` run inside another supervised codex's \
                 shell-out must count TWO codex instances between caller \
                 and supervisor (inner + outer) — production refuses on \
                 count > 1; got {content:?}"
            );
        }

        #[test]
        fn count_codex_ancestors_before_returns_none_on_unreadable_pid() {
            // A pid vanishingly unlikely to exist on any host —
            // introspection fails immediately, which is the "unreadable
            // chain" case production must refuse on
            // (guard-reader-writer-parity.md MUST-2), never read as "zero
            // codex processes found".
            assert_eq!(
                count_codex_ancestors_before(u32::MAX - 1, 1, DEFAULT_ANCESTOR_CHAIN_BOUND),
                None
            );
        }
    }
}
