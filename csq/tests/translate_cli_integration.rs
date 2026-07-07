//! Integration tests for the top-level `csq translate` command (CU1a,
//! an internal ticket).
//!
//! `csq translate --surface <cc|claude-code|codex|gemini> --start <path>
//! --json` promotes the read-only `.coc/` → `SpawnPayload` conversion (until
//! now reachable only via `csq inspect translate`) to a first-class,
//! contract-stable surface the neutral `coc-run` launcher + CU5's byte-parity
//! golden consume.
//!
//! Acceptance criteria (CU1a task file):
//! - AC1: deterministic JSON across ≥30 repeated invocations.
//! - AC2: honors `coc::load`; writes NOTHING under the `.coc/` tree of `--start`.
//! - AC3: both `cc` and `claude-code` accepted, byte-identical ClaudeCode
//!   payloads; the existing `inspect translate` path still works (and now also
//!   accepts the `cc` alias).
//! - AC4: unknown surface rejected cleanly (non-zero exit, no payload, no panic).
//!
//! Per `rules/testing.md` Rule 4/4a + `rules/test-hermeticity.md` MUST 2:
//! subprocess commands use `env_clear()` + whitelist + a sandbox `HOME`, and a
//! per-test `TempDir` rooting both `CSQ_BASE_DIR` and the `.coc/` fixture —
//! never the operator's real `~/.claude`.

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ── Binary path ──────────────────────────────────────────────────────────────

fn csq_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_csq") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("csq")
}

// ── Hermetic subprocess helper (rules/test-hermeticity.md MUST 2) ─────────────

/// Per-process sandbox `$HOME` — a single empty tempdir for the whole test
/// process, so production reads of `HOME` (`~/.codex`, `~/.gemini`, redaction
/// helper, keychain prefix) resolve inside the sandbox, never the operator's
/// real home.
fn sandbox_home() -> PathBuf {
    static H: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    H.get_or_init(|| TempDir::new().expect("sandbox home"))
        .path()
        .to_path_buf()
}

fn clean_cmd() -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    // Hermetic: the spawned `csq` binary must NOT shell `security` against the
    // operator's real login keychain (rules/test-hermeticity.md).
    cmd.env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1");
    cmd.env("HOME", sandbox_home());
    cmd.env("CLAUDE_HOME", sandbox_home());
    for k in [
        "PATH",
        "LANG",
        "LC_ALL",
        "TERM",
        "USER",
        "TMPDIR",
        // Windows-essential (skipped on Unix via the `if let Ok` guard).
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
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd
}

// ── `.coc/` fixture (mirrors csq-core/src/coc/mod.rs::build_coc_dir) ──────────

/// Build a valid `.coc/` tree under `<root>/.coc` exercising all four artifact
/// kinds (rule / agent / skill / command), each visible to every surface so a
/// translate produces non-empty per-kind sections regardless of surface.
fn build_coc_fixture(root: &Path) {
    let coc = root.join(".coc");
    for sub in ["rules", "agents", "skills", "commands"] {
        std::fs::create_dir_all(coc.join(sub)).unwrap();
    }
    std::fs::write(
        coc.join("COC.md"),
        "---\ncoc.version: 1.0.0\n---\n# primer\n",
    )
    .unwrap();
    // COC.lock content is hashed as the cache key; any bytes make the loader
    // treat the tree as a real `.coc/` (a missing lock falls back to legacy).
    std::fs::write(coc.join("COC.lock"), b"{\"version\":\"1.0.0\"}").unwrap();

    let all = "applies_to: [claude-code, codex, gemini]";
    std::fs::write(
        coc.join("rules").join("RULE-ALPHA.md"),
        format!(
            "---\nid: RULE-ALPHA\npaths: [src/**]\n{all}\nprecedence: 5\n---\nrule alpha body\n"
        ),
    )
    .unwrap();
    std::fs::write(
        coc.join("agents").join("AGENT-BETA.md"),
        format!("---\nid: AGENT-BETA\n{all}\nprecedence: 5\n---\nagent beta body\n"),
    )
    .unwrap();
    std::fs::write(
        coc.join("skills").join("SKILL-GAMMA.md"),
        format!("---\nid: SKILL-GAMMA\n{all}\nprecedence: 5\n---\nskill gamma body\n"),
    )
    .unwrap();
    std::fs::write(
        coc.join("commands").join("CMD-DELTA.md"),
        format!("---\nid: CMD-DELTA\n{all}\nprecedence: 5\n---\ncommand delta body\n"),
    )
    .unwrap();
}

/// Recursive snapshot of every file under `dir`, sorted by relative path, as
/// `(relpath, bytes)` — used to assert byte-for-byte stability of the `.coc/`
/// tree across a translate run (AC2).
fn snapshot_tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, cur: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(cur).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    walk(dir, dir, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Run `csq <args...>` with a sandboxed base dir; returns (stdout, stderr,
/// success).
fn run_csq(base: &Path, args: &[&str]) -> (String, String, bool) {
    let out = clean_cmd()
        .env("CSQ_BASE_DIR", base)
        .args(args)
        .output()
        .expect("spawn csq");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

// ── AC1 — deterministic JSON across ≥30 invocations ──────────────────────────

#[test]
fn translate_cc_json_is_deterministic_across_30_runs() {
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    let mut first: Option<String> = None;
    for i in 0..30 {
        let (stdout, stderr, ok) = run_csq(
            base.path(),
            &["translate", "--surface", "cc", "--start", &start, "--json"],
        );
        assert!(ok, "run {i} failed; stderr: {stderr}");
        // Structural field check on the actual serialized tag. `SpawnPayload`
        // carries `#[serde(tag = "surface", rename_all = "kebab-case")]`, so the
        // ClaudeCode variant serializes as `"surface": "claude-code"` — the Rust
        // identifier `ClaudeCode` never reaches stdout.
        assert!(
            stdout.contains("\"surface\": \"claude-code\""),
            "run {i} stdout not a claude-code payload: {stdout}"
        );
        match &first {
            None => first = Some(stdout),
            Some(f) => assert_eq!(*f, stdout, "run {i} diverged from run 0 (nondeterministic)"),
        }
    }
}

// ── AC2 — writes nothing under the `.coc/` tree ──────────────────────────────

#[test]
fn translate_writes_nothing_under_coc_tree() {
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let coc_dir = proj.path().join(".coc");
    let start = proj.path().to_string_lossy().into_owned();

    let before = snapshot_tree(&coc_dir);
    let (_stdout, stderr, ok) = run_csq(
        base.path(),
        &[
            "translate",
            "--surface",
            "gemini",
            "--start",
            &start,
            "--json",
        ],
    );
    assert!(ok, "translate failed; stderr: {stderr}");
    let after = snapshot_tree(&coc_dir);

    assert_eq!(
        before, after,
        "`csq translate` mutated the .coc/ tree (file set or bytes changed)"
    );
}

// ── AC3 — cc and claude-code are byte-identical; inspect-translate parity ─────

#[test]
fn translate_cc_and_claude_code_are_byte_identical() {
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    let (cc_out, cc_err, cc_ok) = run_csq(
        base.path(),
        &["translate", "--surface", "cc", "--start", &start, "--json"],
    );
    let (claude_out, claude_err, claude_ok) = run_csq(
        base.path(),
        &[
            "translate",
            "--surface",
            "claude-code",
            "--start",
            &start,
            "--json",
        ],
    );
    assert!(cc_ok, "cc run failed: {cc_err}");
    assert!(claude_ok, "claude-code run failed: {claude_err}");
    assert_eq!(
        cc_out, claude_out,
        "`--surface cc` and `--surface claude-code` produced different payloads"
    );
}

#[test]
fn inspect_translate_accepts_cc_alias_and_claude_code() {
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    // The existing sub-subcommand must still work with claude-code (no
    // regression for harness fixtures) AND now accept the cc alias.
    let (cc_out, cc_err, cc_ok) = run_csq(
        base.path(),
        &["inspect", "translate", "cc", "--start", &start, "--json"],
    );
    let (claude_out, claude_err, claude_ok) = run_csq(
        base.path(),
        &[
            "inspect",
            "translate",
            "claude-code",
            "--start",
            &start,
            "--json",
        ],
    );
    assert!(cc_ok, "inspect translate cc failed: {cc_err}");
    assert!(
        claude_ok,
        "inspect translate claude-code failed: {claude_err}"
    );
    assert_eq!(
        cc_out, claude_out,
        "inspect translate cc vs claude-code produced different payloads"
    );
}

#[test]
fn top_level_translate_matches_inspect_translate() {
    // The promoted top-level command and the legacy sub-subcommand drive the
    // same `handle_translate` — their output must be identical.
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    for surface in ["claude-code", "codex", "gemini"] {
        let (top, top_err, top_ok) = run_csq(
            base.path(),
            &[
                "translate",
                "--surface",
                surface,
                "--start",
                &start,
                "--json",
            ],
        );
        let (insp, insp_err, insp_ok) = run_csq(
            base.path(),
            &["inspect", "translate", surface, "--start", &start, "--json"],
        );
        assert!(top_ok, "translate {surface} failed: {top_err}");
        assert!(insp_ok, "inspect translate {surface} failed: {insp_err}");
        assert_eq!(
            top, insp,
            "surface {surface}: top-level != inspect translate"
        );
    }
}

// ── AC4 — unknown surface rejected cleanly ───────────────────────────────────

#[test]
fn translate_unknown_surface_rejected() {
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    let (stdout, _stderr, ok) = run_csq(
        base.path(),
        &["translate", "--surface", "foo", "--start", &start, "--json"],
    );
    assert!(!ok, "unknown surface `foo` should exit non-zero");
    assert!(
        !stdout.contains("system_prompt_append") && !stdout.contains("instructions"),
        "rejected surface must emit no SpawnPayload on stdout, got: {stdout}"
    );
}

// ── Sanity — all three surfaces emit a payload ───────────────────────────────

#[test]
fn translate_all_surfaces_emit_payload() {
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    for surface in ["cc", "codex", "gemini"] {
        let (stdout, stderr, ok) = run_csq(
            base.path(),
            &[
                "translate",
                "--surface",
                surface,
                "--start",
                &start,
                "--json",
            ],
        );
        assert!(ok, "surface {surface} failed: {stderr}");
        assert!(
            !stdout.trim().is_empty(),
            "surface {surface} produced empty stdout"
        );
    }
}

// ── Default (non-`--json`) human-summary path of the top-level command ────────

#[test]
fn translate_without_json_prints_human_summary() {
    // The default (no `--json`) branch drives `print_payload_summary`, which the
    // `--json` tests never exercise through the top-level command. Cover it.
    let proj = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    build_coc_fixture(proj.path());
    let start = proj.path().to_string_lossy().into_owned();

    let (stdout, stderr, ok) = run_csq(
        base.path(),
        &["translate", "--surface", "cc", "--start", &start],
    );
    assert!(ok, "non-json translate failed: {stderr}");
    assert!(
        stdout.contains("surface: claude-code"),
        "human summary missing the surface header: {stdout}"
    );
}
