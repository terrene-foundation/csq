//! Binary-smoke demonstration: §10.5 condition-#3 (latency) is measurable via
//! the ALREADY-EXISTING `--bench-mode layer-only` preflight with ZERO CLI
//! spawn, ZERO OAuth, and ZERO keychain access (an internal ticket Part A).
//!
//! `run_capability_layer_preflight` (csq/src/cli/commands/run.rs) resolves
//! `.coc/` from CWD, composes the scaffold, and returns BEFORE the CLI
//! subprocess is spawned; `handle_bench_mode_layer_only` (gated behind
//! `CSQ_BENCH_MODE=1`) terminates the run right there. This test proves that
//! end-to-end against the BUILT binary:
//!
//! 1. `PATH` is reduced to `/usr/bin:/bin` — no `claude`/`codex`/`gemini`
//!    binary of ANY kind is reachable, and the run still succeeds (exit 0).
//! 2. `CSQ_CLI_DEPS_PROBE_DISABLE=1` additionally skips even the cheap
//!    `<cli> --version` probe (`csq_core::cli_deps::probe`'s documented
//!    kill-switch), so the ONLY process ever spawned is `csq` itself.
//! 3. The fixture's OAuth credentials are fabricated, never-validated
//!    placeholders (per `rules/testing.md` MUST Rule 8, mirroring
//!    `audit_no_audit_integration.rs::stage_anthropic_identity_slot`) — the
//!    bench-mode path never reads them for a network call.
//! 4. A synthesized `.coc/` overlay (mirroring
//!    `coc-eval/bench/fixtures/coc-engaged/`, spec 09 §9.1 conformant: all
//!    four canonical subdirs non-empty) makes the layer ENGAGE rather than
//!    no-op, so the emitted `cap.layer_total` timing reflects the actual
//!    NFR-PERF-02 subject, not the FR-RUN-04 no-op fast path.
//!
//! This is the durable regression-test form of the "demonstrate the preflight
//! measures condition #3 with no spawn" requirement — the Python-side
//! recording harness (`coc-eval/bench/condition3_latency_preflight.py`)
//! exercises the identical code path for real recording runs.
//!
//! Whole-file `#![cfg(unix)]`: every test here reduces `PATH` to `/usr/bin:/bin`
//! (a unix-specific "no CLI reachable" mechanism), so all helpers + the tests are
//! unix-only. Without the file-level gate the helpers are dead code on windows and
//! trip the an internal ticket `-D warnings` gate.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

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

/// Stage a complete (fabricated) Anthropic slot the way `csq login N` leaves
/// it. Mirrors `audit_no_audit_integration.rs::stage_anthropic_identity_slot`
/// (`rules/testing.md` MUST Rule 8 — fixtures mirror real csq mint-path
/// output) and `coc-eval/bench/lib/layer_overhead.py::
/// stage_synthetic_anthropic_slot` (the Python-side twin for the recording
/// harness).
#[cfg(unix)]
fn stage_anthropic_identity_slot(base: &std::path::Path, n: u16) {
    use csq_core::accounts::{identity_store, profiles};
    use csq_core::testing::identity_fixtures::fixture_uuid_for_slot;

    let uuid = fixture_uuid_for_slot(n);

    let profiles_path = profiles::profiles_path(base);
    let mut pf = profiles::load(&profiles_path).unwrap_or_else(|_| profiles::ProfilesFile::empty());
    pf.by_slot.insert(n.to_string(), uuid);
    profiles::save(&profiles_path, &pf).unwrap();

    // expiresAt 4102444800000 = 2100-01-01 in ms (testing.md Rule 1 — no
    // wall-clock time-bomb). Never validated over the network: bench-mode
    // returns before any spawn, let alone an OAuth call.
    let identity_cred_path = identity_store::credentials_path_for(base, uuid);
    std::fs::create_dir_all(identity_cred_path.parent().unwrap()).unwrap();
    let json = r#"{"claudeAiOauth":{"accessToken":"tok","refreshToken":"rtok","expiresAt":4102444800000,"scopes":[],"tokenType":"Bearer"}}"#;
    std::fs::write(&identity_cred_path, json).unwrap();

    // `create_handle_dir` hard-errors if `config-<N>/` is absent (not
    // actually reached on the bench-mode path, kept for mint-path parity).
    std::fs::create_dir_all(base.join(format!("config-{n}"))).unwrap();
}

/// Recursively copy a directory tree (small, shallow trees only — no
/// symlink handling needed for this fixture).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path);
        } else {
            std::fs::copy(entry.path(), &dst_path).unwrap();
        }
    }
}

/// Overlay the REAL, already-verified `coc-engaged` `.coc/` fixture
/// (`coc-eval/bench/fixtures/coc-engaged/.coc/`, journal
/// `internal-design-docs`) onto `cwd` so the
/// capability layer auto-engages (spec 10 §10.2.2) instead of taking the
/// FR-RUN-04 no-op fast path. Copied at test-time (not duplicated by hand)
/// so this test can never drift from the fixture's actual, loader-verified
/// shape — the same tree `condition3_latency_preflight.py` overlays for real
/// recording runs.
fn write_engaged_coc(cwd: &std::path::Path) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_coc = manifest_dir
        .parent()
        .unwrap()
        .join("coc-eval")
        .join("bench")
        .join("fixtures")
        .join("coc-engaged")
        .join(".coc");
    assert!(
        fixture_coc.is_dir(),
        "coc-engaged fixture .coc/ not found at {fixture_coc:?} — \
         see coc-eval/bench/fixtures/coc-engaged/README.md"
    );
    copy_dir_recursive(&fixture_coc, &cwd.join(".coc"));
}

/// Env-cleared, PATH-stripped command builder. `PATH="/usr/bin:/bin"`
/// deliberately excludes every plausible location for a real
/// `claude`/`codex`/`gemini` binary (Homebrew, `~/.local/bin`, npm global
/// bin, etc.) — if the run still succeeds, no such binary was ever needed.
/// `sandbox_home` becomes `HOME` (not merely `CSQ_BASE_DIR`) — production
/// code (`dirs::home_dir()` in `handle_bench_mode_layer_only`'s
/// `~/.csq/bench-mode-audits.jsonl` write) reads real `HOME` independently
/// of `CSQ_BASE_DIR`; an un-sandboxed `HOME` would leak into the operator's
/// real home (`rules/test-hermeticity.md` MUST-2 shape).
fn zero_cli_cmd(
    sandbox_home: &std::path::Path,
    csq_base_dir: &std::path::Path,
    claude_home: &std::path::Path,
) -> Command {
    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    cmd.env("HOME", sandbox_home);
    cmd.env("PATH", "/usr/bin:/bin");
    for k in &["LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd.env("CSQ_BASE_DIR", csq_base_dir);
    cmd.env("CLAUDE_HOME", claude_home);
    cmd.env("CSQ_BENCH_MODE", "1");
    cmd.env("CSQ_CLI_DEPS_PROBE_DISABLE", "1");
    cmd
}

#[test]
#[cfg(unix)]
fn bench_mode_layer_only_succeeds_with_zero_cli_on_path_and_no_op_coc() {
    let sandbox = TempDir::new().unwrap();
    let base = sandbox.path().join(".claude").join("accounts");
    std::fs::create_dir_all(&base).unwrap();
    let claude_home = sandbox.path().join("claude-home");
    std::fs::create_dir_all(&claude_home).unwrap();
    stage_anthropic_identity_slot(&base, 1);

    // No `.coc/` overlay in this cwd — the layer takes the FR-RUN-04 no-op
    // fast path (`LayerControl::Inherit`, spec 10 §10.2.2). Still
    // zero-spawn, zero-OAuth, zero-keychain.
    let cwd = TempDir::new().unwrap();

    let output = zero_cli_cmd(sandbox.path(), &base, &claude_home)
        .current_dir(cwd.path())
        .args(["run", "1", "--bench-mode", "layer-only", "--print", "x"])
        .output()
        .expect("failed to spawn csq run 1 --bench-mode layer-only");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "bench-mode layer-only must succeed with NO cli on PATH; \
         status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    // `LayerControl::Inherit` (no `.coc/` found) records ONLY the
    // `cap.coc_load.*` resolve attempt — never `cap.layer_total` (that timer
    // wraps the WithLayer classify/scaffold/mcp_gate pipeline, which never
    // runs on the Inherit path). The load itself must succeed (`"applied"`),
    // proving the graceful no-`.coc/` case, not a parse error.
    let coc_load_line = stdout
        .lines()
        .find(|l| l.contains("\"stage_id\":\"cap.coc_load"))
        .unwrap_or_else(|| panic!("expected a cap.coc_load* stage_timing record; got:\n{stdout}"));
    let rec: serde_json::Value = serde_json::from_str(coc_load_line).unwrap();
    assert_eq!(
        rec["result"].as_str(),
        Some("applied"),
        "no-`.coc/` case must resolve gracefully (FR-RUN-04), not error; got:\n{coc_load_line}"
    );
    let elapsed_ns = rec["elapsed_ns"].as_u64().expect("elapsed_ns must be u64");
    // The no-op resolve is bounded with generous headroom for CI jitter —
    // this assertion would fail loudly if a future change accidentally
    // routed this path through a real spawn (which would cost multiple
    // SECONDS, not milliseconds).
    assert!(
        elapsed_ns < 50_000_000,
        "no-op cap.coc_load should be low-single-digit ms at most, \
         got {elapsed_ns}ns — a real CLI spawn would show up as seconds"
    );
    assert!(
        !stdout.contains("\"stage_id\":\"cap.layer_total\""),
        "the Inherit (no .coc/) path must NOT emit cap.layer_total; got:\n{stdout}"
    );
}

#[test]
#[cfg(unix)]
fn bench_mode_layer_only_engages_the_layer_with_zero_cli_on_path() {
    let sandbox = TempDir::new().unwrap();
    let base = sandbox.path().join(".claude").join("accounts");
    std::fs::create_dir_all(&base).unwrap();
    let claude_home = sandbox.path().join("claude-home");
    std::fs::create_dir_all(&claude_home).unwrap();
    stage_anthropic_identity_slot(&base, 1);

    let cwd = TempDir::new().unwrap();
    write_engaged_coc(cwd.path());

    let output = zero_cli_cmd(sandbox.path(), &base, &claude_home)
        .current_dir(cwd.path())
        .args(["run", "1", "--bench-mode", "layer-only", "--print", "x"])
        .output()
        .expect("failed to spawn csq run 1 --bench-mode layer-only");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "bench-mode layer-only must succeed engaged, with NO cli on PATH; \
         status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    // Engaged path emits more stages than the no-op path (coc_load + scaffold
    // + mcp_gate + layer_total, at minimum) — proves the layer actually ran
    // the pipeline against the `.coc/` overlay rather than short-circuiting.
    let stage_ids: Vec<String> = stdout
        .lines()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            if v.get("event")?.as_str()? == "stage_timing" {
                Some(v.get("stage_id")?.as_str()?.to_string())
            } else {
                None
            }
        })
        .collect();
    assert!(
        stage_ids.iter().any(|s| s == "cap.layer_total"),
        "expected cap.layer_total among stage_timing records; got: {stage_ids:?}\nstdout:\n{stdout}"
    );
    assert!(
        stage_ids.iter().any(|s| s.starts_with("cap.coc_load")),
        "engaged .coc/ overlay must produce a cap.coc_load* stage; got: {stage_ids:?}"
    );
}
