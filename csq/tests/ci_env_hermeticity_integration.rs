//! Guard: subprocess tests are isolated from the parent's CI environment, and
//! the isolation is sourced from the production CI detector's own list.
//!
//! `csq cli install/upgrade` refuses interactive consent when any variable in
//! `csq_core::env::CI_SENTINEL_VARS` is set. The cli_deps / login subprocess
//! tests must therefore never pass one to the child, whatever the parent (a
//! CI runner, a fleet worker) exports.
//!
//! Falsifiers: removing the loop in `common::strip_ci_env` reds the first two
//! tests; adding a CI variable to `TRACK_LATEST_CI_VARS` or the `csq probe`
//! check without adding it to `CI_SENTINEL_VARS` reds the third; re-inlining a
//! private list in `cli.rs::is_ci_environment` reds the fourth.

#[path = "common/mod.rs"]
mod common;

use std::process::Command;

use csq_core::env::CI_SENTINEL_VARS;

#[test]
fn strip_ci_env_removes_every_detector_variable() {
    let mut cmd = Command::new("true");
    for v in CI_SENTINEL_VARS {
        cmd.env(v, "1");
    }
    common::strip_ci_env(&mut cmd);
    for v in CI_SENTINEL_VARS {
        let state = cmd.get_envs().find(|(k, _)| k == v).map(|(_, val)| val);
        assert_eq!(
            state,
            Some(None),
            "{v} must be explicitly removed from the child env"
        );
    }
}

#[cfg(unix)]
#[test]
fn child_sees_no_ci_variable_after_strip() {
    let mut cmd = Command::new("env");
    cmd.env_clear();
    // Simulate a re-injection ahead of the strip, as a parent-env pass-through
    // loop would do; the strip must win.
    for v in CI_SENTINEL_VARS {
        cmd.env(v, "true");
    }
    // PATH is needed to resolve `env` itself on some hosts; it is not a CI var.
    if let Ok(p) = std::env::var("PATH") {
        cmd.env("PATH", p);
    }
    common::strip_ci_env(&mut cmd);
    let out = cmd.output().expect("spawn env");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for v in CI_SENTINEL_VARS {
        assert!(
            !stdout.lines().any(|l| l.starts_with(&format!("{v}="))),
            "child still sees {v}:\n{stdout}"
        );
    }
}

/// Quoted string literals inside the first `[ ... ];` after `anchor`.
fn quoted_after(src: &str, anchor: &str) -> Vec<String> {
    let start = src
        .find(anchor)
        .unwrap_or_else(|| panic!("{anchor} not found"));
    let rest = &src[start..];
    let end = rest.find("];").expect("slice end");
    rest[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn other_production_ci_detectors_are_covered_by_the_shared_list() {
    let gate = include_str!("../src/cli/commands/cli_deps_gate.rs");
    let vars = quoted_after(gate, "const TRACK_LATEST_CI_VARS");
    assert!(!vars.is_empty(), "parsed no TRACK_LATEST_CI_VARS entries");
    // `csq probe` (probe.rs) reads CI and GITHUB_ACTIONS directly.
    for v in vars
        .iter()
        .map(String::as_str)
        .chain(["CI", "GITHUB_ACTIONS"])
    {
        assert!(
            CI_SENTINEL_VARS.contains(&v),
            "production reads {v} as a CI sentinel but it is missing from \
             csq_core::env::CI_SENTINEL_VARS, so tests would not strip it"
        );
    }
}

#[test]
fn consent_detector_iterates_the_shared_list_not_a_private_copy() {
    let cli = include_str!("../src/cli/commands/cli.rs");
    let at = cli.find("fn is_ci_environment()").expect("detector");
    let end = cli[at..].find("\n}\n").expect("fn end") + at;
    let body = &cli[at..end];
    assert!(
        body.contains("CI_SENTINEL_VARS"),
        "is_ci_environment must iterate csq_core::env::CI_SENTINEL_VARS:\n{body}"
    );
    assert!(
        !body.contains("\"GITHUB_ACTIONS\""),
        "is_ci_environment must not carry a private variable list:\n{body}"
    );
}
