//! Instrument tests only. The externally delivered corpus has not arrived.
//! See fixtures/hook_corpus_equivalence/README.md for the opt-in runner contract.
//! Native-only: every case spawns `/bin/sh`, so the whole target is gated here rather than
//! per item (per-item gates left the shared support modules unused, and red, on Windows).
#![cfg(any(target_os = "linux", target_os = "macos"))]
// The fixture root resolves through the `test-utils`-gated
// `csq_core::testing::manifest_dir`. Gated here rather than with
// `required-features` (same convention as `auto_rotate_integration.rs`) so a
// plain `cargo test -p csq-core` builds this as an empty test binary instead of
// failing to compile on an unresolved import. CI and the local sign-off always
// pass `csq-core/test-utils`.
#![cfg(feature = "test-utils")]
#[path = "support/hook_corpus_equivalence/model.rs"]
mod model;
#[path = "support/hook_corpus_equivalence/runner.rs"]
mod runner;
#[path = "support/hook_corpus_equivalence/strict_json.rs"]
mod strict_json;
use model::*;
use std::path::PathBuf;
use std::{collections::BTreeMap, fs, path::Path};

fn fixture_root() -> PathBuf {
    csq_core::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hook_corpus_equivalence")
}
fn instrument_corpus(left: &str, right: &str, decision: Decision) -> Corpus {
    let shell = "/bin/sh";
    let program_sha256 = hash(&read_bounded(Path::new(shell), 128 * 1024 * 1024).unwrap());
    let arm = |mode: &str| Arm {
        program: shell.into(),
        program_sha256: program_sha256.clone(),
        args: vec![
            "${CORPUS_ROOT}/control.sh".into(),
            mode.into(),
            "${CASE_ROOT}".into(),
        ],
    };
    Corpus {
        format: 1,
        release: "instrument-controls-v1".into(),
        source_revision: "synthetic-instrument-only".into(),
        profile: "verdict_output_v1".into(),
        files: vec![Binding {
            path: "control.sh".into(),
            sha256: hash(&fs::read(fixture_root().join("control.sh")).unwrap()),
        }],
        cases: vec![Case {
            id: "control-1".into(),
            stdin: "payload\n".into(),
            timeout_ms: 500,
            initial_files: BTreeMap::from([("seed.txt".into(), "frozen\n".into())]),
            standalone: arm(left),
            dispatched: arm(right),
            expected: Expected {
                exit_code: 0,
                observation: Observation {
                    decision,
                    context: vec![],
                    rewrite: None,
                },
                stderr: "".into(),
            },
        }],
    }
}
fn measure(corpus: &Corpus) -> Report {
    runner::run(
        corpus,
        &hash(&serde_json::to_vec(corpus).unwrap()),
        &fixture_root(),
        "cargo test -p csq-core --test hook_corpus_equivalence (instrument controls only)",
    )
    .unwrap()
}

#[test]
fn allow_and_deny_require_both_arms_and_independent_oracle() {
    for (mode, decision) in [("allow", Decision::Allow), ("deny", Decision::Deny)] {
        let report = measure(&instrument_corpus(mode, mode, decision));
        assert!(report.protocol_equivalent, "{report:?}");
        assert_eq!(
            (
                report.required_cases,
                report.attempted_cases,
                report.completed_cases
            ),
            (1, 1, 1)
        );
        assert_eq!(
            (report.planned_invocations, report.attempted_invocations),
            (2, 2)
        );
        assert_eq!(report.spawned_invocations, 2);
        assert_eq!(
            (
                report.oracle_conformant_cases,
                report.differential_matched_cases
            ),
            (1, 1)
        );
        assert!(!report.full_corpus_qualified);
        assert!(report
            .pairs
            .iter()
            .all(|p| p.standalone.problem.is_none() && p.dispatched.problem.is_none()));
    }
}
#[test]
fn both_wrong_cannot_pass_even_when_differential_matches() {
    let report = measure(&instrument_corpus("allow", "allow", Decision::Deny));
    assert_eq!(report.differential_matched_cases, 1);
    assert_eq!(report.oracle_conformant_cases, 0);
    assert_eq!(report.completed_cases, 1);
    assert!(!report.protocol_equivalent);
}
#[test]
fn candidate_allow_against_denial_is_detected() {
    let report = measure(&instrument_corpus("deny", "allow", Decision::Deny));
    assert_eq!(report.differential_matched_cases, 0);
    assert_eq!(report.oracle_conformant_cases, 0);
    assert!(!report.protocol_equivalent);
}
#[test]
fn missing_population_or_arm_and_unknown_case_cannot_pass() {
    let mut corpus = instrument_corpus("allow", "allow", Decision::Allow);
    corpus.cases.clear();
    assert_eq!(validate(&corpus).unwrap_err(), "invalid_population");
    let mut corpus = instrument_corpus("allow", "allow", Decision::Allow);
    corpus.cases.push(corpus.cases[0].clone());
    assert_eq!(validate(&corpus).unwrap_err(), "invalid_case");
    let mut value =
        serde_json::to_value(instrument_corpus("allow", "allow", Decision::Allow)).unwrap();
    value["cases"][0]
        .as_object_mut()
        .unwrap()
        .remove("dispatched");
    assert!(serde_json::from_value::<Corpus>(value).is_err());
    let mut value =
        serde_json::to_value(instrument_corpus("allow", "allow", Decision::Allow)).unwrap();
    value["cases"][0]["unrecognised_requirement"] = true.into();
    assert!(serde_json::from_value::<Corpus>(value).is_err());
}
#[test]
fn corpus_and_closure_tamper_fail_before_dispatch() {
    let temp = tempfile::TempDir::new().unwrap();
    let path = temp.path().join("corpus.json");
    let mut corpus = instrument_corpus("allow", "allow", Decision::Allow);
    let bytes = serde_json::to_vec(&corpus).unwrap();
    fs::write(&path, &bytes).unwrap();
    let pin = hash(&bytes);
    assert_eq!(load(&path, &pin).unwrap().1, pin);
    assert_eq!(
        load(&path, &"0".repeat(64)).unwrap_err(),
        "corpus_pin_mismatch"
    );
    fs::write(&path, b"{} ").unwrap();
    assert_eq!(load(&path, &pin).unwrap_err(), "corpus_pin_mismatch");
    corpus.files[0].sha256 = "0".repeat(64);
    assert_eq!(
        runner::run(&corpus, &pin, &fixture_root(), "instrument").unwrap_err(),
        "binding_pin_mismatch"
    );
    assert_eq!(
        load(&temp.path().join("missing"), &pin).unwrap_err(),
        "file_missing"
    );
}
#[test]
fn executable_tamper_and_missing_process_never_pass() {
    let mut corpus = instrument_corpus("allow", "allow", Decision::Allow);
    corpus.cases[0].dispatched.program_sha256 = "0".repeat(64);
    let report = measure(&corpus);
    assert_eq!(
        report.pairs[0].dispatched.problem.as_deref(),
        Some("program_pin_mismatch")
    );
    assert_eq!(
        (
            report.attempted_cases,
            report.completed_cases,
            report.unsupported_cases
        ),
        (1, 0, 0)
    );
    assert!(!report.protocol_equivalent);
    corpus.cases[0].dispatched.program = "/fixture-program-does-not-exist".into();
    let report = measure(&corpus);
    assert_eq!(
        report.pairs[0].dispatched.problem.as_deref(),
        Some("file_missing")
    );
    assert!(!report.protocol_equivalent);
    assert_eq!(report.spawned_invocations, 1);
}
#[test]
fn nested_rewrite_and_fixture_duplicate_keys_cannot_be_normalized_into_pass() {
    let mut corpus = instrument_corpus("rewrite", "rewrite", Decision::Allow);
    corpus.cases[0].expected.observation.rewrite = Some(serde_json::json!({"a":2}));
    assert!(measure(&corpus).protocol_equivalent);
    corpus.cases[0].standalone.args[1] = "duplicate-rewrite".into();
    corpus.cases[0].dispatched.args[1] = "duplicate-rewrite".into();
    let report = measure(&corpus);
    assert_eq!(
        (
            report.oracle_conformant_cases,
            report.differential_matched_cases
        ),
        (0, 0)
    );
    assert!(!report.protocol_equivalent);
    let valid = serde_json::to_string(&corpus).unwrap();
    let malformed = valid.replace(
        "\"initial_files\":{\"seed.txt\":\"frozen\\n\"}",
        "\"initial_files\":{\"seed.txt\":\"poisoned\",\"seed.txt\":\"frozen\\n\"}",
    );
    assert_ne!(valid, malformed); // proves the mutation reached the parser input.
    let temp = tempfile::TempDir::new().unwrap();
    let path = temp.path().join("duplicates.json");
    fs::write(&path, malformed.as_bytes()).unwrap();
    assert_eq!(
        load(&path, &hash(malformed.as_bytes())).unwrap_err(),
        "manifest_shape"
    );
}
#[test]
fn malformed_duplicate_and_unknown_verdicts_fail_even_when_equal() {
    for mode in ["malformed", "duplicate", "unknown"] {
        let report = measure(&instrument_corpus(mode, mode, Decision::Allow));
        assert_eq!(report.oracle_conformant_cases, 0, "{mode}");
        assert_eq!(report.differential_matched_cases, 0, "{mode}");
        assert!(!report.protocol_equivalent, "{mode}");
    }
}
#[test]
fn stdout_stderr_and_timeout_are_bounded_not_skipped() {
    let report = measure(&instrument_corpus("allow", "stderr", Decision::Allow));
    assert_eq!(report.pairs[0].dispatched.stderr, b"diagnostic\n");
    assert!(!report.protocol_equivalent);
    for (mode, problem) in [("hang", "timeout"), ("flood", "output_limit")] {
        let mut corpus = instrument_corpus(mode, mode, Decision::Allow);
        corpus.cases[0].timeout_ms = 100;
        let report = measure(&corpus);
        assert_eq!(
            (
                report.attempted_cases,
                report.completed_cases,
                report.unsupported_cases
            ),
            (1, 0, 0)
        );
        for captured in [&report.pairs[0].standalone, &report.pairs[0].dispatched] {
            assert_eq!(captured.problem.as_deref(), Some(problem));
            assert!(captured.stdout.len() <= MAX_BYTES);
            assert!(
                captured.elapsed_ms < 4000,
                "bounded process supervision: {captured:?}"
            );
        }
        assert!(!report.protocol_equivalent);
    }
}
#[test]
fn inherited_pipe_cannot_stall_completed_leader() {
    let mut corpus = instrument_corpus("inherited-pipe", "inherited-pipe", Decision::Allow);
    corpus.cases[0].timeout_ms = 300;
    let report = measure(&corpus);
    assert!(
        !report.protocol_equivalent,
        "forced descendant cleanup cannot pass: {report:?}"
    );
    assert_eq!(report.completed_cases, 0);
    assert_eq!(
        report.pairs[0].standalone.problem.as_deref(),
        Some("forced_cleanup")
    );
    assert!(report.pairs[0].standalone.forced_cleanup);
    assert!(report.pairs[0].standalone.elapsed_ms < 4000);
    assert!(!report.full_corpus_qualified); // no escaped-descendant/effect observer claim.
}
#[test]
fn unsupported_required_profile_retains_denominator_and_zero_execution() {
    let mut corpus = instrument_corpus("allow", "allow", Decision::Allow);
    corpus.profile = "required-effects-observer-v1".into();
    let report = measure(&corpus);
    assert_eq!(
        (
            report.required_cases,
            report.unsupported_cases,
            report.attempted_cases
        ),
        (1, 1, 0)
    );
    assert_eq!(
        (report.planned_invocations, report.attempted_invocations),
        (2, 0)
    );
    assert!(!report.protocol_equivalent);
    assert!(!report.full_corpus_qualified);
}

/// Explicit prerequisite skip: this repo does not carry the owner-delivered corpus.
/// Re-enable with --ignored --exact supplied_corpus_matches_frozen_oracle.
#[cfg(feature = "test-utils")]
#[test]
#[ignore = "requires explicitly supplied trusted owner corpus and independent SHA256 pin; see fixture README"]
fn supplied_corpus_matches_frozen_oracle() {
    let _env = csq_core::platform::test_env::lock();
    let path = PathBuf::from(
        std::env::var_os("CSQ_HOOK_EQUIVALENCE_CORPUS").expect("corpus path required"),
    );
    let pin =
        std::env::var("CSQ_HOOK_EQUIVALENCE_SHA256").expect("independent corpus pin required");
    let (corpus, digest) = load(&path, &pin).expect("pinned corpus admission");
    let report = runner::run(&corpus, &digest, path.parent().expect("corpus directory"),
        "cargo test -p csq-core --features test-utils --test hook_corpus_equivalence -- --ignored --exact supplied_corpus_matches_frozen_oracle --nocapture")
        .expect("corpus source closure admission");
    println!("{}", serde_json::to_string(&report).expect("report"));
    assert!(
        report.protocol_equivalent,
        "corpus protocol/oracle comparison failed; see retained capture report"
    );
}
