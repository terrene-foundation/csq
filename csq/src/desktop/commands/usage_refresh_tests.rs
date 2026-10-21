//! Synthetic desktop-route CPU regression fixtures. Counts are proposed until
//! root runs the actual native tests; no host transcript or credential reads.
#![cfg(unix)]
use super::{aggregate_usage_pairs, refresh_usage_pairs, UsageRefreshState};
use chrono::{DateTime, Duration, Utc};
use csq_core::types::AccountNum;
use csq_core::usage::aggregator::{transcript_test_support::observe, PassKind, SlimLedger};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

const COHORT_FILES: usize = 21_000;
const CHILD_FILES: usize = 20;
const SLOT: u16 = 4;
const CWD: &str = "/synthetic/cpu-fixture";
const MODELS: [&str; 2] = ["claude-sonnet-5", "claude-opus-4-8"];

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-14T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}
fn timestamp(index: usize) -> String {
    (now() - Duration::days([40, 20, 6, 4, 0][index % 5])).to_rfc3339()
}
fn row(index: usize, tokens: [u64; 4]) -> String {
    serde_json::json!({"type":"assistant", "cwd":CWD, "timestamp":timestamp(index),
        "sessionId":format!("s{index}"), "requestId":format!("r{index}"),
        "message":{"id":format!("m{index}"), "model":MODELS[index % 2],
            "usage":{"input_tokens":tokens[0], "output_tokens":tokens[1],
                "cache_creation_input_tokens":tokens[2], "cache_read_input_tokens":tokens[3]}}})
    .to_string()
}
fn manifest_bytes(scale: f64) -> Vec<u8> {
    let mut manifest =
        serde_json::to_value(csq_core::providers::model_manifest::ModelManifest::bundled())
            .unwrap();
    let boundary = DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
        .unwrap()
        .timestamp();
    manifest["rates"] = serde_json::Value::Array(MODELS.iter().enumerate().map(|(index, model)| {
        let model_factor = (index + 1) as f64;
        let epoch = |start, end, factor| serde_json::json!({"start_unix":start,"end_unix":end,"peak":null,
            "rate":{"input_per_1m_usd":2.0*factor*model_factor*scale,
                "output_per_1m_usd":4.0*factor*model_factor*scale,
                "cache_write_per_1m_usd":6.0*factor*model_factor*scale,
                "cache_read_per_1m_usd":factor*model_factor*scale}});
        serde_json::json!({"match_kind":"exact","patterns":[model],"strip_context_hint":false,
            "epochs":[epoch(None,Some(boundary),1.0),epoch(Some(boundary),None,3.0)],
            "evidence":"Owned synthetic rates, not vendor pricing"})
    }).collect());
    serde_json::to_vec(&manifest).unwrap()
}
struct Corpus {
    _root: tempfile::TempDir,
    base: PathBuf,
    files: Vec<PathBuf>,
}
impl Corpus {
    fn create(count: usize, children: usize) -> Self {
        assert!(count > children);
        let root = tempfile::TempDir::new().unwrap();
        let home = root.path().join(".claude");
        let base = home.join("accounts");
        let project = home.join("projects/-synthetic-cpu");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::write(base.join("model-rates.json"), manifest_bytes(1.0)).unwrap();
        csq_core::usage::launch_log::append(
            &base,
            &csq_core::usage::launch_log::LaunchEvent {
                ts: "2026-07-01T00:00:00Z".into(),
                event: "run".into(),
                slot: SLOT,
                pid: 1,
                project_path: CWD.into(),
            },
        )
        .unwrap();
        let mut files = Vec::with_capacity(count);
        for index in 0..count {
            let path = if index < count - children {
                project.join(format!("s{index}.jsonl"))
            } else {
                let sub = project.join("s0/subagents");
                fs::create_dir_all(&sub).unwrap();
                sub.join(format!("child-{index}.jsonl"))
            };
            fs::write(&path, format!("{}\n", row(index, [100, 7, 3, 5]))).unwrap();
            files.push(path);
        }
        Self {
            _root: root,
            base,
            files,
        }
    }
    // A semantic no-op in pricing with a different stat size forces actual
    // outer Full. Merely obtaining PassKind::Reused cannot prove this repair.
    fn force_full(&self) {
        fs::OpenOptions::new()
            .append(true)
            .open(self.base.join("model-rates.json"))
            .unwrap()
            .write_all(b"\n")
            .unwrap();
    }
    fn reference(&self) -> Vec<(AccountNum, csq_core::usage::ledger::UsageEvent)> {
        aggregate_usage_pairs(&self.base, now()).unwrap()
    }
}
fn assert_reference(
    pairs: &SlimLedger,
    reference: &[(AccountNum, csq_core::usage::ledger::UsageEvent)],
) {
    assert_eq!(*pairs, SlimLedger::from_pairs(reference));
    let slot = AccountNum::try_from(SLOT).unwrap();
    let events = reference
        .iter()
        .filter(|(account, _)| *account == slot)
        .map(|(_, event)| event.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        pairs.summarize_slot(slot, now()),
        csq_core::usage::ledger::summarize(&events, now())
    );
    assert_eq!(
        pairs
            .summarize_slot(AccountNum::try_from(7u16).unwrap(), now())
            .event_count,
        0
    );
}
fn assert_zero_content(counts: csq_core::usage::aggregator::transcript_test_support::Counts) {
    assert_eq!(
        counts.read_calls, 0,
        "forced outer Full must not read unchanged admitted transcripts"
    );
    assert_eq!(
        counts.read_bytes, 0,
        "forced outer Full must return zero transcript bytes"
    );
    assert_eq!(
        counts.parses, 0,
        "forced outer Full must perform zero transcript deserializations"
    );
}

#[cfg(unix)]
#[test]
fn desktop_cpu_21000_files_admitted_and_forced_full_matches_accounting() {
    let _env = csq_core::platform::test_env::lock();
    let corpus = Corpus::create(COHORT_FILES, CHILD_FILES);
    let reference = corpus.reference(); // Deliberately outside the measured route.
    assert_eq!(reference.len(), COHORT_FILES);
    assert!(reference.iter().all(|(slot, _)| slot.get() == SLOT));
    for (_, event) in &reference {
        assert_eq!(
            [
                event.input_tokens,
                event.output_tokens,
                event.cache_creation_tokens,
                event.cache_read_tokens
            ],
            [100, 7, 3, 5]
        );
        let time = DateTime::parse_from_rfc3339(&event.ts).unwrap();
        let epoch = if time.timestamp()
            < DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
                .unwrap()
                .timestamp()
        {
            1.0
        } else {
            3.0
        };
        let model = if event.model == MODELS[0] {
            1.0
        } else {
            assert_eq!(event.model, MODELS[1]);
            2.0
        };
        let expected = (100.0 * 2.0 + 7.0 * 4.0 + 3.0 * 6.0 + 5.0) * epoch * model / 1_000_000.0;
        assert!(
            (event.cost_usd_estimate.unwrap() - expected).abs() < 1e-12,
            "per-request synthetic historical price must match independently derived rates"
        );
    }
    let mut state = UsageRefreshState::default();
    let (cold, cold_counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (pairs, kind) = cold.unwrap();
    assert_eq!(kind, PassKind::Full);
    assert!(
        cold_counts.read_calls > 0
            && cold_counts.read_bytes > 0
            && cold_counts.parses >= COHORT_FILES
    );
    let retained = state.scanner.test_cache_observation();
    assert_eq!(
        retained.files,
        corpus.files.len(),
        "actual desktop scanner must admit every one of the 21000 fixture files"
    );
    assert_eq!(retained.file_limit, 32768);
    assert_eq!(retained.seen, corpus.files.len());
    assert_eq!(retained.records, COHORT_FILES);
    assert!(retained.records <= 65536 && retained.payload_bytes <= 32 * 1024 * 1024);
    assert_reference(&pairs, &reference);
    let summary = pairs.summarize_slot(AccountNum::try_from(SLOT).unwrap(), now());
    assert_eq!(
        (summary.event_count, summary.request_count),
        (COHORT_FILES as u64, COHORT_FILES as u64)
    );
    assert_eq!(summary.subagent_request_count, CHILD_FILES as u64);
    assert_eq!(
        (
            summary.duplicate_snapshots_collapsed,
            summary.finalization_divergent_requests,
            summary.unidentified_request_count,
            summary.unestimated_cost_count
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        [
            summary.total_input_tokens,
            summary.total_output_tokens,
            summary.total_cache_creation_tokens,
            summary.total_cache_read_tokens
        ],
        [2_100_000, 147_000, 63_000, 105_000]
    );
    for (events, dimensions) in [
        (
            16800,
            [
                summary.last_30d_input_tokens,
                summary.last_30d_output_tokens,
                summary.last_30d_cache_creation_tokens,
                summary.last_30d_cache_read_tokens,
            ],
        ),
        (
            12600,
            [
                summary.last_7d_input_tokens,
                summary.last_7d_output_tokens,
                summary.last_7d_cache_creation_tokens,
                summary.last_7d_cache_read_tokens,
            ],
        ),
        (
            8400,
            [
                summary.last_5d_input_tokens,
                summary.last_5d_output_tokens,
                summary.last_5d_cache_creation_tokens,
                summary.last_5d_cache_read_tokens,
            ],
        ),
        (
            4200,
            [
                summary.today_input_tokens,
                summary.today_output_tokens,
                summary.today_cache_creation_tokens,
                summary.today_cache_read_tokens,
            ],
        ),
    ] {
        assert_eq!(
            dimensions,
            [events * 100, events * 7, events * 3, events * 5]
        );
    }
    for (actual, expected) in [
        (summary.total_cost_usd, 17.3943),
        (summary.last_30d_cost_usd, 15.813),
        (summary.last_7d_cost_usd, 14.2317),
        (summary.last_5d_cost_usd, 9.4878),
        (summary.today_cost_usd, 4.7439),
    ] {
        assert!(
            (actual - expected).abs() < 1e-8,
            "independent synthetic historical-price window total"
        );
    }
    corpus.force_full();
    let (warm, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (warm, kind) = warm.unwrap();
    assert_eq!(
        kind,
        PassKind::Full,
        "warm oracle must run actual outer aggregate closure"
    );
    assert_zero_content(counts);
    assert_reference(&warm, &reference);
    assert_eq!(state.scanner.test_cache_observation(), retained);
}

#[cfg(unix)]
#[test]
fn desktop_cpu_forced_full_unchanged_performs_zero_reads_and_parses() {
    let _env = csq_core::platform::test_env::lock();
    let corpus = Corpus::create(3, 0);
    let mut state = UsageRefreshState::default();
    let reference = corpus.reference();
    let (cold, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    assert_eq!(cold.unwrap().1, PassKind::Full);
    assert!(counts.read_bytes > 0 && counts.parses > 0);
    corpus.force_full();
    let (warm, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (warm, kind) = warm.unwrap();
    assert_eq!(kind, PassKind::Full);
    assert_zero_content(counts);
    assert_reference(&warm, &reference);
}

#[cfg(unix)]
#[test]
fn desktop_cpu_append_reads_only_tail_and_watermarks_with_exact_finalization() {
    let _env = csq_core::platform::test_env::lock();
    let corpus = Corpus::create(2, 0);
    let path = &corpus.files[0];
    let ignored = format!(
        "{{\"type\":\"progress\",\"padding\":\"{}\"}}\n",
        "x".repeat(4096)
    );
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    for _ in 0..256 {
        file.write_all(ignored.as_bytes()).unwrap();
    }
    drop(file);
    let original_bytes = fs::metadata(path).unwrap().len();
    assert!(original_bytes > 1_048_576);
    let mut state = UsageRefreshState::default();
    refresh_usage_pairs(&mut state, &corpus.base, now()).unwrap();
    let append = format!("{}\n", row(0, [80, 9, 2, 1]));
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(append.as_bytes())
        .unwrap();
    let reference = corpus.reference();
    let (updated, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (updated, kind) = updated.unwrap();
    assert_eq!(kind, PassKind::Full);
    assert_eq!(
        counts.parses, 1,
        "unchanged complete prefix and other file must not be reparsed"
    );
    assert!(counts.read_bytes > 0);
    assert!(
        counts.read_bytes <= append.len() + 8192,
        "actual transcript reads must remain within appended tail plus two bounded watermark reads"
    );
    assert!(
        (counts.read_bytes as u64) < original_bytes,
        "large old transcript prefix must not be reread"
    );
    assert_reference(&updated, &reference);
    let summary = updated.summarize_slot(AccountNum::try_from(SLOT).unwrap(), now());
    assert_eq!(
        (
            summary.request_count,
            summary.duplicate_snapshots_collapsed,
            summary.finalization_divergent_requests
        ),
        (2, 1, 1)
    );
    assert_eq!(
        [
            summary.total_input_tokens,
            summary.total_output_tokens,
            summary.total_cache_creation_tokens,
            summary.total_cache_read_tokens
        ],
        [180, 16, 5, 6]
    );
}

#[cfg(unix)]
#[test]
fn desktop_cpu_base_switch_and_manifest_error_cannot_reuse_foreign_or_stale_result() {
    let _env = csq_core::platform::test_env::lock();
    let a = Corpus::create(2, 0);
    let b = Corpus::create(3, 0);
    fs::write(&b.files[0], format!("{}\n", row(0, [900, 9, 8, 7]))).unwrap();
    let mut state = UsageRefreshState::default();
    for corpus in [&a, &b, &a] {
        let reference = corpus.reference();
        let (result, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
        let (pairs, kind) = result.unwrap();
        assert_eq!(kind, PassKind::Full);
        assert!(
            counts.read_bytes > 0,
            "return to prior base must cold-acquire its own files"
        );
        assert_eq!(state.base.as_deref(), Some(corpus.base.as_path()));
        assert_eq!(
            state.scanner.test_cache_observation().files,
            corpus.files.len()
        );
        assert_reference(&pairs, &reference);
    }
    fs::write(a.base.join("model-rates.json"), b"not a model manifest").unwrap();
    for _ in 0..2 {
        let (error, counts) = observe(|| refresh_usage_pairs(&mut state, &a.base, now()));
        assert!(
            error.unwrap_err().starts_with("MODEL_MANIFEST:"),
            "manifest error cannot become old or empty success"
        );
        assert_zero_content(counts);
    }
    fs::write(a.base.join("model-rates.json"), manifest_bytes(2.0)).unwrap();
    let reference = a.reference();
    let (restored, counts) = observe(|| refresh_usage_pairs(&mut state, &a.base, now()));
    let (restored, kind) = restored.unwrap();
    assert_eq!(
        kind,
        PassKind::Full,
        "failed outer pass must release successful result before recovery"
    );
    assert_zero_content(counts);
    assert_reference(&restored, &reference);
}

#[test]
fn desktop_cpu_partial_eof_completion_and_cold_validation_match_reference() {
    let _env = csq_core::platform::test_env::lock();
    let corpus = Corpus::create(1, 0);
    let path = &corpus.files[0];
    let complete = format!("{}\n", row(0, [100, 7, 3, 5]));
    let speculative = row(1, [200, 8, 4, 6]);
    fs::write(path, format!("{complete}{speculative}")).unwrap();
    let mut state = UsageRefreshState::default();
    let reference = corpus.reference();
    let (first, _) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    assert_reference(&first.unwrap().0, &reference);
    assert_eq!(
        reference.len(),
        2,
        "valid speculative EOF usage remains billable"
    );
    let appended = format!("\n{}\n", row(2, [300, 9, 5, 7]));
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(appended.as_bytes())
        .unwrap();
    let reference = corpus.reference();
    let (result, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (pairs, kind) = result.unwrap();
    assert_eq!(kind, PassKind::Full);
    assert_reference(&pairs, &reference);
    assert_eq!(
        counts.parses, 2,
        "old speculative tail is retried, then only new complete row is parsed"
    );
    assert!(counts.read_bytes <= speculative.len() + appended.len() + 8192);
    let summary = pairs.summarize_slot(AccountNum::try_from(SLOT).unwrap(), now());
    assert_eq!(
        (summary.request_count, summary.duplicate_snapshots_collapsed),
        (3, 0)
    );
    assert_eq!(
        [
            summary.total_input_tokens,
            summary.total_output_tokens,
            summary.total_cache_creation_tokens,
            summary.total_cache_read_tokens
        ],
        [600, 24, 12, 18]
    );
    state.scanner.test_expire_validation();
    corpus.force_full();
    let (cold, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (cold, kind) = cold.unwrap();
    assert_eq!(kind, PassKind::Full);
    assert!(
        counts.read_bytes > 0 && counts.parses >= 3,
        "expired unchanged projection must perform actual cold read and parsing"
    );
    assert_reference(&cold, &reference);
}

#[test]
fn desktop_cpu_removal_and_symlink_exclusion_prune_retained_inputs() {
    let _env = csq_core::platform::test_env::lock();
    let corpus = Corpus::create(2, 0);
    let mut state = UsageRefreshState::default();
    let (first, _) = refresh_usage_pairs(&mut state, &corpus.base, now()).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(state.scanner.test_cache_observation().files, 2);
    let canary = corpus._root.path().join("excluded-canary.jsonl");
    fs::write(
        &canary,
        format!("{}\n", row(99, [99999, 99999, 99999, 99999])),
    )
    .unwrap();
    fs::remove_file(&corpus.files[0]).unwrap();
    fs::remove_file(&corpus.files[1]).unwrap();
    std::os::unix::fs::symlink(&canary, &corpus.files[1]).unwrap();
    corpus.force_full();
    let reference = corpus.reference();
    assert!(reference.is_empty());
    let (result, counts) = observe(|| refresh_usage_pairs(&mut state, &corpus.base, now()));
    let (pairs, kind) = result.unwrap();
    assert_eq!(kind, PassKind::Full);
    assert_reference(&pairs, &reference);
    assert_zero_content(counts);
    let retained = state.scanner.test_cache_observation();
    assert_eq!(
        (
            retained.files,
            retained.seen,
            retained.records,
            retained.payload_bytes
        ),
        (0, 0, 0, 0),
        "removed and excluded nodes must not retain stale projection payload"
    );
    assert!(fs::read(&canary)
        .unwrap()
        .windows(5)
        .any(|bytes| bytes == b"99999"));
}
