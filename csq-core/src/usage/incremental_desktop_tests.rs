//! Real file/read/deserialize oracles; desktop route coverage lives in csq companion.
use super::*;
use tempfile::TempDir;

fn line(id: &str, output: u64) -> String {
    serde_json::json!({"cwd":"/work/cpu", "sessionId":"cpu", "timestamp":"2026-09-14T11:00:00Z",
        "requestId":id, "message":{"model":"claude-sonnet-5", "usage":{"input_tokens":10,
        "output_tokens":output,"cache_creation_input_tokens":3,"cache_read_input_tokens":7}}})
    .to_string()
}

fn scan(scanner: &mut IncrementalScanner, path: &Path) -> Option<ScannedSession> {
    scanner.scan(path, false, None, &mut ScanSkips::default())
}

fn reference(path: &Path) -> Option<ScannedSession> {
    scan_one_transcript(path, false, None, &mut ScanSkips::default())
}

fn assert_retained(scanner: &IncrementalScanner) {
    let actual = scanner
        .files
        .values()
        .fold(CacheFootprint::default(), |sum, c| {
            sum.add(c.parsed.footprint())
        });
    assert_eq!(
        actual, scanner.retained,
        "retention accounting must match actual allocated projections"
    );
    assert!(actual.records <= INCREMENTAL_RECORD_CAP);
    assert!(actual.bytes <= INCREMENTAL_PAYLOAD_BYTE_CAP);
    assert!(scanner.files.len() <= scanner.file_cap);
    assert!(scanner.seen.len() <= scanner.file_cap);
}

#[cfg(unix)]
const CTIME_ADVANCE_MUTATION_CAP: usize = 10_000;

/// Filesystem ctime is stamped from the kernel's coarse clock, which is
/// updated once per timer tick (measured ~1 ms on the Linux CI host): a
/// mutation performed within the same tick as the stamp it replaces observes a
/// bit-identical ctime, so one rewrite plus `set_modified` restore cannot
/// establish the change premise on every host. Re-issue that mutation —
/// same-size rewrite and explicit mtime restore, exactly what this test is
/// about — until the kernel's ctime observation actually advances. Every
/// iteration is a real mutation, not a wait; the coarse clock advances
/// monotonically, so the distinct observation arrives in bounded time, and the
/// cap turns a broken premise into a loud assertion instead of an endless loop.
#[cfg(unix)]
fn mutate_until_ctime_advances(path: &Path, old: &FileStamp, content: &str) -> FileStamp {
    let restore = old
        .modified
        .expect("premise: the mutated file carries an mtime to restore");
    let mut new = FileStamp::of(&std::fs::metadata(path).unwrap());
    let mut mutations = 0;
    while new.changed == old.changed {
        mutations += 1;
        assert!(
            mutations <= CTIME_ADVANCE_MUTATION_CAP,
            "kernel ctime observation never advanced across {mutations} mutations"
        );
        std::fs::write(path, content).unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(restore)
            .unwrap();
        new = FileStamp::of(&std::fs::metadata(path).unwrap());
    }
    new
}

#[test]
fn desktop_profile_keeps_daemon_file_limit_and_shared_record_payload_bounds() {
    let daemon = IncrementalScanner::default();
    let desktop = IncrementalScanner::for_desktop();
    assert_eq!(daemon.file_cap, 4096);
    assert_eq!(desktop.file_cap, 32_768);
    for scanner in [daemon, desktop] {
        assert_eq!(scanner.budget.records, 65_536);
        assert_eq!(scanner.budget.bytes, 32 * 1024 * 1024);
        assert_retained(&scanner);
    }
}

#[cfg(unix)]
#[test]
fn desktop_observations_include_complete_parser_and_unchanged_admission() {
    let _env = crate::platform::test_env::lock();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("usage.jsonl");
    std::fs::write(&path, format!("{}\n", line("r", 1))).unwrap();
    let (full, counts) = transcript_test_support::observe(|| reference(&path));
    assert!(counts.read_calls > 0 && counts.read_bytes > 0);
    assert_eq!(
        counts.parses, 1,
        "actual uncached deserialize must be observed"
    );
    let mut scanner = IncrementalScanner::for_desktop();
    assert_eq!(scan(&mut scanner, &path), full);
    let (warm, counts) = transcript_test_support::observe(|| scan(&mut scanner, &path));
    assert_eq!(warm, full);
    assert_eq!(
        counts,
        transcript_test_support::Counts::default(),
        "unchanged admitted input opens/stats but does not read or deserialize"
    );
    assert_eq!(scanner.files.len(), 1);
    assert_retained(&scanner);
}

#[cfg(unix)]
#[test]
fn desktop_append_reads_only_delta_and_two_bounded_watermarks() {
    let _env = crate::platform::test_env::lock();
    use std::io::Write;
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("usage.jsonl");
    std::fs::write(
        &path,
        format!("{}\n{}\n", line("r", 1), " ".repeat(32 * 1024)),
    )
    .unwrap();
    let mut scanner = IncrementalScanner::for_desktop();
    scan(&mut scanner, &path).unwrap();
    let previous_offset = scanner.files[&path].parsed.offset;
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap(),
        "{}",
        line("r", 9)
    )
    .unwrap();
    let current_size = std::fs::metadata(&path).unwrap().len();
    let expected = reference(&path);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut scanner, &path));
    assert_eq!(actual, expected);
    assert_eq!(counts.parses, 1, "only the new snapshot is deserialized");
    assert!(
        counts.read_bytes as u64 <= current_size - previous_offset + 8192,
        "append read bytes {} exceed delta plus two4KiB watermarks",
        counts.read_bytes
    );
    assert!(
        counts.read_bytes < 32 * 1024,
        "must not read the old full prefix"
    );
    let actual = actual.unwrap();
    assert_eq!(actual.requests.len(), 1);
    assert_eq!(actual.output_tokens, 9);
    assert_retained(&scanner);
}

#[cfg(unix)]
#[test]
fn desktop_replacement_preserving_size_mtime_and_shrink_revalidate() {
    let _env = crate::platform::test_env::lock();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("usage.jsonl");
    std::fs::write(&path, format!("{}\n{}\n", line("r", 1), line("s", 2))).unwrap();
    let mut scanner = IncrementalScanner::for_desktop();
    scan(&mut scanner, &path).unwrap();
    let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    let replacement = temp.path().join("new.jsonl");
    std::fs::write(
        &replacement,
        format!("{}\n{}\n", line("r", 9), line("s", 2)),
    )
    .unwrap();
    std::fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        std::fs::metadata(&replacement).unwrap().len()
    );
    std::fs::rename(&replacement, &path).unwrap();
    let expected = reference(&path);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut scanner, &path));
    assert_eq!(
        actual, expected,
        "replacement identity must invalidate even equal size/mtime"
    );
    assert_eq!(counts.parses, 2);
    std::fs::write(&path, format!("{}\n", line("r", 4))).unwrap();
    let expected = reference(&path);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut scanner, &path));
    assert_eq!(actual, expected);
    assert_eq!(counts.parses, 1);
    assert_retained(&scanner);
}

#[cfg(unix)]
#[test]
fn desktop_same_size_mtime_preserved_ctime_change_revalidates() {
    let _env = crate::platform::test_env::lock();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("usage.jsonl");
    std::fs::write(&path, format!("{}\n", line("r", 1))).unwrap();
    let mut scanner = IncrementalScanner::for_desktop();
    scan(&mut scanner, &path).unwrap();
    let old = FileStamp::of(&std::fs::metadata(&path).unwrap());
    let new = mutate_until_ctime_advances(&path, &old, &format!("{}\n", line("r", 9)));
    assert_eq!(old.identity, new.identity);
    assert_eq!(old.size, new.size);
    assert_eq!(old.modified, new.modified);
    assert_ne!(
        old.changed, new.changed,
        "real mutation must expose a distinct ctime observation"
    );
    let expected = reference(&path);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut scanner, &path));
    assert_eq!(
        actual, expected,
        "ctime change must invalidate unchanged fast path"
    );
    assert_eq!(counts.parses, 1);
    assert_retained(&scanner);
}

#[test]
fn desktop_budget_bypass_is_complete_and_counted_by_actual_parser() {
    let _env = crate::platform::test_env::lock();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("usage.jsonl");
    let records: String = (0..200)
        .map(|i| format!("{}\n", line(&format!("r{i}"), 1)))
        .collect();
    std::fs::write(&path, records).unwrap();
    let mut scanner = IncrementalScanner {
        budget: CacheFootprint {
            records: 8,
            bytes: usize::MAX,
        },
        ..IncrementalScanner::for_desktop()
    };
    let expected = reference(&path);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut scanner, &path));
    assert_eq!(
        actual, expected,
        "budget bypass must preserve complete accounting"
    );
    assert_eq!(actual.unwrap().requests.len(), 200);
    assert_eq!(
        counts.parses, 209,
        "nine candidate parses plus complete200-record fallback must all count"
    );
    assert!(counts.read_bytes > 0 && counts.read_calls > 0);
    assert!(scanner.files.is_empty());
    assert_eq!(scanner.retained, CacheFootprint::default());
}

#[test]
fn desktop_profile_file_and_payload_bypass_preserve_complete_accounting() {
    let _env = crate::platform::test_env::lock();
    let temp = TempDir::new().unwrap();
    let first = temp.path().join("one.jsonl");
    let second = temp.path().join("two.jsonl");
    std::fs::write(&first, format!("{}\n", line("r", 1))).unwrap();
    std::fs::write(&second, format!("{}\n", line("s", 2))).unwrap();
    // Small selected cap probes the same per-profile admission comparison.
    let mut files = IncrementalScanner {
        file_cap: 1,
        ..IncrementalScanner::for_desktop()
    };
    scan(&mut files, &first).unwrap();
    let expected = reference(&second);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut files, &second));
    assert_eq!(actual, expected);
    assert_eq!(
        counts.parses, 1,
        "file-limit bypass must run complete parser"
    );
    assert!(counts.read_bytes > 0);
    assert_eq!(files.files.len(), 1);
    assert!(!files.files.contains_key(&second));
    assert_retained(&files);
    let mut payload = IncrementalScanner {
        budget: CacheFootprint {
            records: 65_536,
            bytes: 1,
        },
        ..IncrementalScanner::for_desktop()
    };
    let expected = reference(&first);
    let (actual, counts) = transcript_test_support::observe(|| scan(&mut payload, &first));
    assert_eq!(actual, expected);
    assert_eq!(
        counts.parses, 2,
        "over-payload candidate plus full fallback must both be counted"
    );
    assert!(payload.files.is_empty());
    assert_eq!(payload.retained, CacheFootprint::default());
}
