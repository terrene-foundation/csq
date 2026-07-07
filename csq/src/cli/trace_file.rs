//! Per-pid trace log file Layer for `csq run --trace` (PR-CA11c T6).
//!
//! Spec: internal-design-docs § Group 3 T6.
//!
//! When the user passes `--trace`, csq-cli opens a fresh log file at
//! `<base>/csq-runs/.trace/<pid>-<ts>.log` and installs this Layer
//! alongside the stderr Layer. Each event is JSON-serialized, redacted
//! via `csq_core::capability_layer::logging::redact_log_line`, and
//! appended.
//!
//! # Permissions
//!
//! - Parent dir `csq-runs/.trace/` is created with mode `0o700` (owner-only).
//! - The log file itself is opened with mode `0o600` (owner read/write only).
//! - Both inherit `rules/security.md` § 5 secure-file posture.
//!
//! # Path discipline
//!
//! The path uses `csq-runs/.trace/` so it sits adjacent to (but
//! separate from) the audit-record + `.pending/` directories. The
//! trace dir lives INSIDE `csq-runs/` so the audit single-writer
//! allowlist (`csq-core/tests/audit_single_writer.rs`) treats this
//! file as part of the audit-pipeline directory tree. The
//! `.trace/*.log` glob is NEVER touched by `audit::persist::write_record`
//! — the trace files are append-only by tracing-subscriber and read +
//! purged by `audit::sweep` (PR-CA11c T7).

use csq_core::capability_layer::logging::redact_log_line;
use csq_core::platform::fs::secure_file;
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Layer that appends each event as one JSON line to a per-pid trace
/// file. Lines are redacted via `redact_log_line` before write.
pub struct TraceFileLayer {
    /// Open file handle wrapped in a Mutex so concurrent emit calls
    /// (multiple threads sharing the global subscriber) serialize on
    /// the lock rather than racing the file descriptor.
    file: Arc<Mutex<File>>,
}

impl TraceFileLayer {
    /// Open (or create) the per-pid trace file under `<base>/csq-runs/.trace/`.
    ///
    /// Returns `Ok(layer)` on success. On any I/O error the caller
    /// MUST log a structured warning and continue without the trace
    /// file — `--trace` is a debugging affordance, never a hard
    /// requirement; failing csq run because the trace dir is
    /// unwriteable would be operator-hostile.
    pub fn open(base: &Path) -> io::Result<Self> {
        let path = trace_log_path(base);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            secure_dir_owner_only(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // Flip to 0o600 immediately. Mode-on-create varies by umask;
        // explicit secure_file is the structural guarantee.
        secure_file(&path).map_err(io::Error::other)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    /// Test-only constructor that opens the trace file at a specific
    /// path without imposing the standard `<base>/csq-runs/.trace/`
    /// layout. Used by integration tests with `TempDir`-rooted paths.
    #[cfg(test)]
    pub fn open_at(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            secure_dir_owner_only(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        secure_file(path).map_err(io::Error::other)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
}

/// Compute the trace log path: `<base>/csq-runs/.trace/<pid>-<ts>.log`.
///
/// The timestamp is seconds since UNIX_EPOCH so the filename sorts
/// chronologically and concurrent `csq run` sessions never collide
/// (different PID + sub-second ordering via the per-process write
/// stream).
pub fn trace_log_path(base: &Path) -> PathBuf {
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    base.join("csq-runs")
        .join(".trace")
        .join(format!("{pid}-{ts}.log"))
}

#[cfg(unix)]
fn secure_dir_owner_only(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(dir, perms)
}

#[cfg(not(unix))]
fn secure_dir_owner_only(_dir: &Path) -> io::Result<()> {
    // Windows ACL defaults are owner-only; no portable mode flip exists.
    Ok(())
}

impl<S: Subscriber> Layer<S> for TraceFileLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = JsonFieldVisitor::default();
        event.record(&mut visitor);
        let line = json!({
            "ts": current_iso8601_utc(),
            "level": metadata.level().to_string(),
            "target": metadata.target(),
            "fields": visitor.fields,
        });
        let line_str = line.to_string();
        let redacted = redact_log_line(&line_str);
        // Best-effort write; never panic into the binary on a trace
        // log error.
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{redacted}");
            let _ = file.flush();
        }
    }
}

/// Visitor that records every event field as a JSON value, indexed by
/// field name. Numeric fields preserve their integer/float type; bool
/// fields stay bool; everything else is rendered via `Debug` and stored
/// as a string.
#[derive(Default)]
struct JsonFieldVisitor {
    fields: serde_json::Map<String, Value>,
}

impl tracing::field::Visit for JsonFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), Value::String(value.to_string()));
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), Value::Bool(value));
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.fields
                .insert(field.name().to_string(), Value::Number(n));
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            Value::String(format!("{value:?}")),
        );
    }
}

/// Stdlib-only ISO-8601 UTC timestamp matching the format used in
/// `audit::sweep::current_iso8601_utc` so trace and audit logs share
/// a timestamp shape.
fn current_iso8601_utc() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = now.as_secs() as i64;
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Civil-time conversion (Howard Hinnant) — duplicated here to keep
/// the trace module standalone. Identical to the helper in
/// `csq-core/src/audit/sweep.rs`.
fn unix_to_ymdhms(mut t: i64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (t.rem_euclid(86_400)) as u32;
    let hour = s / 3_600;
    let minute = (s % 3_600) / 60;
    let second = s % 60;
    t = t.div_euclid(86_400);
    let z = t + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = (y + i64::from(month <= 2)) as i32;
    (year, month, day, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    #[cfg(unix)]
    #[test]
    fn open_creates_file_with_mode_0600_and_parent_0700() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("csq-runs").join(".trace").join("99-1.log");
        let _layer = TraceFileLayer::open_at(&path).unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "trace file mode must be 0o600");

        let parent_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o700, "trace parent dir must be 0o700");
    }

    #[test]
    fn trace_log_path_includes_pid_and_csq_runs_dot_trace() {
        let base = Path::new("/tmp/fake");
        let path = trace_log_path(base);
        let s = path.to_string_lossy();
        assert!(s.contains("csq-runs"), "path must include csq-runs: {s}");
        assert!(s.contains(".trace"), "path must include .trace: {s}");
        assert!(
            s.contains(&format!("{}", std::process::id())),
            "path must embed pid: {s}"
        );
        assert!(s.ends_with(".log"), "path must end .log: {s}");
    }

    #[test]
    fn emitted_events_are_appended_as_json_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("trace.log");
        let layer = TraceFileLayer::open_at(&path).unwrap();
        let subscriber = Registry::default().with(layer);
        with_default(subscriber, || {
            tracing::info!(idx = 1, "hello");
            tracing::warn!(idx = 2, "warned");
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "two events emitted: {content}");
        for line in &lines {
            let v: Value = serde_json::from_str(line).expect("each line must be valid JSON");
            assert!(v.get("ts").is_some(), "ts field present");
            assert!(v.get("level").is_some(), "level field present");
            assert!(v.get("target").is_some(), "target field present");
            assert!(v.get("fields").is_some(), "fields object present");
        }
    }

    #[test]
    fn redaction_strips_anthropic_token_from_event_message() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("trace.log");
        let layer = TraceFileLayer::open_at(&path).unwrap();
        let subscriber = Registry::default().with(layer);
        with_default(subscriber, || {
            tracing::error!(
                key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "auth body"
            );
        });
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("sk-ant-api03-AAAAAAAAAAAA"),
            "redaction must strip raw sk-ant prefix; got: {content}"
        );
        assert!(
            content.contains("REDACTED") || content.contains("redacted"),
            "redacted marker must appear: {content}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_layers_to_separate_files_do_not_interfere() {
        let tmp = TempDir::new().unwrap();
        let path_a = tmp.path().join("a").join("trace.log");
        let path_b = tmp.path().join("b").join("trace.log");
        let layer_a = TraceFileLayer::open_at(&path_a).unwrap();
        let layer_b = TraceFileLayer::open_at(&path_b).unwrap();

        let sub_a = Registry::default().with(layer_a);
        let sub_b = Registry::default().with(layer_b);
        with_default(sub_a, || {
            tracing::info!(side = "a", "a-event");
        });
        with_default(sub_b, || {
            tracing::info!(side = "b", "b-event");
        });
        assert!(std::fs::read_to_string(&path_a).unwrap().contains("\"a\""));
        assert!(std::fs::read_to_string(&path_b).unwrap().contains("\"b\""));
        assert!(!std::fs::read_to_string(&path_a)
            .unwrap()
            .contains("b-event"));
        assert!(!std::fs::read_to_string(&path_b)
            .unwrap()
            .contains("a-event"));
    }

    #[test]
    fn json_field_visitor_preserves_numeric_types() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("trace.log");
        let layer = TraceFileLayer::open_at(&path).unwrap();
        let subscriber = Registry::default().with(layer);
        with_default(subscriber, || {
            tracing::info!(count = 42_u64, ratio = 0.5_f64, ok = true, "metrics");
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        let fields = v.get("fields").unwrap();
        assert_eq!(fields["count"], json!(42));
        assert!((fields["ratio"].as_f64().unwrap() - 0.5).abs() < 1e-9);
        assert_eq!(fields["ok"], json!(true));
    }

    #[test]
    fn iso_timestamp_format_is_year_month_day_t_hms_z() {
        let s = current_iso8601_utc();
        // Sanity: 20 chars in YYYY-MM-DDTHH:MM:SSZ.
        assert_eq!(s.len(), 20, "iso ts must be 20 chars; got {s}");
        assert!(s.ends_with('Z'));
        assert_eq!(s.chars().nth(4), Some('-'));
        assert_eq!(s.chars().nth(10), Some('T'));
    }
}
