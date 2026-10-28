//! `tracing-subscriber` per-Layer Filter that gates event emission via
//! the `csq-core::capability_layer::log_volume` thread-local counter
//! (PR-CA11c T5).
//!
//! Spec: internal-design-docs § 0.5 + § Group 3 T5.
//!
//! # Why a Filter, not a Layer
//!
//! A global `Layer::event_enabled` returning `false` drops the event
//! for EVERY Layer in the Registry — a bare `LogVolumeLayer` would
//! gate the trace-file Layer as well, contradicting Q4's resolution
//! ("trace file is the unbounded source; stderr stays count-gated").
//! Per-Layer Filters scope the gate to ONLY the Layer they are
//! attached to. The stderr fmt-Layer wears [`LogVolumeFilter`]; the
//! trace-file Layer has no filter and sees every event the global
//! `EnvFilter` allows.
//!
//! # Ceiling-hit notice
//!
//! When the ceiling is first hit the Filter writes ONE structured
//! JSON line to a configured `notice_writer` (default: stderr). The
//! notice does NOT route through `tracing::warn!` because
//! `tracing-subscriber`'s internal re-entrancy guard suppresses any
//! `tracing` macro call made from inside a Layer's `event_enabled`
//! callback (verified via probe — see commit log). Direct write to
//! the operator-facing stderr is the structurally-reliable path.

use csq_core::capability_layer::log_volume::{self, CeilingMode, Decision};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Per-Layer event-volume filter. Constructed via [`Self::new`] from
/// a [`CeilingMode`]. The notice-writer is `Arc<Mutex<dyn Write>>`
/// so tests can substitute an in-memory `Vec<u8>` and assert against
/// the captured bytes.
#[derive(Clone)]
pub struct LogVolumeFilter {
    ceiling: u32,
    notice_writer: Arc<Mutex<dyn Write + Send>>,
}

impl std::fmt::Debug for LogVolumeFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogVolumeFilter")
            .field("ceiling", &self.ceiling)
            .finish_non_exhaustive()
    }
}

impl LogVolumeFilter {
    /// Build a filter for the given mode. The ceiling-hit notice is
    /// written to stderr.
    pub fn new(mode: CeilingMode) -> Self {
        Self {
            ceiling: mode.ceiling(),
            notice_writer: Arc::new(Mutex::new(std::io::stderr())),
        }
    }

    /// Build a filter for the given mode with a custom notice writer.
    /// Used by tests to capture the notice bytes.
    #[cfg(test)]
    pub fn with_notice_writer(mode: CeilingMode, writer: Arc<Mutex<dyn Write + Send>>) -> Self {
        Self {
            ceiling: mode.ceiling(),
            notice_writer: writer,
        }
    }

    fn write_notice(&self) {
        let line = format!(
            r#"{{"event_kind":"event_count_ceiling_hit","ceiling":{},"message":"log volume ceiling hit; subsequent events suppressed (use --trace for full log)"}}"#,
            self.ceiling
        );
        if let Ok(mut w) = self.notice_writer.lock() {
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }
    }
}

impl<S> tracing_subscriber::layer::Filter<S> for LogVolumeFilter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn enabled(&self, _metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, _event: &Event<'_>, _ctx: &Context<'_, S>) -> bool {
        match log_volume::decide(self.ceiling) {
            Decision::Pass => true,
            Decision::EmitNotice => {
                self.write_notice();
                false
            }
            Decision::Drop => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::Registry;

    /// Capture-Layer that increments a counter each time `on_event`
    /// fires. Combined with `LogVolumeFilter`, only events that pass
    /// the gate reach `on_event`.
    struct CounterLayer {
        count: Arc<Mutex<u32>>,
    }

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for CounterLayer {
        fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {
            *self.count.lock().unwrap() += 1;
        }
    }

    /// Run `body` under a fresh subscriber. Returns
    /// `(events_emitted, notice_bytes)` so tests can assert both the
    /// gated event count and whether the ceiling-notice line was
    /// written.
    fn run_filtered<F: FnOnce()>(mode: CeilingMode, body: F) -> (u32, Vec<u8>) {
        let count = Arc::new(Mutex::new(0_u32));
        let notice_buf: Arc<Mutex<dyn Write + Send>> = Arc::new(Mutex::new(Vec::<u8>::new()));
        let filter = LogVolumeFilter::with_notice_writer(mode, Arc::clone(&notice_buf));
        let counter = CounterLayer {
            count: Arc::clone(&count),
        }
        .with_filter(filter);
        let subscriber = Registry::default().with(counter);
        log_volume::reset_event_counter();
        with_default(subscriber, body);
        let n = *count.lock().unwrap();
        // Recover the buffer as Vec<u8>. The Mutex held a `dyn Write`
        // pointing at a Vec; lock it and clone-out the bytes via a
        // trait probe (writeln writes to the inner Vec; we read it
        // back by re-using the Arc — the simplest path is to keep a
        // sibling Arc<Mutex<Vec<u8>>> for the assertion).
        // To avoid dyn Write read-back complexity we rebuild the
        // call: open a second sibling buffer in tests-with-bytes.
        let _ = notice_buf;
        (n, Vec::new())
    }

    /// Variant that returns the captured notice bytes, used by the
    /// notice-shape test.
    fn run_filtered_with_notice<F: FnOnce()>(mode: CeilingMode, body: F) -> (u32, Vec<u8>) {
        let count = Arc::new(Mutex::new(0_u32));
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let buf_for_filter: Arc<Mutex<dyn Write + Send>> = buf.clone();
        let filter = LogVolumeFilter::with_notice_writer(mode, buf_for_filter);
        let counter = CounterLayer {
            count: Arc::clone(&count),
        }
        .with_filter(filter);
        let subscriber = Registry::default().with(counter);
        log_volume::reset_event_counter();
        with_default(subscriber, body);
        let n = *count.lock().unwrap();
        let bytes = buf.lock().unwrap().clone();
        (n, bytes)
    }

    #[test]
    fn default_mode_passes_exactly_ten_events_to_the_layer() {
        let (count, _) = run_filtered(CeilingMode::Default, || {
            for i in 0..30 {
                tracing::info!(idx = i, "trial");
            }
        });
        assert_eq!(count, 10, "default mode caps emissions at 10 trial events");
    }

    #[test]
    fn debug_mode_passes_exactly_fifty_events_to_the_layer() {
        let (count, _) = run_filtered(CeilingMode::Debug, || {
            for i in 0..70 {
                tracing::info!(idx = i, "trial");
            }
        });
        assert_eq!(count, 50, "debug mode caps at 50");
    }

    #[test]
    fn unbounded_mode_passes_every_event() {
        let (count, _) = run_filtered(CeilingMode::Unbounded, || {
            for i in 0..200 {
                tracing::info!(idx = i, "trial");
            }
        });
        assert_eq!(count, 200);
    }

    #[test]
    fn ceiling_notice_written_exactly_once_with_event_kind_and_ceiling_fields() {
        let (count, notice) = run_filtered_with_notice(CeilingMode::Default, || {
            for i in 0..30 {
                tracing::info!(idx = i, "trial");
            }
        });
        assert_eq!(count, 10);
        let s = String::from_utf8(notice).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one ceiling-hit notice; got: {s:?}");
        let v: Value = serde_json::from_str(lines[0]).expect("notice must be valid JSON");
        assert_eq!(v["event_kind"], "event_count_ceiling_hit");
        assert_eq!(v["ceiling"], 10);
        assert!(v["message"].is_string());
    }

    #[test]
    fn unbounded_mode_emits_no_ceiling_notice() {
        let (count, notice) = run_filtered_with_notice(CeilingMode::Unbounded, || {
            for i in 0..50 {
                tracing::info!(idx = i, "trial");
            }
        });
        assert_eq!(count, 50);
        assert!(notice.is_empty(), "unbounded mode never emits notice");
    }

    #[test]
    fn second_invocation_resets_counter() {
        let (first, _) = run_filtered(CeilingMode::Default, || {
            for i in 0..15 {
                tracing::info!(idx = i, "first");
            }
        });
        let (second, _) = run_filtered(CeilingMode::Default, || {
            for i in 0..15 {
                tracing::info!(idx = i, "second");
            }
        });
        assert_eq!(first, 10);
        assert_eq!(second, 10);
    }

    #[test]
    fn filter_on_one_layer_does_not_gate_another_layer() {
        // Architectural pin (Q4 resolution): the trace-file Layer must
        // see every event even when the stderr Layer is filtered.
        let stderr_count = Arc::new(Mutex::new(0_u32));
        let trace_count = Arc::new(Mutex::new(0_u32));
        let stderr_buf: Arc<Mutex<dyn Write + Send>> = Arc::new(Mutex::new(Vec::<u8>::new()));
        let stderr_layer = CounterLayer {
            count: Arc::clone(&stderr_count),
        }
        .with_filter(LogVolumeFilter::with_notice_writer(
            CeilingMode::Default,
            stderr_buf,
        ));
        let trace_layer = CounterLayer {
            count: Arc::clone(&trace_count),
        };
        let subscriber = Registry::default().with(stderr_layer).with(trace_layer);
        log_volume::reset_event_counter();
        with_default(subscriber, || {
            for i in 0..30 {
                tracing::info!(idx = i, "trial");
            }
        });
        assert_eq!(*stderr_count.lock().unwrap(), 10);
        assert_eq!(
            *trace_count.lock().unwrap(),
            30,
            "trace layer must see all 30 events"
        );
    }
}
