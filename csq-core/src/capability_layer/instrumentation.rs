//! Per-stage timing instrumentation for the capability-layer pipeline.
//! NFR-PERF-01 budget enforced by aggregating these samples in
//! coc-eval/bench/capability_layer_cost.py; csq emits, harness gates.

use std::cell::RefCell;
use std::time::Instant;

pub const STAGE_COC_LOAD: &str = "cap.coc_load";
pub const STAGE_COC_LOAD_COLD: &str = "cap.coc_load.cold";
pub const STAGE_SCAFFOLD: &str = "cap.scaffold";
pub const STAGE_MCP_GATE: &str = "cap.mcp_gate";
pub const STAGE_TRANSLATE_CC: &str = "cap.translate.cc";
pub const STAGE_TRANSLATE_CODEX: &str = "cap.translate.codex";
pub const STAGE_TRANSLATE_GEMINI: &str = "cap.translate.gemini";
pub const STAGE_POST_VALIDATE: &str = "cap.post_validate";
pub const STAGE_LAYER_TOTAL: &str = "cap.layer_total";
pub const STAGE_COMPLIANCE_REPAIR: &str = "cap.compliance_repair";

/// Closed set of all valid stage IDs for membership tests.
pub const ALL_STAGE_IDS: &[&str] = &[
    STAGE_COC_LOAD,
    STAGE_COC_LOAD_COLD,
    STAGE_SCAFFOLD,
    STAGE_MCP_GATE,
    STAGE_TRANSLATE_CC,
    STAGE_TRANSLATE_CODEX,
    STAGE_TRANSLATE_GEMINI,
    STAGE_POST_VALIDATE,
    STAGE_LAYER_TOTAL,
    STAGE_COMPLIANCE_REPAIR,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageResult {
    Applied,
    Skipped,
    Degraded,
    Error,
}

#[derive(Debug, Clone)]
pub struct StageTiming {
    pub stage_id: &'static str,
    pub started_at_ns: u128,
    pub elapsed_ns: u128,
    pub result: StageResult,
}

pub struct StageTimer {
    stage_id: &'static str,
    start: Instant,
    started_at_ns: u128,
}

impl StageTimer {
    pub fn start(stage_id: &'static str) -> Self {
        Self {
            stage_id,
            start: Instant::now(),
            started_at_ns: monotonic_ns(),
        }
    }

    pub fn finish(self, result: StageResult) -> StageTiming {
        StageTiming {
            stage_id: self.stage_id,
            started_at_ns: self.started_at_ns,
            elapsed_ns: self.start.elapsed().as_nanos(),
            result,
        }
    }
}

thread_local! {
    static TIMINGS: RefCell<Vec<StageTiming>> = const { RefCell::new(Vec::new()) };
}

pub fn emit_stage_timing(t: &StageTiming) {
    // Single emit point — feeds tracing AND the bench JSONL writer.
    tracing::debug!(
        target: "csq::capability_layer::instrumentation",
        stage_id = t.stage_id,
        elapsed_ns = t.elapsed_ns as u64,
        result = ?t.result,
        "stage timing emitted"
    );
    TIMINGS.with(|cell| cell.borrow_mut().push(t.clone()));
}

pub struct PipelineTimings {
    pub timings: Vec<StageTiming>,
    pub total_ns: u128,
}

pub fn drain_timings() -> PipelineTimings {
    TIMINGS.with(|cell| {
        let timings = cell.borrow_mut().drain(..).collect::<Vec<_>>();
        let total_ns = timings.iter().map(|t| t.elapsed_ns).sum();
        PipelineTimings { timings, total_ns }
    })
}

fn monotonic_ns() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// All 10 stage_id constant string values are unique (closed-set
    /// invariant per design 08 §1.1).
    #[test]
    fn stage_id_closed_set_all_constants_unique() {
        let ids: BTreeSet<&str> = ALL_STAGE_IDS.iter().copied().collect();
        assert_eq!(
            ids.len(),
            10,
            "expected 10 unique stage_ids, got {}: {:?}",
            ids.len(),
            ALL_STAGE_IDS
        );
    }

    /// `StageTimer::start` + `finish` records at least 5 ms of elapsed
    /// time when a 5 ms sleep is inserted between them.
    #[test]
    fn stage_timer_records_elapsed_at_finish() {
        let t = StageTimer::start(STAGE_SCAFFOLD);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let timing = t.finish(StageResult::Applied);
        assert!(
            timing.elapsed_ns >= 5_000_000,
            "expected elapsed >= 5ms (5_000_000 ns), got {} ns",
            timing.elapsed_ns
        );
        assert_eq!(timing.stage_id, STAGE_SCAFFOLD);
        assert_eq!(timing.result, StageResult::Applied);
    }

    /// `emit_stage_timing` appends to the thread-local store; two calls
    /// produce two entries with the correct stage_ids.
    #[test]
    fn emit_stage_timing_appends_to_thread_local() {
        // Drain any residue from prior tests on this thread.
        drain_timings();

        let t1 = StageTiming {
            stage_id: STAGE_COC_LOAD,
            started_at_ns: 0,
            elapsed_ns: 100,
            result: StageResult::Applied,
        };
        let t2 = StageTiming {
            stage_id: STAGE_SCAFFOLD,
            started_at_ns: 100,
            elapsed_ns: 200,
            result: StageResult::Skipped,
        };
        emit_stage_timing(&t1);
        emit_stage_timing(&t2);

        let result = drain_timings();
        assert_eq!(result.timings.len(), 2);
        assert_eq!(result.timings[0].stage_id, STAGE_COC_LOAD);
        assert_eq!(result.timings[1].stage_id, STAGE_SCAFFOLD);
    }

    /// `drain_timings` empties the thread-local store; a second drain
    /// returns an empty vec.
    #[test]
    fn drain_timings_clears_thread_local() {
        drain_timings();
        let t = StageTiming {
            stage_id: STAGE_MCP_GATE,
            started_at_ns: 0,
            elapsed_ns: 50,
            result: StageResult::Applied,
        };
        emit_stage_timing(&t);

        let first = drain_timings();
        assert_eq!(first.timings.len(), 1);

        let second = drain_timings();
        assert!(
            second.timings.is_empty(),
            "second drain must return empty after first consumed all timings"
        );
    }

    /// `drain_timings` returns `total_ns` equal to the sum of individual
    /// `elapsed_ns` values.
    #[test]
    fn drain_timings_returns_total_ns_as_sum_of_elapsed() {
        drain_timings();
        let t1 = StageTiming {
            stage_id: STAGE_COC_LOAD,
            started_at_ns: 0,
            elapsed_ns: 1_000_000,
            result: StageResult::Applied,
        };
        let t2 = StageTiming {
            stage_id: STAGE_SCAFFOLD,
            started_at_ns: 1_000_000,
            elapsed_ns: 2_000_000,
            result: StageResult::Applied,
        };
        emit_stage_timing(&t1);
        emit_stage_timing(&t2);

        let result = drain_timings();
        assert_eq!(
            result.total_ns, 3_000_000,
            "total_ns must equal sum of elapsed_ns: {} + {} = 3_000_000, got {}",
            t1.elapsed_ns, t2.elapsed_ns, result.total_ns
        );
    }

    /// All four `StageResult` variants serialize distinctly via `Debug`.
    #[test]
    fn stage_result_applied_skipped_degraded_error_serialize_distinctly() {
        let applied = format!("{:?}", StageResult::Applied);
        let skipped = format!("{:?}", StageResult::Skipped);
        let degraded = format!("{:?}", StageResult::Degraded);
        let error = format!("{:?}", StageResult::Error);

        let variants = [
            applied.as_str(),
            skipped.as_str(),
            degraded.as_str(),
            error.as_str(),
        ];
        let unique: BTreeSet<&str> = variants.iter().copied().collect();
        assert_eq!(
            unique.len(),
            4,
            "all four StageResult variants must Debug-format distinctly: {:?}",
            variants
        );
    }

    /// Each of the 10 constants matches its expected string value from
    /// design 08 §1.1 table (closed-set contract).
    #[test]
    fn closed_set_stage_ids_match_design_08_table() {
        assert_eq!(STAGE_COC_LOAD, "cap.coc_load");
        assert_eq!(STAGE_COC_LOAD_COLD, "cap.coc_load.cold");
        assert_eq!(STAGE_SCAFFOLD, "cap.scaffold");
        assert_eq!(STAGE_MCP_GATE, "cap.mcp_gate");
        assert_eq!(STAGE_TRANSLATE_CC, "cap.translate.cc");
        assert_eq!(STAGE_TRANSLATE_CODEX, "cap.translate.codex");
        assert_eq!(STAGE_TRANSLATE_GEMINI, "cap.translate.gemini");
        assert_eq!(STAGE_POST_VALIDATE, "cap.post_validate");
        assert_eq!(STAGE_LAYER_TOTAL, "cap.layer_total");
        assert_eq!(STAGE_COMPLIANCE_REPAIR, "cap.compliance_repair");
    }

    /// Round-trip: 100 emits with varying stage_ids from the closed set —
    /// every drained timing has a stage_id that belongs to the closed set.
    #[test]
    fn every_emit_carries_one_of_the_closed_set_stage_ids() {
        drain_timings();

        let closed_set: BTreeSet<&str> = ALL_STAGE_IDS.iter().copied().collect();

        for i in 0u128..100 {
            let id = ALL_STAGE_IDS[i as usize % ALL_STAGE_IDS.len()];
            let t = StageTiming {
                stage_id: id,
                started_at_ns: i,
                elapsed_ns: i + 1,
                result: StageResult::Applied,
            };
            emit_stage_timing(&t);
        }

        let result = drain_timings();
        assert_eq!(result.timings.len(), 100);
        for timing in &result.timings {
            assert!(
                closed_set.contains(timing.stage_id),
                "stage_id {:?} is not in the closed set",
                timing.stage_id
            );
        }
    }
}
