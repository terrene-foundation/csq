//! Log-volume gate primitives for the capability-layer + binary-wide
//! tracing surface (PR-CA11c T5).
//!
//! Spec: workspaces/csq-as-cli/02-plans/05-pr-ca11-implementation-plan.md § 0.5 + § Group 3 T5.
//! NFR: NFR-OBS-01 (≤ 10 events default per `csq run`; ≤ 50 with `--debug`).
//!
//! This module is the stdlib-only primitive layer. The
//! `tracing-subscriber::Layer` impl that consumes these primitives lives
//! in `csq-cli/src/log_volume_layer.rs` so `csq-core` does not pull
//! `tracing-subscriber` as a dependency (workspace `Cargo.toml` keeps
//! that crate `csq-cli`-only).
//!
//! # Why thread_local only
//!
//! Originally the plan called for `tokio::task_local!` covering async
//! stages and `thread_local!` covering sync stages. Reading
//! `csq-cli/src/main.rs::main` (`fn main() -> Result<()>` — no
//! `#[tokio::main]`) and `csq-core/src/capability_layer/{driver,
//! pipeline}.rs` (every `PipelineStage::run` is `fn run`, not `async
//! fn run`; zero `tokio::spawn` in the stage implementations) confirms
//! the whole `csq run` invocation runs on a single OS thread. Pure
//! `thread_local!` therefore covers the full lifecycle of one `csq run`
//! invocation — see journal 0077 (PR-CA11c R1 Q3 resolution).
//!
//! # Reentrancy and the ceiling-notice
//!
//! When the ceiling is hit the Layer emits ONE `event_count_ceiling_hit`
//! event so the operator sees the truncation. That emission re-enters
//! the Layer; without a guard it would either recurse (if the gate
//! always counts) or silently drop (if the gate is at-ceiling). The
//! guard is a thread-local `EMITTING_CEILING_NOTICE` flag the Layer
//! sets before the notice and clears after. While set, [`decide`]
//! returns [`Decision::Pass`] without touching the counter so the
//! notice itself is not counted against the ceiling.

use std::cell::Cell;

/// Default ceiling: 10 events per `csq run` invocation. Matches the
/// NFR-OBS-01 budget for the default-mode run.
pub const DEFAULT_CEILING: u32 = 10;

/// `--debug` ceiling: 50 events per `csq run` invocation.
pub const DEBUG_CEILING: u32 = 50;

thread_local! {
    /// Per-thread counter of events that passed the gate during the
    /// current `csq run` invocation. Reset by [`reset_event_counter`]
    /// at the top of each command handler.
    static EVENTS_EMITTED: Cell<u32> = const { Cell::new(0) };

    /// Latched once when the ceiling is first hit. Distinguishes the
    /// "emit ONE notice" case from the "drop silently" case the Layer
    /// branches on.
    static CEILING_NOTICE_LATCHED: Cell<bool> = const { Cell::new(false) };

    /// Reentrancy guard: when true, [`decide`] returns
    /// [`Decision::Pass`] without touching the counter so the
    /// ceiling-notice event itself is not counted.
    static EMITTING_CEILING_NOTICE: Cell<bool> = const { Cell::new(false) };
}

/// Volume mode for the gate. `--trace` does NOT pick a different
/// ceiling here — `--trace` adds an unbounded trace-file Layer alongside
/// the count-gated stderr Layer. See journal 0077 (Q4 resolution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingMode {
    /// 10 events (NFR-OBS-01 default).
    Default,
    /// 50 events (`--debug`).
    Debug,
    /// `u32::MAX` — used by the trace-file Layer which has no cap.
    Unbounded,
}

impl CeilingMode {
    /// Numeric ceiling for this mode.
    pub const fn ceiling(self) -> u32 {
        match self {
            CeilingMode::Default => DEFAULT_CEILING,
            CeilingMode::Debug => DEBUG_CEILING,
            CeilingMode::Unbounded => u32::MAX,
        }
    }
}

/// Decision returned by [`decide`] — what the Layer should do with
/// the event currently being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allow the event through. Counter has been incremented (unless
    /// the reentrancy guard was set, in which case Pass is returned
    /// without touching the counter).
    Pass,
    /// Suppress the event AND emit ONE ceiling-notice event before
    /// returning. The Layer is responsible for setting the reentrancy
    /// guard around its notice-emit call; this primitive only signals
    /// the transition.
    EmitNotice,
    /// Suppress the event. The notice has already been emitted earlier
    /// in this invocation.
    Drop,
}

/// Reset the per-`csq run` event counter and notice latch. Call at the
/// top of each command handler so the count is scoped to one
/// invocation. Idempotent.
pub fn reset_event_counter() {
    EVENTS_EMITTED.with(|c| c.set(0));
    CEILING_NOTICE_LATCHED.with(|c| c.set(false));
    EMITTING_CEILING_NOTICE.with(|c| c.set(false));
}

/// Decide whether the next event passes the ceiling gate. Increments
/// the counter on Pass; latches the notice flag on first ceiling-hit.
///
/// Reentrant calls (made while the Layer is emitting the
/// ceiling-notice itself) skip the counter and return Pass — the
/// notice is not counted against the ceiling.
pub fn decide(ceiling: u32) -> Decision {
    if EMITTING_CEILING_NOTICE.with(|c| c.get()) {
        return Decision::Pass;
    }
    EVENTS_EMITTED.with(|counter| {
        let current = counter.get();
        if current < ceiling {
            counter.set(current + 1);
            Decision::Pass
        } else {
            CEILING_NOTICE_LATCHED.with(|latch| {
                if !latch.get() {
                    latch.set(true);
                    Decision::EmitNotice
                } else {
                    Decision::Drop
                }
            })
        }
    })
}

/// Set the reentrancy guard. The Layer calls
/// `set_emitting_ceiling_notice(true)` before its notice emission and
/// `set_emitting_ceiling_notice(false)` after, so the notice's own
/// `tracing::warn!` call passes through [`decide`] without recursion.
pub fn set_emitting_ceiling_notice(emitting: bool) {
    EMITTING_CEILING_NOTICE.with(|c| c.set(emitting));
}

/// Read the current emitted-event count. Used by integration tests
/// asserting per-`csq run` counter independence.
pub fn events_emitted() -> u32 {
    EVENTS_EMITTED.with(|c| c.get())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: cargo test runs each `#[test]` in its own thread, so
    /// thread_local state is fresh per test. We still call reset to
    /// cover the case where a single thread's runner reuses threads
    /// across tests (newer cargo nextest behavior).
    fn fresh() {
        reset_event_counter();
    }

    #[test]
    fn first_ten_events_pass_under_default_ceiling() {
        fresh();
        for i in 0..DEFAULT_CEILING {
            assert_eq!(
                decide(DEFAULT_CEILING),
                Decision::Pass,
                "event {i} must pass under default ceiling"
            );
        }
        assert_eq!(events_emitted(), DEFAULT_CEILING);
    }

    #[test]
    fn eleventh_event_emits_notice() {
        fresh();
        for _ in 0..DEFAULT_CEILING {
            decide(DEFAULT_CEILING);
        }
        assert_eq!(
            decide(DEFAULT_CEILING),
            Decision::EmitNotice,
            "first event past ceiling must emit notice"
        );
    }

    #[test]
    fn events_after_notice_drop_silently() {
        fresh();
        for _ in 0..DEFAULT_CEILING {
            decide(DEFAULT_CEILING);
        }
        decide(DEFAULT_CEILING); // EmitNotice
        for i in 0..20 {
            assert_eq!(
                decide(DEFAULT_CEILING),
                Decision::Drop,
                "post-notice event {i} must drop"
            );
        }
    }

    #[test]
    fn reentrancy_guard_bypasses_gate() {
        fresh();
        for _ in 0..DEFAULT_CEILING {
            decide(DEFAULT_CEILING);
        }
        decide(DEFAULT_CEILING); // EmitNotice
                                 // Layer enters its notice-emit code path:
        set_emitting_ceiling_notice(true);
        assert_eq!(
            decide(DEFAULT_CEILING),
            Decision::Pass,
            "reentrant call during notice emission must Pass without counting"
        );
        set_emitting_ceiling_notice(false);
        // Counter must NOT have advanced past ceiling during the
        // bypass (still at exactly ceiling, not ceiling+1).
        assert_eq!(events_emitted(), DEFAULT_CEILING);
        // Subsequent normal events drop.
        assert_eq!(decide(DEFAULT_CEILING), Decision::Drop);
    }

    #[test]
    fn reset_restores_counter_and_latch() {
        fresh();
        for _ in 0..DEFAULT_CEILING {
            decide(DEFAULT_CEILING);
        }
        decide(DEFAULT_CEILING); // EmitNotice
        decide(DEFAULT_CEILING); // Drop
        reset_event_counter();
        assert_eq!(
            decide(DEFAULT_CEILING),
            Decision::Pass,
            "post-reset event must pass"
        );
        assert_eq!(events_emitted(), 1);
    }

    #[test]
    fn debug_mode_allows_fifty_events() {
        fresh();
        for i in 0..DEBUG_CEILING {
            assert_eq!(
                decide(DEBUG_CEILING),
                Decision::Pass,
                "event {i} under debug ceiling must pass"
            );
        }
        assert_eq!(decide(DEBUG_CEILING), Decision::EmitNotice);
    }

    #[test]
    fn unbounded_mode_never_hits_notice() {
        fresh();
        let ceiling = CeilingMode::Unbounded.ceiling();
        for _ in 0..1_000 {
            assert_eq!(decide(ceiling), Decision::Pass);
        }
    }

    #[test]
    fn ceiling_mode_constants_are_stable() {
        // Pin the contract that PR-CA11c plan + spec 12 + NFR-OBS-01 cite.
        assert_eq!(CeilingMode::Default.ceiling(), 10);
        assert_eq!(CeilingMode::Debug.ceiling(), 50);
        assert_eq!(CeilingMode::Unbounded.ceiling(), u32::MAX);
    }

    #[test]
    fn idempotent_reset() {
        fresh();
        reset_event_counter();
        reset_event_counter();
        assert_eq!(events_emitted(), 0);
    }

    #[test]
    fn notice_emitted_exactly_once_per_invocation() {
        fresh();
        for _ in 0..DEFAULT_CEILING {
            decide(DEFAULT_CEILING);
        }
        let mut notices = 0;
        for _ in 0..100 {
            if decide(DEFAULT_CEILING) == Decision::EmitNotice {
                notices += 1;
            }
        }
        assert_eq!(notices, 1, "exactly one notice per ceiling-hit window");
    }

    #[test]
    fn reentrancy_guard_independent_of_counter_state() {
        fresh();
        // Even before the ceiling is hit, the reentrancy guard takes
        // priority — defense-in-depth in case the Layer's notice
        // emission ever fires before the gate flips (test pin only).
        set_emitting_ceiling_notice(true);
        assert_eq!(decide(DEFAULT_CEILING), Decision::Pass);
        // Counter UNCHANGED while the guard is set.
        assert_eq!(events_emitted(), 0);
        set_emitting_ceiling_notice(false);
        assert_eq!(decide(DEFAULT_CEILING), Decision::Pass);
        assert_eq!(events_emitted(), 1);
    }
}
