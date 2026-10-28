//! Child-completion wake tracking for the native Codex app-server.
//!
//! A supervised Codex TUI can spawn subagent threads. When a child finishes
//! while the main thread is idle, Codex does not start a parent turn, so a
//! queued csq notice waits for the parent's next natural turn. The native
//! app-server PUSHES thread/turn notifications over the bound socket csq
//! already holds (codex-cli 0.163.0 protocol table: `turn/started`,
//! `turn/completed`, `thread/status/changed`, `thread/closed`,
//! `thread/queue/changed`, `item/completed`, …). This tracker turns those
//! notifications into the missing edge without polling.
//!
//! It is deliberately PURE and method-agnostic: the caller re-reads
//! authoritative metadata (`thread/read`) on every notification that names a
//! thread and hands the OBSERVED status here. This module only remembers the
//! last observation per thread and reports every OBSERVED `active -> idle`
//! transition. It deliberately does NOT dedupe per child: a long-lived child
//! may finish many turns, and a later completion with a NEW queued notice must
//! still wake the parent. The caller dedupes on `(child, item)`, which is the
//! only pair that may start at most once.
//!
//! FAIL CLOSED: an unknown status or an unobserved previous status yields no
//! edge. The caller still checks that the thread is parented to the supervised
//! main thread, that the main thread is idle and accepting direct input, and
//! that the exact recorded notice row is queued, before starting anything.

use std::collections::HashMap;

/// Status value the native app-server reports in `status.type` for a thread
/// that is currently running a turn.
pub const STATUS_ACTIVE: &str = "active";

/// Status value for a thread that is waiting.
pub const STATUS_IDLE: &str = "idle";

/// Tracks the last OBSERVED status per thread.
#[derive(Debug, Default)]
pub struct ChildWakeTracker {
    last: HashMap<String, String>,
}

impl ChildWakeTracker {
    /// Record OBSERVED status for `thread`.
    ///
    /// Returns true iff this observation is an `active -> idle` transition.
    /// The result is a CANDIDATE only: the caller checks parentage, main-idle,
    /// the queued item, and its own `(child, item)` dedupe before starting.
    /// Every genuine transition is reported — a child that finishes a later
    /// turn must be able to wake its parent again.
    pub fn observe(&mut self, thread: &str, status: &str) -> bool {
        let previous = self.last.insert(thread.to_owned(), status.to_owned());
        previous.as_deref() == Some(STATUS_ACTIVE) && status == STATUS_IDLE
    }

    /// Seed the observation map from metadata read at subscribe time, so a
    /// child that was already active before the watcher connected still
    /// produces an edge on its first idle observation. Seeding never counts
    /// as an edge.
    pub fn seed(&mut self, thread: &str, status: &str) {
        self.last.insert(thread.to_owned(), status.to_owned());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const MAIN: &str = "01a0f6f5-1ba8-7202-94c4-bb7233a1f783";
    const CHILD_A: &str = "01a11624-fed4-71e1-b2a0-cbceaf8db0ff";
    const CHILD_B: &str = "01a11625-aaaa-71e1-b2a0-cbceaf8db0ff";

    #[test]
    fn active_to_idle_child_is_exactly_one_edge() {
        let mut t = ChildWakeTracker::default();
        assert!(
            !t.observe(CHILD_A, STATUS_ACTIVE),
            "a fresh active is not an edge"
        );
        assert!(
            t.observe(CHILD_A, STATUS_IDLE),
            "active -> idle is the edge"
        );
        assert!(
            !t.observe(CHILD_A, STATUS_IDLE),
            "idle -> idle is not an edge"
        );
        // A LATER turn of the same child is a fresh edge: dedupe belongs to
        // the watcher's (child, item) pair, never to the tracker.
        assert!(!t.observe(CHILD_A, STATUS_ACTIVE));
        assert!(
            t.observe(CHILD_A, STATUS_IDLE),
            "a later completion of the same child is a new edge"
        );
    }

    #[test]
    fn idle_without_an_observed_active_is_no_edge() {
        let mut t = ChildWakeTracker::default();
        assert!(
            !t.observe(CHILD_A, STATUS_IDLE),
            "unknown state does nothing"
        );
        // A child first observed idle, then idle again, still has no edge.
        assert!(!t.observe(CHILD_A, STATUS_IDLE));
        let mut seeded = ChildWakeTracker::default();
        seeded.seed(CHILD_A, STATUS_IDLE);
        assert!(!seeded.observe(CHILD_A, STATUS_IDLE));
    }

    #[test]
    fn unknown_status_breaks_the_edge() {
        let mut t = ChildWakeTracker::default();
        assert!(!t.observe(CHILD_A, STATUS_ACTIVE));
        assert!(
            !t.observe(CHILD_A, "systemError"),
            "unknown status is no edge"
        );
        assert!(
            !t.observe(CHILD_A, STATUS_IDLE),
            "active -> unknown -> idle is not an observed active -> idle"
        );
    }

    #[test]
    fn two_children_each_get_one_edge_and_no_double_start() {
        let mut t = ChildWakeTracker::default();
        t.seed(CHILD_A, STATUS_ACTIVE);
        t.seed(CHILD_B, STATUS_ACTIVE);
        assert!(t.observe(CHILD_A, STATUS_IDLE));
        assert!(t.observe(CHILD_B, STATUS_IDLE));
        // A repeated IDLE observation is not a second edge for either child.
        assert!(!t.observe(CHILD_A, STATUS_IDLE));
        assert!(!t.observe(CHILD_B, STATUS_IDLE));
        // The main thread itself is never a child candidate.
        assert!(!t.observe(MAIN, STATUS_ACTIVE));
    }
}
