// child-supervisor.mjs — ONE supervised spawner for every child process that
// scripts/ci/*.mjs starts.
//
// WHY THIS EXISTS (D237 R3, 2026-10-18): four hand-rolled spawn/kill paths
// (capture, runTrestleBounded, runGateWorkers, the per-test watchdog) each
// re-learned the same lessons one round at a time — and each round closed one
// site while exposing the next:
//   - a stop reached the children of only some paths (capture's detached groups
//     were invisible to every handler);
//   - liveness keyed on `close` in one path and `exit` in another, so a
//     descendant holding inherited stdio kept a dead leader "live" (and kept the
//     reused-pgid guard from ever running);
//   - a KILL backstop lived in a process that exited milliseconds later, so the
//     timer that existed to kill a TERM-ignoring member was discarded with the
//     process (`probe/r3/exitafter.mjs`, measured leak pid 44453);
//   - Windows could signal a raw pid after its leader was reaped.
//
// THE CONTRACT, in one place:
//   - one stop set, one latch: installStopHandlers() registers SIGTERM/SIGINT/
//     SIGHUP, records the first signal, and stops every live child;
//   - liveness is keyed on `exit`, never `close`, and EXIT IS THE REMOVAL: an
//     exited child leaves the stop set itself, so no caller has to remember
//     dispose() and a later stop can never reach a stale pid;
//   - LEADER-EXIT SWEEP (D237 R1 H1): the exit callback is the one moment the
//     group's ownership is freshly proven — POSIX pins the leader's pid as a
//     usable pgid while any task still holds it as its group id, and the exit
//     was just observed. If members remain, TERM the group NOW and arm the KILL
//     (which re-probes when it fires), then drop the entry. A later stop() sends
//     nothing: whatever survived has already been signalled at its freshest
//     proof. The remaining check-then-act window (probe -> signal) needs a full
//     pid wrap inside one grace period; that bound is stated, not assumed;
//   - the KILL backstop is OWNED by a promise that outlives the child: every
//     process exit path awaits awaitBackstops() (bounded) before exiting. Its
//     fire-time probe re-checks the group first — members that justified it may
//     have exited during the grace window, freeing the pgid;
//   - on win32 everything goes through child.kill() — a handle-bound call that
//     is a no-op once the process is reaped — never a raw pid. win32 has NO
//     process groups, so only the LEADER is reachable: a grandchild that
//     outlives its leader is not reaped by any path here. The supported sign-off
//     legs are --os linux/darwin; a win32 local preflight is stated as out of
//     scope rather than silently assumed safe (D237 R1 L3);
//   - CRASH PATH: the first adoption in a process installs uncaughtException /
//     unhandledRejection handlers that drain the stop set and await the
//     backstops before exiting non-zero. Node's default crash exits on the spot
//     and orphans every detached group the process owns (D237 R1 M3).
//
// Callers keep their own result collection, classification and evidence
// retention; this module owns only process lifecycle.

import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';

export const BACKSTOP_GRACE_MS = 2000;        // TERM -> KILL (legs)
// Strictly ABOVE every grace a backstop can be armed with in this process
// (legs 2000; a supervised WORKER 3000): the bound is only the net for a timer
// that failed to fire, never a deadline that discards the KILL. The earlier
// 2500 sat BELOW the worker grace, so a parent could exit 500 ms before its
// worker's SIGKILL fired and take the timer with it (D237 R2 advisory LOW).
// The worker's own leg grace (2000) still lands well before the parent's
// worker-group SIGKILL (WORKER_KILL_GRACE_MS 3000); that ordering is what the
// ladder needs, not the wait bound.
export const BACKSTOP_SETTLE_BOUND_MS = 3500;

const live = new Set();
const armedBackstops = new Set();
const resolvedBackstops = new Set();
let stopName = null;
let onStopHandler = null;
// A pre-stop hook runs BEFORE any supervised child is signalled: the watchdog
// uses it to snapshot and TERM cargo's descendants while cargo still lives
// (D237 R2 corr MED-1). It is awaited; a failing hook never blocks the stop.
let onBeforeStopHandler = null;
// An exit barrier is awaited by the CRASH drain after the backstops: the
// watchdog registers its owned tree-KILL escalation there so a crash cannot
// exit before the tree escalation has fired (D237 R2 corr MED-1).
let exitBarrier = null;
export function registerExitBarrier(fn) { exitBarrier = fn; }

/** The first terminating signal seen, or null. The stop latch, one per process. */
export function stopSignal() {
  return stopName;
}

/** Platform-injectable group probe. Windows has no process groups. */
export function groupHasMembers(child, platform = process.platform) {
  if (platform === 'win32') return false;
  if (child?.pid == null) return false;
  try { process.kill(-child.pid, 0); return true; }
  catch (e) { return e.code !== 'ESRCH'; }
}

/** The decision every stop/KILL site shares: an empty group whose leader has
 *  exited can never gain members again, so it must not be signalled. */
export function shouldSignalGroup(exited, hasMembers) {
  return !exited || hasMembers;
}

/** Stop every live supervised child (the single set's legacy alias path). */
export function stopAllLive() {
  for (const supervised of live) supervised.stop('SIGTERM');
}

/**
 * CRASH PATH (D237 R1 M3). Installed by the FIRST adoption in any process:
 * Node's default crash exits immediately, and every detached group this
 * process owns is then orphaned. The handlers take the same path a terminating
 * signal takes — drain the one stop set, await the backstops (bounded), then
 * exit non-zero. Exit 2 = every backstop settled; 3 = the settle bound was
 * reached with a backstop still armed (an honest non-zero, never a silent one).
 */
function ensureCrashHandlers() {
  if (ensureCrashHandlers.installed) return;
  ensureCrashHandlers.installed = true;
  const drain = (kind, cause) => { void drainAfterCrash(kind, cause); };
  process.on('uncaughtException', (error) => drain('uncaughtException', error));
  process.on('unhandledRejection', (reason) => drain('unhandledRejection', reason));
}

let crashDrained = false;
/** True once the crash drain owns the process exit (2/3). A concurrent normal
 *  settle MUST then leave the exit to the drain: exiting with the child's own 0
 *  reports SUCCESS for a run whose supervisor crashed (D237 rule-6 RED: the
 *  crash was named and the case killed, yet the process exited 0 when the stop
 *  settle won the race). */
export function crashDraining() { return crashDrained; }
// The crash line carries a FIXED vocabulary, never free-form text: a cause's
// message can hold test output, a path or a token echoed by an upstream error,
// and this line is operator output (D237 R2-L2). The error CLASS is enough to
// tell an assertion from a TypeError; anything outside the allowlist is a
// non-error rejection or an unknown class, reported as such.
const CRASH_CLASSES = new Set(['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError', 'EvalError', 'URIError', 'AssertionError']);
function crashClass(cause) {
  if (!(cause instanceof Error)) return 'non-error';
  return CRASH_CLASSES.has(cause.name) ? cause.name : 'Error';
}
async function drainAfterCrash(kind, cause) {
  if (crashDrained) {
    // NEVER silent (zero-tolerance Rule 3): a second crash during the drain is
    // one fixed line, not swallowed and not another free-form dump.
    process.stderr.write(`CSQ_SUPERVISOR_CRASH kind=${kind} cause=secondary-during-drain\n`);
    return;
  }
  crashDrained = true;
  // THE DRAIN OWNS A NON-ZERO EXIT FROM THIS LINE ON (D237 R3 5d). The body has
  // hooks and await points; if one throws, or the process empties its event loop
  // before the final exit call below, Node must not report the crash as SUCCESS
  // (an unset exitCode is 0). The final exit refines this to 2 when every
  // backstop settled; 3 is the honest non-zero for every other shape.
  process.exitCode = 3;
  process.stderr.write(`CSQ_SUPERVISOR_CRASH kind=${kind} cause=${crashClass(cause)}\n`);
  let settled = false;
  try {
    // THE CRASH IS A STOP (D237 R2-M4): the same latch a terminating signal sets,
    // so the caller's stop-gated flows (no new attempt, no new gate) engage and
    // supervise() refuses new spawns while the drain owns the process. Without
    // it, work started during the 3.5 s drain would be orphaned by the exit.
    if (!stopName) {
      stopName = 'SIGTERM';
      onStopHandler?.('SIGTERM');
    }
    // The same pre-stop hook a terminating signal runs: stop-path and crash-path
    // must not diverge on what is reaped (D237 R2 corr MED-1).
    if (onBeforeStopHandler) {
      try { await onBeforeStopHandler(stopName); } catch { /* the stop must proceed regardless */ }
    }
    stopAllLive();
    settled = await awaitBackstops();
    if (exitBarrier) {
      try { await exitBarrier(); } catch { /* an exit barrier may not veto the exit */ }
    }
  } catch {
    // A throw inside the drain must not become a SECOND crash: the re-entry
    // would find the latch set, print the secondary line and return, leaving
    // NOBODY to own the exit. Report it in the fixed vocabulary; the finally
    // exits 3.
    process.stderr.write(`CSQ_SUPERVISOR_CRASH kind=${kind} cause=drain-failed\n`);
  } finally {
    process.exit(settled ? 2 : 3);
  }
}

function send(child, signal, platform = process.platform, ownGroup = true) {
  if (platform === 'win32' || !ownGroup) {
    // Handle-bound: after the leader is reaped this is a no-op, so it cannot
    // reach whatever process now owns the numeric pid. ownGroup:false means the
    // child shares the CALLER's group (the per-test watchdog keeps cargo in the
    // leg's group so an outer stop reaches the whole test tree); signalling that
    // group here would kill the caller's own siblings, so only the pid is sent.
    try { child.kill(signal); } catch { /* already gone */ }
    return;
  }
  try { process.kill(-child.pid, signal); } catch { /* ESRCH / already gone */ }
}

export class SupervisedChild {
  constructor(child, { graceMs = BACKSTOP_GRACE_MS, ownGroup = true } = {}) {
    this.child = child;
    this.graceMs = graceMs;
    // OWN-GROUP MODE. true (default): the child was spawned detached and its pid
    // IS its group id, so stop/KILL/sweep act on the whole group. false: the
    // child shares the CALLER's group (the per-test watchdog keeps cargo in the
    // leg's group so the outer ladder still reaches the test tree after this
    // process is SIGKILLed); signals then go to the pid, handle-bound, and there
    // is NO owned group to sweep — the group belongs to the caller.
    this.ownGroup = ownGroup;
    ensureCrashHandlers();
    this.exited = false;
    this.exitStatus = null;
    this.exitSignal = null;
    this.backstop = null;
    this.backstopPromise = null;
    this.resolveBackstop = null;
    live.add(this);
    // An ADOPTED child that arrives after the latch is already set (a crash
    // drain or a terminating signal won) is stopped at once: it must not
    // outlive the drain that cannot own it. THE CHECK SITS BELOW THE FIELD
    // INITIALISERS (D237 R2 corr L1 / sec L4): above them, stop() armed a
    // backstop whose promise the next initialisers nulled — the promise stayed
    // in armedBackstops forever, so every later awaitBackstops() returned false
    // after the full bound and a crash drain exited 3 instead of 2.
    if (stopName && child.pid !== undefined) this.stop('SIGTERM');
    // `error` with no pid never emits `exit`; mark it exited so the probe and
    // every caller's settle path see a terminal state. Removal from the stop
    // set is the supervisor's, not a caller's obligation.
    child.on('error', () => {
      if (child.pid === undefined) { this.exited = true; live.delete(this); }
    });
    // LIVENESS IS KEYED ON EXIT (never close): `close` waits for every stdio
    // holder, so a descendant in another process group can keep `close` pending
    // long after the leader is gone — and the reused-pgid guard keyed on close
    // never ran. EXIT IS ALSO THE REMOVAL: a stop set keyed on live leaders can
    // never carry a stale entry into a later signal, and no caller has to
    // remember dispose() (D237 R2 advisory HIGH).
    //
    // LEADER-EXIT SWEEP (D237 R1 H1): members that survive their leader are
    // signalled HERE, the one moment the group's ownership is freshly proven.
    // An EMPTY group can never gain members again, so an armed backstop is
    // cancelled; a NON-empty one is TERMed now and gets the KILL backstop.
    //
    // CAVEAT (fragile, do not lean on it): this handler signals only ITS OWN
    // child's group and must never synchronously stop a DIFFERENT supervised
    // child. libuv reaps a batch of children before running their exit
    // callbacks, so a sibling may already be exited without its callback having
    // run; `live` can name it, and a signal would then be aimed by numeric pid.
    child.on('exit', (status, signal) => {
      this.exited = true;
      this.exitStatus = status;
      this.exitSignal = signal;
      live.delete(this);
      if (this.ownGroup && groupHasMembers(child)) {
        // Named, fixed-vocabulary evidence: a straggler is the test-leak class
        // that once took the fleet offline, so it is never silent.
        process.stderr.write(`CSQ_GROUP_STRAGGLERS pgid=${child.pid}\n`);
        send(child, 'SIGTERM', process.platform, this.ownGroup);
        this.armBackstop();
      } else if (this.backstop) {
        // Empty owned group, or no owned group at all: nothing can be gained by
        // a later KILL, so the backstop resolves instead of holding the exit.
        this.cancelBackstop();
      }
    });
  }

  /** True when a signal was sent. An EXITED leader is never signalled by a
   *  LATER stop(): the exit-time sweep already TERMed its group at the freshest
   *  ownership proof (D237 R1 H1), so anything still alive has been signalled
   *  once already and the numeric pgid may now be ambiguous. */
  stop(signal = 'SIGTERM') {
    if (this.exited) return false;
    send(this.child, signal, process.platform, this.ownGroup);
    this.armBackstop();
    return true;
  }

  /** Arm the KILL backstop. Allowed AFTER exit: the leader-exit sweep needs the
   *  escalation, and the timer re-probes the group when it fires. */
  armBackstop() {
    if (this.backstop) return;
    this.backstopPromise = new Promise((resolve) => { this.resolveBackstop = resolve; });
    // The KILL's own due time, on the monotonic clock. awaitBackstops derives
    // its deadline from these, so a backstop armed late (the event loop itself
    // starved) keeps its full grace instead of being cut off by a deadline
    // computed before it existed.
    this.backstopPromise.dueAt = performance.now() + this.graceMs;
    armedBackstops.add(this.backstopPromise);
    this.backstop = setTimeout(() => {
      this.backstop = null;
      // Re-probe at fire time: members that justified the backstop may have
      // exited during the grace window, freeing the pgid for reuse. The shared
      // predicate is the ONE decision every stop/KILL site uses (D237 R1 L5).
      // With no owned group the probe is the pid itself: a handle-bound kill is
      // a no-op once the leader is reaped, so it is always safe to attempt.
      const fire = this.ownGroup
        ? shouldSignalGroup(this.exited, groupHasMembers(this.child))
        : true;
      if (fire) send(this.child, 'SIGKILL', process.platform, this.ownGroup);
      this.finishBackstop();
    }, this.graceMs);
  }

  cancelBackstop() {
    if (this.backstop) clearTimeout(this.backstop);
    this.backstop = null;
    this.finishBackstop();
  }

  finishBackstop() {
    if (this.backstopPromise) {
      armedBackstops.delete(this.backstopPromise);
      // Remember it: dispose() re-registers an ARMED promise for the exit path
      // to await, and a resolved one must never be mistaken for pending work
      // (a resolved promise left in the set spins the settling loop; measured
      // 2026-10-18 as the stop-retry hang).
      resolvedBackstops.add(this.backstopPromise);
    }
    this.resolveBackstop?.();
    this.resolveBackstop = null;
  }

  backstopArmed() {
    return this.backstop !== null;
  }

  awaitBackstop() {
    return this.backstopPromise ? this.backstopPromise : Promise.resolve();
  }

  /** Drop stop targets after the caller has settled; an armed backstop is kept
   *  in armedBackstops so awaitBackstops() still sees it. */
  dispose() {
    live.delete(this);
    // Keep an ARMED backstop owned so the process exit path still awaits it;
    // an already-fired or cancelled one must not be re-registered.
    if (this.backstop !== null && this.backstopPromise) armedBackstops.add(this.backstopPromise);
  }
}

/** Adopt an already-spawned child (fork, or a caller that owns spawn options).
 *  The ownership mode CANNOT be derived from an existing child: a caller whose
 *  child is NOT detached must pass ownGroup:false explicitly (the watchdog
 *  does); the default stays true for the detached callers. */
export function adopt(child, options = {}) {
  return new SupervisedChild(child, options);
}

/** Spawn and adopt in one call. The ownership mode is DERIVED from
 *  spawn.detached (D237 R2-M3): a child that is not a session leader has no
 *  group of its own, so group-mode signals are ESRCH and a TERM-ignoring member
 *  survives every stop — the latent missed-kill trap the mis-called rows hit.
 *  An EXPLICIT ownGroup:true without detached:true is refused loudly here; a
 *  caller that genuinely keeps a detached child in a foreign group must pass
 *  ownGroup:false explicitly (the watchdog does exactly that). */
// The ONE fixed phrase for a spawn refused by the stop latch. Callers classify
// on it (dev-preflight names it instead of reporting a fleet-admission error);
// it is part of this module's contract, not a message detail.
export const STOP_LATCH_REFUSAL = 'stop latched: refusing a new supervised spawn during drain';
export function supervise(command, args, { spawn: spawnOptions = {}, graceMs, ownGroup } = {}) {
  // A LATCHED STOP REFUSES NEW WORK (R2-M4): during the crash drain (and after
  // any terminating signal) a fresh group would be orphaned by the exit.
  if (stopName) throw new Error(STOP_LATCH_REFUSAL);
  const detached = spawnOptions.detached === true;
  if (ownGroup === true && !detached) {
    throw new Error('supervise: ownGroup:true requires spawn.detached:true (the child must be its own group leader)');
  }
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...spawnOptions });
  return new SupervisedChild(child, { graceMs, ownGroup: ownGroup ?? detached });
}

/**
 * ONE stop set, ONE latch, drained by every terminating signal. Idempotent.
 * The first signal wins; later signals during the drain do not re-stop.
 */
export function installStopHandlers({ onStop, onBeforeStop } = {}) {
  // Registered BEFORE the idempotence check: a later call may be the one that
  // supplies the handlers the crash drain must invoke (R2-M4).
  if (onStop) onStopHandler = onStop;
  if (onBeforeStop) onBeforeStopHandler = onBeforeStop;
  if (installStopHandlers.installed) return;
  installStopHandlers.installed = true;
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(signal, () => {
      if (stopName) {
        // A LATER signal re-drains (D237 R2 advisory LOW): a child adopted
        // after the first drain must not be left unsignalled. The first signal
        // still owns the latch and the one-time onStop side effects.
        for (const supervised of live) supervised.stop('SIGTERM');
        return;
      }
      stopName = signal;
      // The pre-stop hook runs BEFORE the stop set: the watchdog snapshots and
      // TERMs cargo's descendants while cargo still lives (corr MED-1). It is
      // async, and a hook failure must not block the stop.
      void (async () => {
        if (onBeforeStopHandler) {
          try { await onBeforeStopHandler(signal); } catch { /* the stop must proceed regardless */ }
        }
        for (const supervised of live) supervised.stop('SIGTERM');
        onStop?.(signal);
      })();
    });
  }
}

/**
 * The ONE exit path for a process that owns supervised children: fire/await
 * every armed backstop (bounded), then exit. Synchronous when nothing is armed,
 * so an exit branch keeps its exact ordering; when a backstop is armed the
 * process waits for it (bounded) instead of discarding it (R3 N1).
 *
 * EVERY CALL SITE MUST `await` IT: when a backstop is armed the exit is
 * DEFERRED, and an un-awaited call lets the caller continue into the code that
 * follows (a subset run reached the canonical receipt writer that way, measured
 * 2026-10-18). The import-graph self-test fails on any un-awaited call.
 *
 * A CRASH DRAIN OWNS THE EXIT (D237 R3 5d): once the drain is in flight this
 * function NEVER exits. The latch is re-checked after the await as well as
 * before it, because it can be set DURING the wait — a settle that exited with
 * its own code (0 when the stopped child had finished normally) reported
 * SUCCESS for a run whose supervisor crashed. Returning without exiting leaves
 * the one exit to the drain, whose awaits are bounded.
 */
export function exitAfterBackstops(code = 0) {
  if (crashDraining()) return;
  if (!armedBackstops.size) process.exit(code);
  return awaitBackstops().then(() => {
    if (crashDraining()) return;
    process.exit(code);
  });
}

/**
 * The backstop owner: resolves when every armed KILL backstop has fired or
 * been cancelled. The bound is SHARED across the whole wait, not per backstop:
 * a backstop armed BEFORE the wait is guaranteed the full
 * BACKSTOP_SETTLE_BOUND_MS (which sits above every grace armed by then), while
 * one armed LATE gets only what remains of the shared deadline. That is the
 * honest bound (D237 R1 L2): the exit paths arm their backstops before
 * awaiting, so the guarantee they need is the start-of-wait one; anything the
 * deadline cuts off is covered by the caller's next ladder rung, and the call
 * returns false rather than pretending the set drained.
 * Every process exit path that can run with an armed backstop MUST await this
 * first. Returns false when the bound was reached with backstops still armed.
 */
const SETTLE_NET_MARGIN_MS = BACKSTOP_SETTLE_BOUND_MS - BACKSTOP_GRACE_MS;

export async function awaitBackstops({ timeoutMs = BACKSTOP_SETTLE_BOUND_MS } = {}) {
  if (!armedBackstops.size) return true;
  // A backstop ARMED DURING the wait is awaited too (D237 R2 advisory LOW): a
  // single snapshot left a late-armed one to be discarded by the exit that was
  // already waiting.
  //
  // THE DEADLINE IS DERIVED FROM THE ARMED SET'S OWN DUE TIMES (2026-10-20):
  // `timeoutMs` is the net for a timer that failed to fire, and each pass waits
  // until at least every CURRENT backstop's due time plus the net margin. A
  // fixed deadline computed once could expire before a backstop that was armed
  // after it existed — measured under a starved event loop: the second stop of
  // the R fixture is armed 300 ms into the wait, and on a loaded host its grace
  // ran past the fixed 3.5 s bound, so awaitBackstops returned false and the
  // driver exited with that KILL still armed. Deriving per pass keeps the
  // documented property ("never a deadline that discards the KILL") structurally
  // true; the parent's worker-group SIGKILL remains the outer net.
  const deadlineFor = () => {
    let deadline = performance.now() + timeoutMs;
    for (const p of armedBackstops) {
      if (Number.isFinite(p.dueAt)) deadline = Math.max(deadline, p.dueAt + SETTLE_NET_MARGIN_MS);
    }
    return deadline;
  };
  while (armedBackstops.size) {
    for (const p of [...armedBackstops]) if (resolvedBackstops.has(p)) armedBackstops.delete(p);
    if (!armedBackstops.size) break;
    const pending = [...armedBackstops];
    const remaining = deadlineFor() - performance.now();
    if (remaining <= 0) return false;
    let timer;
    const bound = new Promise((resolve) => { timer = setTimeout(() => resolve(false), remaining); });
    const settled = Promise.allSettled(pending).then(() => true);
    const ok = await Promise.race([settled, bound]);
    clearTimeout(timer);
    if (!ok) return false;
  }
  // Settled: no promise can re-enter armedBackstops after its fire/cancel
  // (dispose re-adds only while a timer is still armed), so the resolved memo
  // is pruned here rather than growing for the life of the process (D237 R1
  // corr L4). The false returns above keep it: their entries may still matter.
  resolvedBackstops.clear();
  return true;
}
