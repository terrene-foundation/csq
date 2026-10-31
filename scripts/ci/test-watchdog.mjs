#!/usr/bin/env node
// test-watchdog.mjs — a per-TEST wall bound for a cargo-test sign-off leg.
//
// THE GAP THIS CLOSES (D237 rule 8, measured 2026-10-18): a darwin sign-off leg
// (`cargo test --workspace --lib --bins`) hung for 64+ minutes with no way to
// name the test that was spinning. The leg's caller bound
// (LEG_CALLER_TIMEOUT_MS, 65 min/attempt) turns a hang into a bounded red, but
// that red is OPAQUE — it says "the leg did not finish", never WHICH test hung,
// and it costs the full 65 minutes to say it.
//
// WHAT IT DOES: runs the command with stdout/stderr passed through UNCHANGED
// while reading libtest's result stream. MULTI-THREADED IS THE PRODUCTION
// SHAPE: libtest prints a `test NAME ... ` start line ONLY when single-threaded
// (pretty.rs write_test_start is gated on !is_multithreaded), and both
// cargo-test legs run multi-threaded (lib-bins by default, integration with
// --test-threads=2). In that mode the ONLY in-flight signal is libtest's own
// `test NAME has been running for over 60 seconds`, so that warning IS a start
// signal — accepted ONLY inside the binary's window, between its
// `running N tests` line and the `failures:` / `test result:` line that closes
// its FRAME. Frames NEST (D237 R2-M2): a test may re-execute its own binary as
// a libtest helper with inherited stdio, and that helper's `running` /
// `test result:` pair opens and closes a nested frame without ending the outer
// one. A test CAN forge lines: libtest's capture covers print!, never raw fd
// writes from a subprocess with inherited stdio. The direction of each forgery
// is stated, never assumed, and it is NOT uniformly "RED early" (D237 R2 corr
// L1): a forged `test ... ok` line advances the progress clock (it can hide a
// real stall), and a forged outermost `test result:` line closes the binary and
// drops its open tests (it can hide a real hang). Both fail toward a MISSED
// per-test bound, never toward a wrong PASS — the caller's 65 min leg bound
// still holds and the leg verdict is unaffected — so the residual is a missed
// diagnosis, not a fail-open. A nested pair can never drop an outer open test.
// A CRASHED binary's opens are cleared at the next OUTERMOST window:
// a `running` that arrives while the open test was START-opened (serial mode)
// means the binary that opened it is gone, while a WARNING-opened open (the
// multi-threaded production shape) keeps its window through a nested helper;
// the serial-helper residual is stated at that boundary. Outside a frame the
// warning is foreign or forged: ignored and counted (D237 R1 H3 / ROOT's
// corrected directive).
//
// IT FIRES ON STALLED PROGRESS, NOT ON A TEST'S ELAPSED AGE (ROOT ruling
// 2026-10-20). Libtest's elapsed time for a test includes time it spent QUEUED
// behind a process-global test lock, so an age bound cannot tell a hung test
// from a healthy one waiting on a healthy holder — measured: a trivial pty test
// took 173 s under load and 2.6 s alone, and the 120 s age bound killed a
// healthy queued test twice. The trigger is therefore: at least one test is OPEN
// and the binary has COMPLETED NO TEST for --per-test-ms (the stall window; the
// caller derives it from the enforced positive-path wait envelope). A queued
// waiter behind live progress is never killed; a hung lock holder eventually
// stalls the whole queue and is caught, bounded by the suite time plus one
// window. On a stall it
//   1. prints `CSQ_TEST_WATCHDOG_STALL no_completion_ms=<n> open_tests=<k>`,
//      then one `CSQ_TEST_WATCHDOG_TIMEOUT name=<name> elapsed_ms=<age>` line
//      on stdout for EVERY open test (age from its start line or its warning),
//   2. samples the running test process's stacks BEFORE any signal (darwin
//      `sample`; linux gdb with a /proc/<pid>/task/*/stack fallback), printing
//      the sample under SAMPLE_BEGIN/END, or SAMPLE_UNAVAILABLE with the
//      instrument's own reason — a failed instrument is REPORTED, never omitted.
//      Sampling is ASYNCHRONOUS and bounded (the event loop, the ticker and the
//      stop handlers stay live while a slow sampler runs), unlike the blocking
//      calls that could delay a forwarded TERM by tens of seconds (D237 R1 M2),
//   3. TERMs the watched command and arms its OWNED SIGKILL backstop.
//
// PROCESS LIFECYCLE (D237 R1 H2). The watched command is deliberately NOT
// detached: it stays in the LEG's process group, the group the caller's ladder
// reaches (TERM, then SIGKILL after the caller's leg grace). That is
// what makes an outer stop total: a SIGHUP, a group TERM, or even a SIGKILL of
// THIS process still reaches cargo and every test binary, because the kernel
// signals the group rather than relying on this process being alive. A signal
// delivered to THIS PROCESS ALONE (or a crash inside it) does not ride that
// ladder, so EVERY exit path — the stall tick, the stop handlers and the crash
// drain — runs the same tree reap (D237 R2 corr MED-1): cargo's descendants are
// snapshotted while cargo still lives, TERMed, and SIGKILLed at the grace if
// they survive. The
// command is adopted through scripts/ci/child-supervisor.mjs in its own-group-
// OFF mode: signals go to the pid, handle-bound (never to the caller's group,
// whose other members are not ours), liveness is keyed on exit, and every exit
// path awaits the one backstop owner. The watchdog's grace (default 1000 ms) is
// strictly BELOW the caller's leg grace, so on a shared stop this process finishes
// its verdict and its KILL before the outer SIGKILL.
//
// What a per-test timeout guarantees BY ITSELF (D237 R2-H1): the test is NAMED;
// the OBSERVED TEST TREE is signalled directly — a ps snapshot of cargo's
// descendants is taken while cargo is still alive (its child is pinned then),
// every pid is re-checked against its recorded START TIME (pid+started is the
// identity; a reparented orphan keeps its start time but not its ppid, so the
// escalation does not assume reparent-to-init), TERMed deepest-first, and
// SIGKILLed at the grace if it survives — and only then is cargo stopped; the
// leg exits 124. This matters on a REMOTE leg above all: the
// watchdog and the test tree run on the fleet host, where no csq supervisor
// exists to reap the leg's group, so the kill must not depend on one. The
// leg-level leader-exit sweep (D237 R1 H1) remains the backstop for anything
// else the leg leaves in its group when the leg leader exits, and for a SIGKILL
// of this process. On win32 there are no process groups: that ladder reaches
// only the leader, and the supported sign-off legs are --os linux/darwin —
// stated, not assumed (D237 R1 L3).
//
// Exit: the child's own status; 124 when a test was killed by the bound; 2 on a
// usage error. On success it prints one summary line naming the slowest test and
// its duration, so the bound is sized from MEASURED worsts rather than chosen
// (`tooling-self-verification.md` Rule 3).
//
// The watchdog is wired through the locked-cargo shim in `preflight-runtime.mjs`
// (the `test` subcommand), so the leg commands themselves stay byte-identical.

import { spawn, execFile } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { promisify } from 'node:util';
import { adopt, installStopHandlers, exitAfterBackstops, registerExitBarrier, stopSignal, crashDraining } from './child-supervisor.mjs';
import { CALLER_KILL_GRACE_MS } from './preflight-runtime.mjs';

const execFileAsync = promisify(execFile);
const USAGE = 'usage: test-watchdog.mjs --per-test-ms <n> [--sample-ms <n>] [--kill-grace-ms <n>] -- <command> [args...]';
// The caller's leg-group KILL is IMPORTED from the one place that states it
// (D237 R2-M5: the former local `CALLER_LEG_GRACE_MS = 2000` copy drifted the
// moment preflight-runtime's constant moved). This process must fire its own
// KILL FIRST: a grace at or above the caller's ceiling would be discarded by
// the caller's SIGKILL before it fired (D237 R1 M2). lockedScript emits
// WATCHDOG_KILL_GRACE_MS explicitly, which the load-time ladder assertion keeps
// strictly below this value; the check below guards direct invocations. On a
// remote leg the ceiling is the LOCAL client's clock — the two clocks cannot be
// ordered here (stated limit, preflight-runtime's ladder comment).

class UsageError extends Error {}

function usage(message) {
  throw new UsageError(message);
}

function parseArgs(argv) {
  const opts = { perTestMs: null, sampleMs: 3_000, killGraceMs: 1_000, command: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') { opts.command = argv.slice(i + 1); break; }
    const take = () => {
      const value = argv[i + 1];
      if (value === undefined) usage(`${arg} needs a value`);
      i += 1;
      return value;
    };
    switch (arg) {
      case '--per-test-ms': opts.perTestMs = Number(take()); break;
      case '--sample-ms': opts.sampleMs = Number(take()); break;
      case '--kill-grace-ms': opts.killGraceMs = Number(take()); break;
      default: usage(`unknown argument ${arg}`);
    }
  }
  if (!Number.isInteger(opts.perTestMs) || opts.perTestMs <= 0) usage('--per-test-ms must be a positive integer');
  if (!Number.isInteger(opts.sampleMs) || opts.sampleMs <= 0) usage('--sample-ms must be a positive integer');
  if (!Number.isInteger(opts.killGraceMs) || opts.killGraceMs <= 0) usage('--kill-grace-ms must be a positive integer');
  if (opts.killGraceMs >= CALLER_KILL_GRACE_MS) usage(`--kill-grace-ms must be strictly below the caller's ${CALLER_KILL_GRACE_MS} ms leg grace`);
  if (!opts.command.length) usage('a command is required after --');
  return opts;
}

let opts;
try {
  opts = parseArgs(process.argv.slice(2));
} catch (error) {
  if (!(error instanceof UsageError)) throw error;
  process.stderr.write(`test-watchdog: ${error.message}\n${USAGE}\n`);
  // No child exists yet, so nothing is armed; the call is synchronous and exits.
  await exitAfterBackstops(2);
}

// ── libtest observation (D237 R1 H3/M1, ROOT's corrected directive).
//
// Multi-threaded is the production shape (see the header). Every scan is
// ANCHORED and line-bounded — never a lazy match over the whole buffer — so the
// parser stays linear even at the 4 MiB partial budget (D237 R1 M4).
const TERMINAL = new Set(['ok', 'FAILED', 'ignored', 'measured', 'bench']);
const MAX_LINE = 2000;             // one output line; bounded before any regex
const MAX_PARTIAL = 4 * 1024 * 1024;
const WARNING_AGE_MS = 60_000;     // libtest's own fixed threshold

// Per-BINARY state (D237 R1 M1): `cargo test` runs one binary at a time and a
// test name repeats across integration binaries, so names are keyed per
// binary — a global map suppressed a later binary's hang.
//
// NESTING (D237 R2-M2): a test may RE-EXECUTE its own binary as a libtest
// helper with inherited stdio (`--exact <helper> --nocapture`), which prints
// its own `running N tests` / `test result:` pair. Those lines are a FRAME:
// a `running` INSIDE an open binary pushes, a `test result:` pops, and only the
// OUTERMOST close ends the binary. A nested close therefore can never drop the
// outer binary's open tests — the forged early-close window the R2 probe
// exercised.
let binary = null;            // the OUTERMOST open binary
const completedDurations = []; // finished binaries' duration maps (for the summary)
let partial = '';
let ignoredWarnings = 0;
// CARGO'S OWN BINARY HEADER (D237 R2 corr L2). Cargo prints `     Running
// unittests …` (stderr) immediately BEFORE a new test binary's `running N
// tests` (stdout). A nested libtest helper is a re-exec of the SAME binary and
// gets NO such line. That marker is the only structural discriminator between
// "the next binary started" and "this binary re-executed itself as a helper",
// so a CRASHED multi-threaded binary's warning-opened test is closed at the
// next binary instead of staying open for the rest of the run. Stated limit:
// the two are separate pipes, so a late-delivered marker can only make this
// one boundary behave as before (a missed close, never a missed open).
// cargo names the next target on stderr as `Running <target>` (`unittests
// src/lib.rs`, `tests/x.rs`, …) or `Doc-tests <crate>` (D237 R2 corr L2). The
// former `Running (?:unittests|tests|doc-tests) ` missed `tests/x.rs` (no space
// before the slash), the capitalized `Doc-tests`, and a COLOURED line (cargo
// emits ANSI CSIs when stderr is a TTY and CARGO_TERM_COLOR is not set). The
// regex is deliberately narrow and lexical: those two line shapes only — any
// other cargo output is NOT a boundary.
const ANSI_CSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
let cargoRunningBoundary = false;
function noteStderr(chunk) {
  const text = String(chunk).replace(ANSI_CSI, '');
  if (/(^|\n)\s*(?:Running \S|Doc-tests )/.test(text)) cargoRunningBoundary = true;
}

function newFrame() {
  return { inFailures: false, opens: new Map(), durations: new Map(), warned: new Set() };
}
function beginBinary() {
  binary = { stack: [newFrame()] };
}
function endBinary() {
  // `test result:` at depth 1 ends the binary: nothing it started is running.
  // Every frame's durations are kept for the summary; its opens die with it.
  if (binary) { for (const frame of binary.stack) completedDurations.push(frame.durations); }
  binary = null;
}
function topFrame() { return binary ? binary.stack[binary.stack.length - 1] : null; }
function inFailures() { const top = topFrame(); return top ? top.inFailures : false; }

// ONE anchored shape covers BOTH start and result lines. The tail's first word
// decides: a terminal word completes the test (`ignored, <reason>`,
// `FAILED (time limit exceeded)` and --report-time suffixes such as
// `ok <0.01s>` all match); an empty tail is a serial-mode start. A start line
// inside the failures listing comes from captured output, so it is ignored —
// only libtest prints RESULT lines, and a completion is honoured there too.
function startsOrCompletes(line, now) {
  const m = /^test (.{1,500}?) \.\.\.(?: *)(.*)$/.exec(line);
  if (!m) return;
  const frame = topFrame();
  if (!frame) return;
  const name = m[1];
  const word = /^([A-Za-z]+)/.exec(m[2]);
  if (word && TERMINAL.has(word[1])) {
    lastProgress = now;
    const start = frame.opens.get(name);
    if (start !== undefined) {
      frame.opens.delete(name);
      frame.durations.set(name, now - start);
    } else if (!frame.durations.has(name)) {
      // Multi-threaded mode never shows a start line: the test completed but
      // its duration is UNMEASURED. It is still COUNTED (the summary's total
      // is a count, and the slowest line is only claimed from measured
      // starts — serial mode or a warning-opened test).
      frame.durations.set(name, 0);
    }
    return;
  }
  if (frame.inFailures) return;
  if (!frame.opens.has(name) && !frame.durations.has(name)) frame.opens.set(name, now);
}

// Libtest's own "still running" line: in multi-threaded mode it is the ONLY
// in-flight signal, so inside the binary's window it OPENS the test at the
// earliest time libtest's own statement permits (now - 60 s); an earlier start
// is never moved later. Outside the window it is foreign or forged: counted and
// ignored. The fixed wording is matched in full — extra words never match.
function warningIn(line, now) {
  const m = /^test (.{1,500}) has been running for over 60 seconds$/.exec(line);
  if (!m) return;
  const frame = topFrame();
  if (!frame || frame.inFailures) { ignoredWarnings += 1; return; }
  const name = m[1];
  if (frame.durations.has(name)) return;
  if (!frame.opens.has(name)) frame.opens.set(name, now - WARNING_AGE_MS);
  frame.warned.add(name);
}

function boundaryIn(line, now) {
  if (/^running \d+ tests?$/.test(line)) {
    lastProgress = now;
    // Inside an open binary this is EITHER a nested libtest helper window OR a
    // NEW binary after the previous one CRASHED (D237 R2-M2/M1). The only
    // line-level discriminator: a live multi-threaded binary's in-flight test
    // was opened by its 60 s WARNING (the production shape), while a crashed
    // serial binary's open came from a START line. Warning-opened → push a
    // nested frame and keep the outer window; start-opened (or no open) → the
    // outer binary is gone: clear its opens by starting a fresh outermost one.
    // Residual, stated: a nested helper under a SERIAL outer binary is
    // indistinguishable from a crash and clears that serial open (a missed
    // per-test bound, still bounded by the caller's 65 min ladder).
    const frame = topFrame();
    const warnedOpen = frame && [...frame.opens.keys()].some((name) => frame.warned.has(name));
    const nextBinary = cargoRunningBoundary;
    cargoRunningBoundary = false;
    if (binary && warnedOpen && !nextBinary) binary.stack.push(newFrame());
    else { if (binary) endBinary(); beginBinary(); }
    return true;
  }
  if (/^failures:$/.test(line)) { const frame = topFrame(); if (frame) frame.inFailures = true; return true; }
  // GRAMMAR, not a bare token (D237 R2-M2): libtest's own result line carries
  // the verdict and its counts. A forged `test result:` without the grammar is
  // not a close at all (fails toward a missed close, never a missed OPEN).
  if (/^test result: (?:ok|FAILED)\.\s/.test(line)) {
    if (binary) { if (binary.stack.length > 1) binary.stack.pop(); else endBinary(); }
    return true;
  }
  return false;
}

function observe(chunk) {
  const now = performance.now();
  let buffer = partial + chunk.toString();
  let nl;
  while ((nl = buffer.indexOf('\n')) !== -1) {
    let line = buffer.slice(0, nl);
    if (line.length > MAX_LINE) line = line.slice(0, MAX_LINE);
    if (!boundaryIn(line, now)) { startsOrCompletes(line, now); warningIn(line, now); }
    buffer = buffer.slice(nl + 1);
  }
  partial = buffer.length > MAX_PARTIAL ? buffer.slice(-MAX_PARTIAL) : buffer;
  // The partial line always begins at a line boundary; scan only its bounded
  // head — a serial-mode start line arrives WITHOUT a newline, so it lives here.
  startsOrCompletes(partial.slice(0, MAX_LINE), now);
}

// ── Sampling. ASYNC and bounded: execFile (never execFileSync) with a timeout
// and a maxBuffer, plus a printed-text cap, so a slow sampler can never block
// the ticker or the stop handlers for the seconds `sample`/`gdb` take (D237 R1
// M2). Pids come from a ps snapshot and are NOT pinned — the attach could reach
// a recycled same-uid pid only after a full pid wrap inside a few milliseconds;
// the instruments pause the target rather than kill it (D237 R1 L4, noted).
const SAMPLE_TEXT_CAP = 32 * 1024;
// lstart is carried for the TREE KILL (R2-H1): a pid is signalled only when a
// fresh snapshot shows the SAME start time. THE IDENTITY IS pid + lstart; the
// PARENT IS NOT RECHECKED (D237 R2 sec M3: an orphan reparents to the nearest
// PR_SET_CHILD_SUBREAPER ancestor, not to pid 1, so a ppid gate skipped real
// targets). REAL RESIDUAL (sec N3, stated, not claimed away): lstart has 1 s
// resolution, so a pid recycled within the same second and showing the same
// printed start time can still be signalled.
// THE SNAPSHOT HAS TWO BOUNDS (D237 R3 5d, M-B). execFile's own timeout, with
// killSignal SIGKILL, is the first: its default TERM can be ignored by a
// wrapper script, and the promise then stayed pending until the wrapper's own
// work ended — measured with a PATH `ps` that traps TERM and sleeps, where
// every exit path waited out the whole sleep and the empty snapshot read as
// "no descendants". The race below is the net for a settle that never arrives
// at all (unreachable with an unblockable SIGKILL — stated, not claimed as a
// live path); it rejects at the hard bound and flows into the SAME
// TREE_UNAVAILABLE / SAMPLE_UNAVAILABLE reporting every caller already has.
const PS_SNAPSHOT_TIMEOUT_MS = 5_000;
const PS_SNAPSHOT_HARD_MS = 5_500;
async function psSnapshot() {
  let timer;
  const hard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`ps snapshot exceeded ${PS_SNAPSHOT_HARD_MS} ms`)), PS_SNAPSHOT_HARD_MS);
    timer.unref?.();
  });
  const run = execFileAsync('ps', ['-Ao', 'pid=,ppid=,pgid=,lstart=,command='], {
    encoding: 'utf8', timeout: PS_SNAPSHOT_TIMEOUT_MS, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024, env: { ...process.env, LC_ALL: 'C' },
  });
  // The race owns the report once the hard bound fires; this arm only keeps a
  // LATE rejection from the abandoned run (it settles when the stray pipe
  // finally closes) from becoming an unhandled rejection, which the supervisor
  // would treat as a second crash.
  void run.catch(() => {});
  let stdout;
  try {
    ({ stdout } = await Promise.race([run, hard]));
  } finally {
    clearTimeout(timer);
  }
  return stdout.split('\n').map((line) => {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4})\s+(.*)$/.exec(line);
    return m ? { pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]), started: m[4], command: m[5] } : null;
  }).filter(Boolean);
}

/** Descendants of `rootPid`, DEEPEST FIRST (a child is TERMed before its parent
 *  so the parent cannot reparent it mid-reap). */
function descendantsOf(rootPid, snapshot) {
  const byParent = new Map();
  for (const p of snapshot) {
    if (!byParent.has(p.ppid)) byParent.set(p.ppid, []);
    byParent.get(p.ppid).push(p);
  }
  const out = [];
  const queue = [[rootPid, 0]];
  while (queue.length) {
    const [pid, depth] = queue.shift();
    for (const child of byParent.get(pid) || []) {
      out.push({ ...child, depth: depth + 1 });
      queue.push([child.pid, depth + 1]);
    }
  }
  return out.sort((a, b) => b.depth - a.depth);
}

function sampleText(pid, tool, text) {
  const raw = String(text);
  const capped = raw.length > SAMPLE_TEXT_CAP
    ? `${raw.slice(0, SAMPLE_TEXT_CAP)}\n[sample truncated at ${SAMPLE_TEXT_CAP} chars of ${raw.length}]`
    : raw;
  process.stdout.write(`CSQ_TEST_WATCHDOG_SAMPLE_BEGIN pid=${pid} tool=${tool}\n${capped}\nCSQ_TEST_WATCHDOG_SAMPLE_END pid=${pid}\n`);
}
function sampleUnavailable(pid, tool, reason) {
  process.stdout.write(`CSQ_TEST_WATCHDOG_SAMPLE_UNAVAILABLE pid=${pid} tool=${tool} reason=${String(reason).replace(/\s+/g, ' ').slice(0, 300)}\n`);
}

async function sampleProcess(pid) {
  if (process.platform === 'darwin') {
    try {
      const { stdout } = await execFileAsync('sample', [String(pid), '3', '-mayDie'], { encoding: 'utf8', timeout: opts.sampleMs + 10_000, maxBuffer: 4 * 1024 * 1024 });
      sampleText(pid, 'sample', stdout);
    } catch (e) {
      sampleUnavailable(pid, 'sample', (e && (e.stdout || e.message)) || e);
    }
    return;
  }
  try {
    const { stdout } = await execFileAsync('gdb', ['-batch', '-p', String(pid), '-ex', 'set pagination off', '-ex', 'set print frame-arguments none', '-ex', 'thread apply all bt'],
      { encoding: 'utf8', timeout: opts.sampleMs + 17_000, maxBuffer: 4 * 1024 * 1024 });
    sampleText(pid, 'gdb', stdout);
    return;
  } catch (e) {
    const captured = `${(e && e.stdout) || ''}${(e && e.stderr) || ''}`;
    if (captured && /^#\d+|Backtrace|Thread \d+/m.test(captured)) { sampleText(pid, 'gdb', captured); return; }
    // Fallback: kernel stacks per task. Usually readable only as root; when it is
    // not, the reason is reported rather than the sample being omitted.
    try {
      const tasks = readdirSync(`/proc/${pid}/task`);
      const parts = [];
      for (const task of tasks.slice(0, 8)) {
        try { parts.push(`== task ${task}\n${readFileSync(`/proc/${pid}/task/${task}/stack`, 'utf8')}`); }
        catch (inner) { parts.push(`== task ${task}: ${String(inner.message || inner)}`); }
      }
      sampleText(pid, 'proc-stack', parts.join('\n'));
    } catch (inner) {
      sampleUnavailable(pid, 'gdb', (e && (e.message || e)) + ' | /proc fallback: ' + String(inner.message || inner));
    }
  }
}

async function sampleGroup() {
  let found;
  try { found = await psSnapshot(); }
  catch (e) { sampleUnavailable(0, 'ps', (e && e.message) || e); return; }
  // Candidates are CARGO'S DESCENDANTS, DEEPEST FIRST (D237 R2 corr MED-2): the
  // leg's GROUP also holds the leg's own bash/node wrappers, whose lower pids
  // would fill any fixed slice while the spinning test binary was never sampled
  // yet SAMPLE_BEGIN/END still printed as success. The old `/cargo|rustc|node/`
  // name filter also dropped a legitimate test binary whose path contained one
  // of those words. When nothing is sampled that is said plainly below.
  const candidates = descendantsOf(child.pid, found);
  if (!candidates.length) {
    sampleUnavailable(0, 'none', 'ps shows no descendant of the watched command; the hung test was not sampled');
    return;
  }
  for (const candidate of candidates.slice(0, 3)) await sampleProcess(candidate.pid);
}

// ── TREE KILL (D237 R2-H1). Pid mode signals cargo alone, and cargo does not
// forward SIGTERM to the test binary it is waiting on: without this, a per-test
// timeout would name the hung test and exit 124 while the test process kept
// spinning on the leg's host (nothing csq-side reaps a REMOTE leg). The tree is
// snapshotted BEFORE cargo is signalled — while cargo lives its direct child is
// pinned unreaped, and the grandchildren are pinned by it in turn — and every
// signal re-checks the recorded START TIME first (pid + lstart; the parent is
// NOT rechecked, M3). REAL RESIDUAL (sec N3): lstart has 1 s resolution, so a
// pid recycled within the same second can still be hit; that second is the
// bound this check has, not a guarantee. Deepest-first: a child is signalled
// before its parent.
// THE IN-FLIGHT PROMISE IS THE LATCH (D237 R2 sec N1). The former boolean latch
// returned null to a SECOND caller while the first reap was still inside `ps`;
// a child exit (finishWhenSettled) or a crash drain reaching its exit barrier in
// that window then settled and exited, DISCARDING the KILL that was still being
// armed. Now the first call starts the one reap and every later caller receives
// the SAME promise, so no exit path can pass a reap that has not finished.
// A SKIP IS NEVER SILENT (zero-tolerance Rule 3). The identity gate below refuses
// to signal a pid whose START TIME changed since the snapshot that named it: that
// is a recycled pid (a stranger), and signalling it would kill the wrong process.
// The skip is correct; saying nothing about it is not. A pid that is PRESENT with
// a different start time is reported by name and phase (term | kill); a pid that
// has simply GONE is the normal outcome of a TERM and is never reported.
function reportIdentityChanged(pid, phase) {
  process.stderr.write(`CSQ_TEST_WATCHDOG_TREE_IDENTITY_CHANGED pid=${pid} phase=${phase}\n`);
}
let treeReap = null;
function beginTreeReap() {
  // EVERY EXIT PATH RUNS THIS (D237 R2 corr MED-1): the stall tick, the stop
  // handlers and the crash drain. Before this, only the stall tick reaped the
  // tree, so a TERM to the watchdog ALONE (or a crash inside it) stopped cargo
  // and let every test binary survive — measured: rc 143 with `sleep 29` alive,
  // reparented to init. The promise makes repeated stops (a second signal, a
  // child exit, or a stop racing the stall tick) share one snapshot and one
  // escalation.
  treeReap ??= (async () => {
    // AN EXITED LEADER IS NOT A TREE ROOT (D237 R3 5d, M-A): once the watched
    // command has closed, its pid may be reaped or recycled and no snapshot can
    // attribute a tree to it. Whatever it left alive is the leg-level
    // leader-exit sweep's to reap, never a numerical descendance claim here.
    // NOT SILENT (zero-tolerance: a kill path must never skip without a
    // reason): a caller that expected a tree line gets WHY there is none,
    // instead of an output file that explains nothing.
    if (childClosed) {
      // A spawn that never produced a pid leaves child.pid undefined; say so
      // rather than printing the literal string "undefined" as if it were a pid.
      process.stdout.write(`CSQ_TEST_WATCHDOG_TREE_UNAVAILABLE reason=leader-exited:pid=${child.pid ?? 'none'}\n`);
      return null;
    }
    let snapshot;
    try { snapshot = await psSnapshot(); }
    catch (e) {
      // A failed ps is NO LONGER SWALLOWED (D237 R2 sec M3): the tree could not
      // be enumerated, so the leg's own ladder is the only remaining net and the
      // reason is printed for the operator.
      process.stdout.write(`CSQ_TEST_WATCHDOG_TREE_UNAVAILABLE reason=${String(e && e.message ? e.message : e).replace(/\s+/g, ' ').slice(0, 200)}\n`);
      return null;
    }
    // THE LEADER'S ROW MUST STILL BE OURS (D237 R3 5d, M-A). pid alone is not
    // identity across a reap: a recycled pid carries a different parent. A
    // zombie's row still names THIS process as its parent, so the check admits
    // the still-unreaped leader while rejecting both a recycled pid and a row
    // that vanished already; with no attributed root there is no tree to signal.
    const leader = snapshot.find((p) => p.pid === child.pid);
    if (!leader || leader.ppid !== process.pid) {
      process.stdout.write(`CSQ_TEST_WATCHDOG_TREE_UNAVAILABLE reason=leader-identity:pid=${child.pid} observed_ppid=${leader ? leader.ppid : 'absent'}\n`);
      return null;
    }
    // PID + START TIME is the identity (D237 R2 sec M3 / corr MED-1): the old
    // ppid gate assumed an orphan reparents to pid 1, but on Linux it reparents
    // to the nearest PR_SET_CHILD_SUBREAPER ancestor (systemd --user, a container
    // init), where the ppid is neither the recorded parent nor 1 and the KILL was
    // skipped. Membership is established here, once, by descendantsOf(child.pid);
    // a same-uid pid reuse still has to reproduce the same lstart second.
    const targets = descendantsOf(child.pid, snapshot).map((p) => ({ pid: p.pid, started: p.started }));
    process.stdout.write(`CSQ_TEST_WATCHDOG_TREE targets=${targets.length}\n`);
    if (!targets.length) return null;
    let fresh;
    try { fresh = await psSnapshot(); } catch (e) {
      process.stdout.write(`CSQ_TEST_WATCHDOG_TREE_UNAVAILABLE reason=recheck:${String(e && e.message ? e.message : e).replace(/\s+/g, ' ').slice(0, 160)}\n`);
      fresh = [];
    }
    const freshBy = new Map(fresh.map((p) => [p.pid, p]));
    for (const t of targets) {
      const now = freshBy.get(t.pid);
      if (!now) continue;
      if (now.started !== t.started) { reportIdentityChanged(t.pid, 'term'); continue; }
      try { process.kill(t.pid, 'SIGTERM'); } catch { /* ESRCH / already gone */ }
    }
    // OWNED escalation: survivors take SIGKILL at the grace. It is INSIDE the
    // returned promise, so every caller awaits the KILL, not just the TERM.
    return new Promise((resolve) => {
      setTimeout(async () => {
        let later;
        try { later = await psSnapshot(); } catch (e) {
          // NOT a silent fallback (D237 R2 sec N2): the re-check could not run,
          // so the KILL is skipped for every target and the operator must see it.
          // Same vocabulary and reason prefix as the other ps sites.
          process.stdout.write(`CSQ_TEST_WATCHDOG_TREE_UNAVAILABLE reason=kill-recheck:${String(e && e.message ? e.message : e).replace(/\s+/g, ' ').slice(0, 160)}\n`);
          later = [];
        }
        const laterBy = new Map(later.map((p) => [p.pid, p]));
        for (const t of targets) {
          const now = laterBy.get(t.pid);
          if (!now) continue;
          if (now.started !== t.started) { reportIdentityChanged(t.pid, 'kill'); continue; }
          try { process.kill(t.pid, 'SIGKILL'); } catch { /* gone */ }
        }
        resolve();
      }, opts.killGraceMs);
    });
  })();
  return treeReap;
}

// ── Run. NOT detached: cargo stays in the leg's group, which is the group every
// outer ladder signal reaches (see PROCESS LIFECYCLE). The supervisor owns
// liveness and the KILL backstop; its own-group-off mode signals the pid only.
const child = spawn(opts.command[0], opts.command.slice(1), {
  cwd: process.cwd(), env: process.env, stdio: ['ignore', 'pipe', 'pipe'],
});
const supervised = adopt(child, { graceMs: opts.killGraceMs, ownGroup: false });
// Every stop path takes the SAME tree reap before cargo is signalled (corr
// MED-1): the signal handler awaits this hook before stopping the live set, and
// the crash drain awaits it too. The IN-FLIGHT REAP PROMISE is registered as the
// supervisor's exit barrier (sec N1), so a crash drain that reaches it while the
// first reap is still in `ps` waits for it instead of exiting and discarding the
// tree KILL.
installStopHandlers({ onBeforeStop: () => beginTreeReap() });
registerExitBarrier(() => treeReap || Promise.resolve());
for (const stream of [child.stdout, child.stderr]) {
  stream.on('data', (chunk) => {
    (stream === child.stdout ? process.stdout : process.stderr).write(chunk);
    if (stream === child.stdout) observe(chunk);
    else noteStderr(chunk);
  });
}

let timedOutName = null;
// PROGRESS CLOCK: advanced by a frame opening and by every completed test.
let lastProgress = performance.now();
let childClosed = false;
let signalDelivered = false;

const tick = setInterval(() => {
  if (timedOutName || childClosed) return;
  const now = performance.now();
  const open = [];
  if (binary) for (const frame of binary.stack) for (const [name, start] of frame.opens) open.push([name, start]);
  // No in-flight test: the command may legitimately be between binaries (cargo
  // builds the next test target), and no test can be hung while none is open.
  if (!open.length) return;
  const stalled = now - lastProgress;
  if (stalled <= opts.perTestMs) return;
  // PROGRESS-BASED: a per-test ELAPSED bound cannot discriminate a hung test
  // from one queued behind a healthy holder of a process-global lock, because
  // libtest's elapsed includes queue time (measured: 173 s queued vs 2.6 s
  // alone). Completing NOTHING for the window is the property that only a real
  // stall produces; name EVERY open test so a blocked lock holder and its
  // waiters are all visible.
  open.sort((a, b) => a[1] - b[1]);
  timedOutName = open[0][0];
  process.stdout.write(`CSQ_TEST_WATCHDOG_STALL no_completion_ms=${Math.round(stalled)} open_tests=${open.length}\n`);
  for (const [name, start] of open) {
    process.stdout.write(`CSQ_TEST_WATCHDOG_TIMEOUT name=${name} elapsed_ms=${Math.round(now - start)}\n`);
  }
  // Sample BEFORE any signal, asynchronously: the loop and the stop handlers
  // stay live, so an outer stop still reaches cargo while a slow sampler runs.
  // The stop closes over `supervised`, which refuses once the leader exited.
  void (async () => {
    await sampleGroup();
    await beginTreeReap();
    // Cargo goes LAST, after its tree has been signalled.
    signalDelivered = supervised.stop('SIGTERM');
  })();
}, 500);
tick.unref?.();

child.on('error', async (error) => {
  process.stderr.write(`CSQ_TEST_WATCHDOG_SPAWN_ERROR ${String(error && error.message ? error.message : error)}\n`);
  await exitWith(1);
});

// ── Settlement. The preflight's own rule is "settle on EXIT, not on close": a
// background grandchild can hold the inherited pipe long after the command has
// finished (the pipe-holder fixtures pin exactly that). The watchdog therefore
// settles on the child's EXIT after a short bounded drain, and settles at once
// when close arrives first.
let settled = false;
let drainTimer = null;
function settle(code, signal) {
  if (settled) return;
  settled = true;
  childClosed = true;
  clearInterval(tick);
  if (drainTimer) clearTimeout(drainTimer);
  void finishWhenSettled(code, signal);
}
async function finishWhenSettled(code, signal) {
  // Both escalations are OWNED promises: the tree reap's SIGKILL (R2-H1) and
  // the supervisor's KILL of cargo are awaited before exiting, whichever path
  // armed them (timeout, stop, or a sweep). The reap promise may still be IN
  // FLIGHT here — a child that exited while the first `ps` ran (sec N1) — so it
  // is awaited whether it has resolved or not; the former null-latch exit
  // discarded the KILL in exactly that window.
  if (treeReap) await treeReap;
  if (supervised.backstopArmed()) await supervised.awaitBackstop();
  await finish(code, signal);
}
async function finish(code, signal) {
  // A crash drain owns a NON-ZERO exit (2 settled / 3 bound). A settle that
  // reaches here while the drain is still awaiting its backstops must not exit
  // with the child's code: when the stopped child had finished normally that is
  // 0, which reports SUCCESS for a run whose supervisor crashed (D237 rule-6
  // RED: the CR row saw the crash named, the case killed, and rc 0). Returning
  // leaves the one exit to the drain, whose awaits are bounded.
  if (crashDraining()) return;
  if (timedOutName) {
    // Truthful evidence (D237 R2 sec L3): a signal is reported as sent only
    // when stop() actually delivered it. If cargo exited during the async
    // sample, the watchdog killed nothing — it reports the exit it saw and the
    // child's own rc. The verdict stays non-pass: the measured bound WAS
    // exceeded, so 124 is the bound's verdict, not a kill that never happened.
    const rc = code === null ? signal : code;
    if (signalDelivered) {
      process.stdout.write(`CSQ_TEST_WATCHDOG_KILLED name=${timedOutName} rc=${rc}\n`);
    } else {
      process.stdout.write(`CSQ_TEST_WATCHDOG_EXITED_DURING_SAMPLE name=${timedOutName} rc=${rc} — no signal was delivered\n`);
    }
    await exitWith(124);
    return;
  }
  let completed = 0;
  let slowest = null;
  const maps = [...completedDurations, ...(binary ? binary.stack.map((frame) => frame.durations) : [])];
  for (const durations of maps) {
    for (const [name, ms] of durations) {
      completed += 1;
      if (!slowest || ms > slowest.ms) slowest = { name, ms };
    }
  }
  // STDERR, deliberately: the red-evidence printer treats a `test result:` line
  // as a final trailer only when nothing but EOF / the next `running N tests` /
  // our own leg-RC line follows it. A successful-run summary on stdout would sit
  // after a failing binary's trailer and invalidate that trailer — the printer
  // would then name no tests at all. Diagnostics that may accompany a RED run
  // (TIMEOUT / SAMPLE / KILLED) stay on stdout: those occur only when the leg is
  // already failing and no final trailer exists to protect.
  // A STOPPED run is never reported as OK (D237 R2 corr L4): `CSQ_TEST_WATCHDOG_OK`
  // alongside rc 143 read as a successful run in the operator's evidence. A stop
  // names itself instead; OK is printed only on a real settle.
  if (stopSignal()) {
    process.stderr.write(`CSQ_TEST_WATCHDOG_STOPPED signal=${stopSignal()} tests=${completed}\n`);
    await exitWith(code !== null ? code : signal ? signalExitCode(signal) : 1);
    return;
  }
  process.stderr.write(`CSQ_TEST_WATCHDOG_OK tests=${completed}` +
    ` ignored_warnings=${ignoredWarnings}` +
    (slowest ? ` slowest=${slowest.name} elapsed_ms=${Math.round(slowest.ms)}` : ' slowest=none') + '\n');
  await exitWith(code !== null ? code : signal ? signalExitCode(signal) : 1);
}
// The rc of a signal death is 128+N for EVERY signal (D237 R2 corr L7): the old
// hand map collapsed SIGSEGV/SIGABRT/… to 128, which is non-zero (no verdict
// change) but a wrong number in the evidence. An exotic signal Node does not
// know still maps to the conventional 128, never to 0.
function signalExitCode(signal) {
  const n = os.constants.signals[signal];
  return Number.isInteger(n) ? 128 + n : 128;
}
// EVERY exit goes through here, and every call site is an awaited
// exitAfterBackstops (the import-graph self-test enforces both).
async function exitWith(code) {
  await exitAfterBackstops(code);
}
child.on('exit', (code, signal) => {
  childClosed = true;
  drainTimer = setTimeout(() => settle(code, signal), 300);
  drainTimer.unref?.();
});
child.on('close', (code, signal) => settle(code, signal));
