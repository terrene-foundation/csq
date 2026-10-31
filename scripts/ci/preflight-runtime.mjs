import { fork } from 'node:child_process';
import { chmodSync, mkdtempSync, writeFileSync, mkdirSync, lstatSync, realpathSync, unlinkSync, rmdirSync, readdirSync, openSync, closeSync, fstatSync, readSync, rmSync, constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, delimiter, resolve, dirname, basename } from 'node:path';
import { performance } from 'node:perf_hooks';

// Remove every environment entry through which the HOST can change what a gate
// shell or node worker runs: exported bash functions (BASH_FUNC_<name>%% on
// bash 4+, __BASH_FUNC<name>() on the vendor-patched 3.2 spelling), shell
// startup files (BASH_ENV, ENV) and NODE_OPTIONS (a --require preload). Bash
// imports an exported function with no startup file, so `bash --noprofile
// --norc` and `env -u BASH_ENV` do not stop it: an exported `python3() { return
// 0; }` turns a derived gate GREEN with nothing measured. Called as the first
// statement of both preflight entry points, before any spawn, so every
// sh/tryRun/capture/fork/trestle launch inherits the scrubbed environment (the
// same set scripts/ci/s1-landing-preflight.sh strips for the push queue).
// Returns the removed key names (names only; values may be arbitrary code).
export function scrubShellEnvironment(env = process.env) {
  const removed = [];
  for (const key of Object.keys(env)) {
    if (/^BASH_FUNC_/.test(key) || /^__BASH_FUNC</.test(key) || key === 'NODE_OPTIONS' || key === 'BASH_ENV' || key === 'ENV') {
      delete env[key];
      removed.push(key);
    }
  }
  return removed;
}

export const FLEET_SHARE_CAP = 6;
// Captured-output cap for a supervised child's stdout+stderr, in CHARACTERS.
// ONE cap for capture() and for gate workers: unbounded concatenation reaches
// V8's string limit and crashes the supervisor with a RangeError — the crash
// path would then have to drain what the crash itself caused (D237 R1 M3).
// 64 Mi chars is far beyond any legitimate gate's output and far below the
// limit; over the cap the child is stopped and the row is UNDETERMINED.
const OUTPUT_CAP_CHARS = 64 * 1024 * 1024;
// ── THE STOP LADDER. A leg runs in its OWN process group (detached), so a
// signal to the worker's group reaches neither the launcher nor its helpers;
// every stop therefore TERMs the LEG's group and arms ONE KILL backstop for the
// same group after CALLER_KILL_GRACE_MS. The group is what a signal reaches: a
// descendant that leaves it (setsid/setpgid) is NOT signalled — the
// caller-timeout message discloses the resulting remote-orphan possibility. The
// worker-level stop (the parent's SIGTERM/SIGINT handler, which supervises the
// worker's group) uses WORKER_KILL_GRACE_MS, deliberately LONGER than the leg
// KILL: the worker's own in-process leg backstop fires at CALLER_KILL_GRACE_MS
// and must get to run before the worker is SIGKILLed. The watchdog is NOT a
// worker-level stop — its own backstop is item 1 of the ladder below, with the
// strictly shorter WATCHDOG_KILL_GRACE_MS.
// kill(-pgid) on a group with no members is ESRCH, which every signal helper
// here tolerates — "while it has members" needs no separate probe.
export const CALLER_KILL_GRACE_MS = 2_000;
// ── THE KILL LADDER, stated once and ASSERTED (D237 R1 M2). Three SIGKILLs can
// be in flight for one leg; their order is the contract:
//   1. the watchdog's own backstop (per-test timeout / stop), WATCHDOG_KILL_GRACE_MS
//      — strictly BELOW the caller's leg grace, so a shared stop lets the
//      watchdog finish its verdict and its KILL before the leg is SIGKILLed;
//   2. the caller's leg-group KILL, CALLER_KILL_GRACE_MS;
//   3. the worker-level KILL, WORKER_KILL_GRACE_MS — the LAST resort.
// The margin is the worker's allowance to run its own SYNCHRONOUS sections
// between (2) and (3): retainOutput writes and hashes up to the 64 Mi-char
// capture cap, and treeFingerprint runs `spawnSync git` (R2-M5 — the earlier
// wording credited the async samplers, which were never on this path). A
// synchronous section longer than the margin must raise it here, not silently
// eat the margin — the load-time assertion below rejects a drifted ordering.
// WORKER is an INDEPENDENT constant, not `CALLER + MARGIN`: an identity cannot
// fail its own assertion (D237 R2-M5 tautology), so raising CALLER or MARGIN
// without also raising WORKER now throws at import.
// LIMIT, stated not assumed: on a remote leg the WATCHDOG runs on the fleet
// host while (2) is the LOCAL trestle client's group KILL. The assertion below
// can only order the constants on one clock; the cross-host firing order is the
// design's assumption (the client TERMs, the far-side watchdog stops itself on
// its own SIGHUP/group signal) and is NOT machine-checkable here.
export const WATCHDOG_KILL_GRACE_MS = 1_000;
export const KILL_LADDER_MARGIN_MS = 1_000;
export const WORKER_KILL_GRACE_MS = 3_000;
if (!(WATCHDOG_KILL_GRACE_MS < CALLER_KILL_GRACE_MS
  && CALLER_KILL_GRACE_MS + KILL_LADDER_MARGIN_MS <= WORKER_KILL_GRACE_MS)) {
  throw new Error('kill ladder ordering violated (watchdog < caller and caller + margin <= worker)');
}
// THE LEG EXIT TRAP'S SERVER STOP runs AFTER the caller's TERM and must finish,
// with its own kill-after and the socket-dir `rm` that follows it, before the
// caller's group KILL at CALLER_KILL_GRACE_MS. Its `timeout` arguments are
// DERIVED from these constants (cachedScript), and the sum is asserted here:
// stop bound + kill-after + TRAP_STOP_MARGIN_MS (the rm and shell overhead)
// <= CALLER_KILL_GRACE_MS. Fractional seconds (`0.5s`) are accepted by GNU
// coreutils timeout (9.11 checked 2026-10-24 on a macOS host, /opt/homebrew/bin/timeout).
export const TRAP_STOP_TIMEOUT_MS = 1_000;
export const TRAP_STOP_KILL_AFTER_MS = 500;
export const TRAP_STOP_MARGIN_MS = 500;
if (!(TRAP_STOP_TIMEOUT_MS + TRAP_STOP_KILL_AFTER_MS + TRAP_STOP_MARGIN_MS <= CALLER_KILL_GRACE_MS)) {
  throw new Error('trap stop bound violated (stop + kill-after + margin <= caller kill grace)');
}
const trapSeconds = (ms) => `${ms / 1000}s`;
// Last-resort settlement bound if a worker's IPC channel never disconnects.
// It SHOULD disconnect at exit (the worker's spawned children do not inherit
// the IPC fd), so this only bounds a pathological channel and is deliberately
// far longer than one turn of a blocked event loop. Exported so the self-test
// derives its settlement bound instead of choosing one (D237 R2 corr L5).
export const IPC_SETTLE_BOUND_MS = 2_000;
// ── ONE PER-GATE DEADLINE, expressed ONCE (dev-preflight.mjs and
// preflight-shell-tests.mjs import these; the self-tests assert the arithmetic
// directly). A gate draws caller-slot admission, each attempt's bound and the
// retry from the same clock; the constants live here so the rest of the
// expressions cannot drift.
export const LEG_ATTEMPTS = 2;
// The caller-slot admission SHARE each attempt contributes to the deadline. It
// is a budget term, never a cap on one wait: a caller slot is held for a whole
// attempt (queue wait + leg), so with FLEET_SHARE_CAP 6 and more legs than
// that, a fixed 30-minute cap refused legs 7+ ("caller fleet admission failed")
// exactly while the fleet was cooling. An attempt instead waits for a slot as
// long as one FULL attempt bound still fits in what remains afterwards
// (admissionWaitMsFor).
export const LEG_ADMISSION_WAIT_MS = 30 * 60 * 1000;
// Trestle's own queue wait, passed as `--wait-s` on EVERY attempt (the first
// one included) and spent INSIDE the trestle invocation. Trestle withholds a
// host in io cool-down for up to its psi_io_cooldown_s = 1800 s. The first
// attempt used to pass no --wait-s (trestle's default, 900 s) and the 116 retry
// 600 s, so both ran out while a cooling host was still withheld and the leg
// ended 116 "nothing ran" although the fleet would have admitted it (two
// release sign-offs lost Linux legs this way, 2026-10-26). 2700 s is the 1800 s
// cool-down plus a 900 s (50 %) margin for a host that only enters cool-down
// after the wait starts, or for queued legs ahead of this one; it is the value
// trestle's orchestrator recommends as the floor. The retry reuses it: a retry
// can meet the same cool-down. The check below enforces the stated margin.
export const TRESTLE_IO_COOLDOWN_S = 1800;
export const LEG_QUEUE_WAIT_MARGIN_S = 900;
export const LEG_QUEUE_WAIT_S = 2700;
if (!(LEG_QUEUE_WAIT_S >= TRESTLE_IO_COOLDOWN_S + LEG_QUEUE_WAIT_MARGIN_S)) {
  throw new Error('leg queue wait must outlast the trestle io cool-down by the stated margin');
}
// The workflow's Python provision step calls a bare `python -m venv`, but every
// leg runs under enforced `bash --noprofile --norc -p` with host init stripped
// (BASH_ENV/ENV removed), so a host whose PATH carries no bare `python` is
// normal — measured 2026-10-31 on ovh-1: `/bin/bash: line 7: python: command
// not found`, exit 127. When `python` does NOT resolve, expose an absolute
// interpreter from a fixed list as `python` through a private shim dir inside
// the leg's own temp dir; never rely on host init. When the host or CI PATH
// already carries `python`, that interpreter WINS and no shim is created — a
// fixture or managed environment that provides its own python must not be
// shadowed. `exit 125` is the leg's cannot-measure code.
export const PYTHON_SHIM_PRELUDE = `if ! command -v python >/dev/null 2>&1; then
  csq_python=
  for csq_py in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    if [ -x "$csq_py" ]; then csq_python="$csq_py"; break; fi
  done
  [ -n "$csq_python" ] || { echo 'dev-preflight: no python3 on the fixed search list (/usr/bin/python3, /usr/local/bin/python3, /opt/homebrew/bin/python3)' >&2; exit 125; }
  mkdir -p -- "$csq_step_tmp/bin" || exit 125
  printf '#!/bin/sh\nexec %s "$@"\n' "$csq_python" > "$csq_step_tmp/bin/python" || exit 125
  chmod +x "$csq_step_tmp/bin/python" || exit 125
  export PATH="$csq_step_tmp/bin:$PATH"
fi`;
// One attempt's caller bound: the --wait-s spent INSIDE the trestle invocation
// plus the leg (or a shard's ceiling and transport room). `queueWaitMs`
// defaults to LEG_QUEUE_WAIT_S; only a fixture with a stubbed trestle (which
// never queues) passes less, so its timeout paths cost seconds.
const QUEUE_WAIT_MS = LEG_QUEUE_WAIT_S * 1000;
export function attemptMsFor(legMs, queueWaitMs = QUEUE_WAIT_MS) {
  return queueWaitMs + legMs;
}
// The deadline: every attempt's admission share plus its full bound. A slow
// admission spends the share of a later attempt (and so may forfeit the retry),
// never extends the deadline.
export function budgetDeadlineMsFor(attemptMs) {
  return LEG_ATTEMPTS * (LEG_ADMISSION_WAIT_MS + attemptMs);
}
export function gateDeadlineMsFor(legMs, queueWaitMs = QUEUE_WAIT_MS) {
  return budgetDeadlineMsFor(attemptMsFor(legMs, queueWaitMs));
}
// How long an attempt may wait for a caller slot: everything that remains
// beyond one full attempt bound. 0 means the attempt cannot start.
export function admissionWaitMsFor(remainingMs, attemptMs) {
  return Math.max(0, Math.floor(remainingMs - attemptMs));
}
// Each attempt's caller bound, clamped to what remains of the deadline; a bound
// of the leg alone would cut a leg admitted late in its queue wait short.
export function attemptBoundMsFor(legMs, remainingMs, queueWaitMs = QUEUE_WAIT_MS) {
  return Math.min(attemptMsFor(legMs, queueWaitMs), Math.max(1, Math.round(remainingMs)));
}
// An attempt (first or retry: 116/104/113 nothing-ran, or 114/2 engine) starts
// ONLY when some admission wait AND a full attempt bound still fit.
export function retryFits(remainingMs, legMs, queueWaitMs = QUEUE_WAIT_MS) {
  return admissionWaitMsFor(remainingMs, attemptMsFor(legMs, queueWaitMs)) > 0;
}
// Upper bound on one async caller-slot wait. It only rejects a nonsense value:
// every caller derives its wait from a deadline far below this.
export const FLEET_ADMISSION_MAX_WAIT_MS = 12 * 60 * 60 * 1000;
let defaultFleetScope;
export function createFleetScope() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'csq-preflight-fleet-')));
  chmodSync(directory, 0o700);
  const token = randomUUID();
  writeFileSync(join(directory, 'scope.json'), JSON.stringify({ schema: 'csq.preflight_fleet.v1', token, cap: FLEET_SHARE_CAP }), { mode: 0o600, flag: 'wx' });
  process.on('exit', () => {
    // A crashed holder is never silently reaped into extra capacity. Retain
    // occupied scopes as diagnostics; clean only the empty caller-owned scope.
    try { if (readdirSync(directory).length === 1) { unlinkSync(join(directory, 'scope.json')); rmdirSync(directory); } } catch {}
  });
  return { CSQ_PREFLIGHT_FLEET_DIR: directory, CSQ_PREFLIGHT_FLEET_TOKEN: token };
}
function readFleetIdentity(path) {
  // NONBLOCK prevents a same-owner FIFO from hanging before fstat. NOFOLLOW
  // refuses leaf symlinks; one owned regular handle and a fixed read bound
  // prevent growth after the initial stat from becoming an unbounded read.
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > 4096 || before.mode & 0o077 || (process.getuid && before.uid !== process.getuid())) throw new Error('unsafe caller fleet identity');
    const bytes = Buffer.alloc(4097);
    let length = 0;
    while (length < bytes.length) {
      const n = readSync(fd, bytes, length, bytes.length - length, null);
      if (!n) break; length += n;
    }
    const after = fstatSync(fd);
    if (length > 4096 || before.size !== length || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error('caller fleet identity changed during bounded read');
    return { value: JSON.parse(bytes.subarray(0, length).toString('utf8')), identity: before };
  } finally { closeSync(fd); }
}
function fleetScope(env) {
  let directory = env.CSQ_PREFLIGHT_FLEET_DIR, token = env.CSQ_PREFLIGHT_FLEET_TOKEN;
  if (!directory && !token) {
    if (env.CSQ_PREFLIGHT_CANONICAL_WORKER === '1') throw new Error('canonical worker missing caller fleet admission');
    defaultFleetScope ||= createFleetScope();
    directory = defaultFleetScope.CSQ_PREFLIGHT_FLEET_DIR; token = defaultFleetScope.CSQ_PREFLIGHT_FLEET_TOKEN;
  }
  if (typeof directory !== 'string' || typeof token !== 'string' || !/^[0-9a-f-]{36}$/.test(token)) throw new Error('invalid caller fleet admission');
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(directory) !== directory || (process.getuid && info.uid !== process.getuid()) || info.mode & 0o077) throw new Error('unsafe caller fleet directory');
  const scope = readFleetIdentity(join(directory, 'scope.json')).value;
  if (scope.schema !== 'csq.preflight_fleet.v1' || scope.token !== token || scope.cap !== FLEET_SHARE_CAP) throw new Error('caller fleet identity mismatch');
  return directory;
}
function claimFleetSlot(directory) {
  for (let slot = 0; slot < FLEET_SHARE_CAP; slot++) {
    const path = join(directory, 'slot-' + slot), nonce = randomUUID();
    try { mkdirSync(path, { mode: 0o700 }); } catch (e) { if (e.code === 'EEXIST') continue; throw e; }
    try { writeFileSync(join(path, 'lease.json'), JSON.stringify({ nonce, pid: process.pid }), { mode: 0o600, flag: 'wx' }); }
    catch (e) { try { rmdirSync(path); } catch {} throw e; }
    return () => {
      const leasePath = join(path, 'lease.json');
      const lease = readFleetIdentity(leasePath), current = lstatSync(leasePath);
      if (lease.value.nonce !== nonce || current.dev !== lease.identity.dev || current.ino !== lease.identity.ino || !current.isFile() || current.size !== lease.identity.size || current.mtimeMs !== lease.identity.mtimeMs || current.ctimeMs !== lease.identity.ctimeMs) throw new Error('caller fleet lease identity changed');
      unlinkSync(leasePath); rmdirSync(path);
    };
  }
  return null;
}
export function acquireFleetSlotSync({ env = process.env, waitMs = 30 * 60 * 1000 } = {}) {
  if (!Number.isFinite(waitMs) || waitMs <= 0 || waitMs > 30 * 60 * 1000) throw new Error('invalid fleet admission deadline');
  const directory = fleetScope(env), deadline = performance.now() + waitMs;
  do {
    const release = claimFleetSlot(directory); if (release) return release;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(25, Math.max(1, deadline - performance.now())));
  } while (performance.now() < deadline);
  throw new Error('caller fleet admission deadline exhausted');
}
// ASYNC admission (used by runHeavy): the wait slices yield to the event loop,
// so a SIGTERM handler can run and `stopWhen` can interrupt the wait. The sync
// variant below blocks the loop for its whole span and is kept only for callers
// that cannot await (it cannot observe a signal).
export async function acquireFleetSlot({ env = process.env, waitMs = 30 * 60 * 1000, stopWhen = () => false } = {}) {
  if (!Number.isFinite(waitMs) || waitMs <= 0 || waitMs > FLEET_ADMISSION_MAX_WAIT_MS) throw new Error('invalid fleet admission deadline');
  const directory = fleetScope(env), deadline = performance.now() + waitMs;
  do {
    if (stopWhen()) throw new Error('caller fleet admission stopped by signal');
    const release = claimFleetSlot(directory); if (release) return release;
    await new Promise((resolve) => setTimeout(resolve, Math.min(25, Math.max(1, deadline - performance.now()))));
  } while (performance.now() < deadline);
  throw new Error('caller fleet admission deadline exhausted');
}
export function parseFooter(output) {
  // Native launcher contract: LAST nonempty stderr line. stdout is workload
  // content; concatenating streams can manufacture a terminal attribution.
  const stream = typeof output === 'string' ? output : output?.stderr;
  if (typeof stream !== 'string' || output?.error) return null;
  const line = stream.replace(/(?:\r?\n[ \t]*)+$/, '').split(/\r?\n/).at(-1);
  const m = /^\[(trestle-run|trestle-remote-run)\] exit=([0-9]{1,3}) (command|engine:([a-z][a-z0-9-]{0,31})|arbiter:([a-z][a-z0-9-]{0,31}))((?: [a-z][a-z0-9_-]*=[^\s\x00]+)*)$/.exec(line);
  if (!m || Number(m[2]) > 255) return null;
  // Accept only launcher-owned fields, once each, on this terminal footer. The
  // set is the DOCUMENTED writer shapes (trestle run --help): 113/104/114/116
  // footers carry cause=/requirement= and the host lists, and a reader that
  // rejected them would call every real retryable footer unclassifiable
  // (guard-reader-writer-parity MUST-1). Values are shape-checked, never free
  // text, so a forged line still cannot smuggle attribution.
  const HOST_LIST = /^[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*$/;
  const FIELD_SHAPES = {
    tree: /^[0-9a-f]{40}$/, host: /^[A-Za-z0-9_.-]+$/, wall: /^[0-9]+(?:\.[0-9]+)?s$/,
    lock: /^[A-Za-z0-9_.:-]+$/, cause: /^(deadline|interrupted)$/, requirement: /^[a-z][a-z0-9-]*$/,
    busy: HOST_LIST, not_admitted: HOST_LIST, unreadable: HOST_LIST, mirror_full: HOST_LIST,
    skipped: HOST_LIST, ci_busy: HOST_LIST, ci_unread: HOST_LIST,
    // `burst=<hosts>` is on the SAME documented 116 footer: a host whose reading
    // predates a run held there (trestle run --help). Leaving it out of this set
    // made every burst footer unclassifiable, which is the exact failure the
    // comment above says the set exists to prevent — and the unclassifiable
    // return happens BEFORE the [113,104,116] retry, so the retry never ran.
    burst: HOST_LIST,
  };
  const metadata = {};
  for (const field of m[6].trim().split(/ +/).filter(Boolean)) {
    const at = field.indexOf('='), key = field.slice(0, at), value = field.slice(at + 1);
    if (!Object.hasOwn(FIELD_SHAPES, key) || Object.hasOwn(metadata, key)) return null;
    if (!FIELD_SHAPES[key].test(value)) return null;
    metadata[key] = value;
  }
  // A footer written by a launcher that then DIED BY SIGNAL or under our
  // timeout cannot be trusted as a terminal verdict: if trestle crashed before
  // writing its own footer, the last stderr line is whatever the workload
  // printed, and accepting it lets a workload line buy a retry (D237 R2
  // LOW-D). The same holds for an engine/arbiter footer whose code is not the
  // process's actual exit status.
  if (output?.signal || output?.timedOut) return null;
  const kind = m[3] === 'command' ? 'command' : m[4] ? 'engine' : 'arbiter';
  if (kind !== 'command' && typeof output?.status === 'number' && Number(m[2]) !== output.status) return null;
  return { code: Number(m[2]), kind,
    engine: m[4], arbiter: m[5], ...metadata };
}
// ── EVIDENCE RETENTION. retainOutput leaves one tmp dir per capture and nothing
// reaped them (58k csq-preflight-output-* dirs on one host, ~8k/day). Two
// layers, both writer-owned:
//  1. A GREEN gate keeps no evidence: releaseGreenEvidence removes the dirs of
//     every GREEN row once its final state is known (RED and UNDETERMINED rows
//     are never touched — the printed report names those paths).
//  2. At preflight start, prune THIS uid's remaining dirs older than three days.
// The name must match mkdtemp's exact shape, the entry must be a real directory
// (lstat — a symlink is never followed or removed), and a fresh dir — including
// every dir this run will create — is untouched. The bound counts REMOVAL
// CANDIDATES (matching, real, owned, old enough), so a directory full of fresh
// entries cannot exhaust it before an old entry is reached; a separate, larger
// cap on readdir entries scanned keeps one pass bounded. Where the platform has
// no uid (Windows), the ownership check is skipped; the other checks still apply.
export const EVIDENCE_DIR_RE = /^csq-preflight-output-[A-Za-z0-9]{6}$/;
// A Svelte leg's private clone/HOME dir (mktemp -d, mode 0700). A leg killed by
// SIGKILL never runs its own cleanup, so the same age-gated prune reaps it.
export const SVELTE_TEMP_DIR_RE = /^csq-svelte\.[A-Za-z0-9]{6}$/;
const EVIDENCE_RETAIN_MS = 3 * 24 * 60 * 60 * 1000;
const EVIDENCE_PRUNE_MAX = 2048;
const EVIDENCE_SCAN_MAX = 262144;
export function pruneEvidenceDirs({ tmpdirPath = tmpdir(), now = Date.now(), retainMs = EVIDENCE_RETAIN_MS,
  maxCandidates = EVIDENCE_PRUNE_MAX, maxScanned = EVIDENCE_SCAN_MAX, uid = process.getuid?.() } = {}) {
  let names;
  try { names = readdirSync(tmpdirPath); } catch { return { examined: 0, removed: 0, scanned: 0 }; }
  let examined = 0, removed = 0, scanned = 0;
  for (const name of names) {
    if (examined >= maxCandidates || scanned >= maxScanned) break;
    scanned++;
    const svelteTemp = SVELTE_TEMP_DIR_RE.test(name);
    if (!svelteTemp && !EVIDENCE_DIR_RE.test(name)) continue;
    const path = join(tmpdirPath, name);
    let info;
    try { info = lstatSync(path); } catch { continue; }
    if (!info.isDirectory() || info.isSymbolicLink()) continue;
    if (uid !== undefined && info.uid !== uid) continue;
    if (svelteTemp && (info.mode & 0o777) !== 0o700) continue;
    if (now - info.mtimeMs < retainMs) continue;
    examined++;
    try { rmSync(path, { recursive: true, force: true }); removed++; } catch { /* not removable: leave it */ }
  }
  return { examined, removed, scanned };
}
// Remove the evidence dirs a GREEN row owns, then drop the references so no
// later reader is handed a deleted path. Only an exact retainOutput artifact is
// removed (<root>/csq-preflight-output-XXXXXX/output.json, real dir, this uid,
// under a root the pruner also covers). Skipped entirely when the run was asked
// to PRINT gate evidence (DEV_PREFLIGHT_SHOW_GATE_EVIDENCE=1): the printed
// report references those paths. Any non-GREEN row is left untouched.
const EVIDENCE_FILE_MAX = 192 * 1024 * 1024;
// The row's entry must describe THIS artifact: a regular file (lstat), under the
// size cap, whose sha256 equals the entry's. The hash covers the label retainOutput
// wrote, so an entry pointing at another row's dir (a RED row's evidence) mismatches.
// Returns null when the entry describes this artifact, else an identifier-only reason.
function artifactMismatch(dir, entry, maxBytes = EVIDENCE_FILE_MAX) {
  const sha = entry?.sha256;
  if (typeof sha !== 'string' || !/^[0-9a-f]{64}$/.test(sha)) return 'hash_mismatch';
  // One fd for check and read: O_NOFOLLOW refuses a symlink swapped in after the
  // dir check, O_NONBLOCK keeps a FIFO from blocking the open, fstat on the SAME fd
  // proves a regular file, and the read loop is capped so a file that grows after
  // the size check still cannot exceed maxBytes.
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
  let fd;
  try {
    try { fd = openSync(join(dir, 'output.json'), flags); } catch { return 'not_regular'; }
    const info = fstatSync(fd);
    if (!info.isFile()) return 'not_regular';
    if (info.size > maxBytes) return 'hash_mismatch';
    const hash = createHash('sha256'), chunk = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    for (;;) {
      const n = readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) return 'hash_mismatch';
      hash.update(chunk.subarray(0, n));
    }
    return hash.digest('hex') === sha ? null : 'hash_mismatch';
  } catch { return 'hash_mismatch'; }
  finally { if (fd !== undefined) { try { closeSync(fd); } catch { /* nothing to close */ } } }
}
const ROW_EVIDENCE_KEYS = ['heavy_output_evidence', 'command_output_evidence', 'gate_output_evidence', 'worker_output_evidence'];
// `local_evidence` is deliberately absent: retainLocalReplay sets it only on nested RED shell-test results, never on a gate row.
export function releaseGreenEvidence(rows, { env = process.env, uid = process.getuid?.(), roots = evidenceRoots(env), maxBytes = EVIDENCE_FILE_MAX } = {}) {
  let released = 0;
  // Every entry that is NOT released is counted under an identifier-only reason; none is kept silently.
  const kept = { hash_mismatch: 0, not_regular: 0, rm_failed: 0, outside_root: 0 };
  if (env.DEV_PREFLIGHT_SHOW_GATE_EVIDENCE === '1') return { released, kept };
  for (const row of rows) {
    if (!row || row.state !== 'GREEN') continue;
    for (const key of ROW_EVIDENCE_KEYS) {
      const value = row[key];
      if (value === undefined) continue;
      // A released entry keeps its sha256 (the receipt still names the bytes that
      // existed) and drops only the path; an entry that was not released is untouched.
      const settled = (Array.isArray(value) ? value : [value]).map((e) => {
        if (e?.released === true) return e;
        const keep = (reason) => { kept[reason]++; return e; };
        const path = e?.path;
        if (typeof path !== 'string' || basename(path) !== 'output.json') return keep('outside_root');
        const dir = dirname(path);
        if (!EVIDENCE_DIR_RE.test(basename(dir))) return keep('outside_root');
        // Exact-path containment: string equality with <root>/<dirname>/output.json
        // for ONE allowed root — no `..`, no extra component, no normalisation.
        if (!roots.some((root) => path === join(root, basename(dir), 'output.json'))) return keep('outside_root');
        let info;
        try { info = lstatSync(dir); } catch { return keep('not_regular'); }
        if (!info.isDirectory() || info.isSymbolicLink() || (uid !== undefined && info.uid !== uid)) return keep('not_regular');
        const reason = artifactMismatch(dir, e, maxBytes);
        if (reason) return keep(reason);
        try { rmSync(dir, { recursive: true, force: true }); } catch { return keep('rm_failed'); }
        released++;
        return { sha256: e.sha256, released: true };
      });
      row[key] = Array.isArray(value) ? settled : settled[0];
    }
  }
  return { released, kept };
}
// Cleanup must never change a verdict: this wrapper never throws and reports an
// identifier-only cause (never a message, which could carry a path or a token).
export function releaseGreenEvidenceSafe(rows, opts) {
  try { return releaseGreenEvidence(rows, opts); }
  catch (e) {
    const id = String(e?.code ?? e?.name ?? 'Error');
    return { released: 0, kept: {}, error: /^[A-Za-z0-9_]{1,64}$/.test(id) ? id : 'Error' };
  }
}
// The evidence dirs live under tmpdir(), but a writer that ran without TMPDIR
// wrote under /tmp (measured: 5,929 there vs 29,187 in the account TMPDIR), so a
// CANONICAL pass covers BOTH roots. On Windows only tmpdir() exists. A duplicate
// root (TMPDIR=/tmp) is harmless: the second pass finds nothing left to remove.
//
// A FIXTURE run covers ONLY its own tmpdir: adding the operator's real /tmp
// would let a self-test prune live evidence it never wrote (R1 LOW-5). The roots
// are injectable through CSQ_PREFLIGHT_EVIDENCE_ROOTS for fixtures only; a
// canonical run REFUSES the override, like the other fixture-only knobs.
export function evidenceRoots(env = process.env) {
  const canonical = env.CSQ_PREFLIGHT_CANONICAL_WORKER === "1";
  const fixture = !!env.DEV_PREFLIGHT_ONLY && !canonical;
  const override = env.CSQ_PREFLIGHT_EVIDENCE_ROOTS;
  if (override !== undefined && override !== "") {
    if (!fixture) throw new Error("CSQ_PREFLIGHT_EVIDENCE_ROOTS is refused outside a fixture run");
    return override.split(delimiter).filter(Boolean);
  }
  const t = tmpdir();
  if (fixture) return [t];
  return process.platform === "win32" || t === "/tmp" ? [t] : [t, "/tmp"];
}
export function prunePreflightEvidence({ roots = evidenceRoots(), ...opts } = {}) {
  let examined = 0, removed = 0, scanned = 0;
  for (const root of roots) {
    const pass = pruneEvidenceDirs({ tmpdirPath: root, ...opts });
    examined += pass.examined; removed += pass.removed; scanned += pass.scanned;
  }
  return { examined, removed, scanned };
}
export function retainOutput(r, label) {
  const directory = mkdtempSync(join(tmpdir(), 'csq-preflight-output-'));
  chmodSync(directory, 0o700);
  const path = join(directory, 'output.json');
  const bytes = JSON.stringify({ label, status: r.status, signal: r.signal ?? null,
    error_code: r.error?.code ?? null, elapsed_ms: r.elapsed_ms ?? null,
    timeout_diagnostics: r.timeout_diagnostics ?? null,
    stdout: r.stdout ?? '', stderr: r.stderr ?? '' }, null, 2) + '\n';
  writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' });
  chmodSync(path, 0o600);
  return { path, sha256: createHash('sha256').update(bytes).digest('hex') };
}
// Process lifecycle — spawn, the one stop set, exit-keyed liveness, the group
// probe, the owned KILL backstop and win32 handle-bound signals — lives in
// child-supervisor.mjs, ONE implementation for every scripts/ci child (D237 R3
// root-cause decision). capture() keeps only its own result collection and
// evidence retention.
import { supervise, adopt, stopAllLive } from './child-supervisor.mjs';
export { groupHasMembers, shouldSignalGroup } from './child-supervisor.mjs';

export function stopLiveCaptures() {
  // Legacy alias kept for the pre-migration handlers: drains every live
  // supervised child. dev-preflight's handlers move to installStopHandlers().
  stopAllLive();
}
function stoppedResult(started) {
  return { status: null, signal: null, error: { code: 'STOPPED' }, timedOut: false,
    stdout: '', stderr: 'capture stopped by signal', elapsed_ms: performance.now() - started };
}
// `admissionWaitMs`, when given, is the caller-slot wait a deadline-budgeted
// caller derived (admissionWaitMsFor); otherwise the slot wait is the capture's
// own timeout, capped at 30 min, as before.
export async function capture(command, args, { cwd, env = process.env, timeoutMs = 0, admissionWaitMs = 0, onTimeout = null, stopWhen = () => false } = {}) {
  const started = performance.now();
  // The latch is checked BEFORE admission and again before the spawn: a stop
  // that lands during either window must never start a new detached group.
  if (stopWhen()) return stoppedResult(started);
  let release;
  try { if (command === 'trestle') release = await acquireFleetSlot({ env, waitMs: admissionWaitMs || Math.min(timeoutMs || 30 * 60 * 1000, 30 * 60 * 1000), stopWhen }); }
  catch (e) {
    const r = { status: null, signal: null, error: { code: stopWhen() ? 'STOPPED' : 'FLEET_ADMISSION' }, timedOut: false, stdout: '', stderr: String(e.message), elapsed_ms: performance.now() - started };
    try { r.evidence = retainOutput(r, command); } catch { r.evidence_error = 'output-evidence-write-failed'; }
    return r;
  }
  if (stopWhen()) { try { release?.(); } catch { /* best effort: the run is stopping */ } return stoppedResult(started); }
  return new Promise((resolve) => {
    const supervised = supervise(command, args, { spawn: { cwd, env, detached: process.platform !== 'win32' } });
    const child = supervised.child;
    let stdout = '', stderr = '', error = null, timedOut = false, bytes = 0, settled = false;
    let timeoutDiagnostics = '';
    let timeoutTimer = null, drainTimer = null;
    const finish = (status, signal) => {
      if (settled) return;
      settled = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (drainTimer) clearTimeout(drainTimer);
      try { release?.(); } catch { error = { code: 'FLEET_LEASE_RELEASE' }; }
      // Our stream ends are ours to close: a descendant that inherited them can
      // keep `close` pending forever, and the caller needs its evidence now.
      child.stdout?.destroy(); child.stderr?.destroy();
      const r = { status, signal, error, timedOut, stdout, stderr, elapsed_ms: performance.now() - started, ...(timeoutDiagnostics ? { timeout_diagnostics: timeoutDiagnostics } : {}) };
      try { r.evidence = retainOutput(r, command); } catch { r.evidence_error = 'output-evidence-write-failed'; }
      // The supervisor keeps any armed backstop owned after dispose(), so the
      // worker's awaitBackstops() before exit still sees it.
      supervised.dispose();
      resolve(r);
    };
    const collect = (which, chunk) => {
      bytes += chunk.length;
      if (bytes > OUTPUT_CAP_CHARS) { error = { code: 'OUTPUT_LIMIT' }; supervised.stop('SIGTERM'); return; }
      if (which === 'stdout') stdout += chunk.toString(); else stderr += chunk.toString();
    };
    child.stdout.on('data', (d) => collect('stdout', d)); child.stderr.on('data', (d) => collect('stderr', d));
    child.on('error', (e) => { error = { code: e.code ?? 'SPAWN_ERROR' }; if (child.pid === undefined) finish(null, null); });
    // The hook runs while the child is STILL ALIVE and before the first signal,
    // so a bound-kill can name what it killed (process tree, open files). It is
    // synchronous by contract (bounded internally) and never allowed to change
    // the verdict: a throwing or absent hook costs one fixed line, not a pass.
    if (timeoutMs) timeoutTimer = setTimeout(() => {
      timedOut = true;
      if (typeof onTimeout === 'function') {
        try { timeoutDiagnostics = String(onTimeout(child) ?? ''); } catch { timeoutDiagnostics = 'CSQ_STUCK diagnostic_failed'; }
      }
      supervised.stop('SIGTERM');
    }, timeoutMs);
    // SETTLE ON EXIT with a bounded drain, never on close alone: a descendant
    // in another process group can hold the inherited stdio indefinitely, which
    // leaves `close` pending with no bound. `close` settles at once if it does
    // arrive first.
    child.on('exit', (status, signal) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (!drainTimer) drainTimer = setTimeout(() => finish(status, signal), 250);
    });
    child.on('close', (status, signal) => finish(status, signal));
  });
}
// Fixed shell wrapper inserts --locked before lint's `--` separator. Cargo fmt
// does not resolve a graph and deliberately receives no unsupported lock flag.
// `testWatchdogMs` (D237 rule 8, 2026-10-18): when non-zero, `cargo test` is run
// under scripts/ci/test-watchdog.mjs, which NAMES a hung test, samples its stacks
// BEFORE any signal, and then kills the group. The leg COMMAND stays
// byte-identical — the bound is applied here, at the one place that already
// rewrites the cargo invocation. A host with no node reports
// WATCHDOG_UNAVAILABLE and runs the leg per-test-unbounded: a silently absent
// bound would be worse than a loud one.
export function lockedScript(command, { fixture = false, testWatchdogMs = 0 } = {}) {
  const flat = command.replace(/\\\r?\n/g, ' ').trim();
  // Admission resolves one target from the final environment. A payload must
  // not select another target/config/workspace after that boundary.
  if (/--(?:target-dir|config|manifest-path)(?:[= \t'"]|$)/.test(flat)) throw new Error('unsupported command grammar: Cargo target/config diversion');
  const direct = /^cargo(?:[ \t]+\+[A-Za-z0-9_.-]+)?[ \t]+(?:build|check|clippy|doc|test|run|metadata|tree|fetch|update|generate-lockfile|fmt|clean|help|--help|-h|--version|-V)(?:[ \t]+(?:[A-Za-z0-9_./:=,+@%+-]+|'[^'\r\n]*'|"[^"$`\\\r\n]*"))*[ \t]*$/;
  if (!direct.test(flat) && !(fixture && !/cargo|[$`]/i.test(flat))) throw new Error('unsupported command grammar: cannot prove direct locked Cargo argv');
  const bound = Number.isInteger(testWatchdogMs) && testWatchdogMs > 0 ? String(testWatchdogMs) : '';
  const lockedCargo = 'if [[ -n "$tc" ]]; then command cargo "$tc" "$sub" --locked "$@"; else command cargo "$sub" --locked "$@"; fi';
  // The watchdog's OWN grace is emitted explicitly (never left to its default):
  // it must sit strictly below CALLER_KILL_GRACE_MS in the ladder above.
  const watchedTest = `if [[ -n "$tc" ]]; then node scripts/ci/test-watchdog.mjs --per-test-ms ${bound} --kill-grace-ms ${WATCHDOG_KILL_GRACE_MS} -- cargo "$tc" "$sub" --locked "$@"; else node scripts/ci/test-watchdog.mjs --per-test-ms ${bound} --kill-grace-ms ${WATCHDOG_KILL_GRACE_MS} -- cargo "$sub" --locked "$@"; fi`;
  const plainTest = bound
    ? `if command -v node >/dev/null 2>&1; then ${watchedTest}; else printf '%s\\n' 'CSQ_TEST_WATCHDOG_UNAVAILABLE reason=node-missing (per-test bound NOT applied)' >&2; ${lockedCargo}; fi`
    : lockedCargo;
  return `cargo() { local tc="" sub; if [[ "\${1:-}" == +* ]]; then tc="$1"; shift; fi; sub="\${1:-}"; shift || return 125; case "$sub" in build|check|clippy|doc|run|metadata|tree|fetch|update|generate-lockfile) ${lockedCargo} ;; test) ${plainTest} ;; fmt|clean|help|--help|-h|--version|-V) if [[ -n "$tc" ]]; then command cargo "$tc" "$sub" "$@"; else command cargo "$sub" "$@"; fi ;; *) printf '%s\\n' 'UNDETERMINED: unsupported Cargo subcommand' >&2; return 125 ;; esac; };\n${command}`;
}
// Each sign-off leg prints its own status after its build and workload finish.
export function measuredScript(command) {
  // These are measurements from the executing checkout, never expected values
  // supplied by the parent. pipefail preserves a failed git status producer.
  return `set -o pipefail\nprintf '\\nCSQ_PREFLIGHT_LEG_START measured\\n' >&2\ncsq_tree=$(git rev-parse 'HEAD^{tree}') || exit 125\nprintf 'TREE=%s\\n' "$csq_tree"\ncsq_porcelain=$(git status --porcelain | wc -l) || exit 125\nprintf 'PORCELAIN=%s\\n' "$((csq_porcelain))"\n${command}`;
}
// Sign-off legs that are repo shell gates, not a cargo argv: they run verbatim
// (each script drives its own cargo invocations, e.g. cargo-about's --locked).
// Exact-match allowlist, so any other command still has to prove locked Cargo.
export const COMMUNITY_EXTRACTION_COMMAND = `csq_extract_dir=$(mktemp -d "\${TMPDIR:-/tmp}/csq-community-extract.XXXXXX") || exit 125
trap 'csq_extract_rc=$?; rm -rf -- "$csq_extract_dir" || exit 125; exit "$csq_extract_rc"' EXIT
for csq_extract_git_key in \${!GIT_@}; do unset "$csq_extract_git_key" || exit 125; done
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 CARGO_NET_OFFLINE=true bash scripts/extract-community-edition.sh --no-build "$csq_extract_dir/tree"`;
// `test-targets-nonempty.sh` drives its own `cargo test --test <t> -- --list`
// invocations exactly as CI's rust-test step runs it — the script is the unit
// under test here, so rewriting its argv through the wrapper would measure a
// command CI never runs.
// `check-enterprise-deny.sh` is the same class: it drives its own
// `cargo deny --offline --locked` invocations (plus its own cargo-deny version
// probe), so admission must judge the SCRIPT, not a cargo argv. Its roster leg
// was first added WITHOUT this entry, so the builder threw `unsupported command
// grammar` and both platforms reported UNDETERMINED — masked behind an
// unrelated red, because RED outranks UNDETERMINED in aggregateExit.
const BARE_SIGNOFF_SCRIPTS = new Set(['bash scripts/check-edition-leak.sh', 'bash scripts/check-third-party-licenses-fresh.sh', 'bash scripts/verify/test-targets-nonempty.sh .', 'bash scripts/check-enterprise-deny.sh', COMMUNITY_EXTRACTION_COMMAND]);
export function signoffScript(command, { token, buildStub = false, fixture = false, testWatchdogMs = 0 }) {
  if (!/^[a-z0-9-]+$/.test(token)) throw new Error('invalid leg marker token');
  const body = BARE_SIGNOFF_SCRIPTS.has(command) ? command : lockedScript(command, { fixture, testWatchdogMs });
  const build = buildStub ? `${lockedScript('cargo build -p csq-core --bin stub-cli --features test-utils')}\ncsq_build_rc=$?; if [ "$csq_build_rc" -ne 0 ]; then exit "$csq_build_rc"; fi\n` : '';
  // LEG-START SENTINEL, the very first action (Q8 sec H1). Launcher lines are
  // trusted only BEFORE this point: without it, the tree under test could print
  // `[trestle-run] host=A REFUSED this run` + `rerouting to host=B` + a forged
  // placement on its own stderr and supersede the genuine placement.
  return `( printf '\\nCSQ_PREFLIGHT_LEG_START ${token}\\n' >&2; ${build}${body}\n); csq_leg_rc=$?; printf '\\nCSQ_PREFLIGHT_LEG_RC ${token} %s\\n' "$csq_leg_rc"; exit "$csq_leg_rc"`;
}
export function signoffVerdict(result, { token, tree }) {
  const footer = parseFooter(result);
  if (!footer || footer.kind !== 'command' || footer.code !== result.status) return { und: 'missing or inconsistent command footer' };
  const stdout = (result.stdout || '').split(/\r?\n/);
  if (stdout[0] !== `TREE=${tree}`) return { und: 'missing or mismatched in-run TREE measurement' };
  if (stdout[1] !== 'PORCELAIN=0') return { und: 'missing or dirty in-run PORCELAIN measurement' };
  if (stdout.filter((line) => /^(?:TREE|PORCELAIN)=/.test(line)).length !== 2) return { und: 'duplicate in-run source measurement' };
  if (footer.tree !== undefined && footer.tree !== tree) return { und: 'trestle footer tree does not match fingerprinted and in-run trees' };
  const stderr = (result.stderr || '').split(/\r?\n/).filter((line) => line.trim());
  const observations = [];
  if (footer.host) observations.push({ host: footer.host, source: 'terminal-footer' });
  let remoteSeen = false;
  let remoteHost = null;
  // THE REMOTE FOOTER IS FOR ATTRIBUTION; THE VERDICT IS THE LAST LINE. Trestle's
  // contract (`trestle run --help`) guarantees only that the LAST stderr line is
  // the terminal `[trestle-run] exit=N <kind>` footer carrying the outcome; the
  // verdict here is that footer plus this leg's own CSQ_PREFLIGHT_LEG_RC token
  // line and its in-run TREE/PORCELAIN measurements, never the remote footer.
  // Nothing about the lines between the remote footer and the terminal footer
  // is promised: the local launcher prints bookkeeping notices there (for
  // example `[trestle-run] host=public-builder.example.org ran this run; its
  // recorded failures are cleared`), the remote engine itself prints more
  // `[trestle-remote-run] ` lines AFTER its own exit= footer (`WARNING: could
  // not write --verdict-file …`, staging-ref withdrawal warnings, `| `
  // continuations), and with --return the terminal footer can turn a remote 0
  // into 115 or 102. So the remote footer is read only for host attribution and
  // for the placement pairing check below, never for the verdict. WHICH line it
  // is depends on the live launcher placement, so it is chosen after the
  // placements are parsed (see REMOTE FOOTER SELECTION below).
  // LAUNCHER PLACEMENTS, WITH REROUTES (Q8). A refused admission is rerouted:
  //   host=A (remote) slot=n ADMITTED
  //   host=A REFUSED this run (…)
  //   rerouting to host=B
  //   host=B (remote) slot=m ADMITTED
  // Counting every placement line made a refused-then-rerouted leg look like
  // TWO hosts and forced UNDETERMINED — measured on every linux leg while
  // a measured host's remote_run_root was unmounted and the launcher rerouted. A
  // placement is SUPERSEDED by its own REFUSED line; only the live one counts.
  // EVERY half-shape stays UNDETERMINED: a REFUSED with no open placement, a
  // REFUSED with no reroute, a reroute whose target is never placed LATER, two
  // live placements, or no surviving placement. A superseded host equal to the
  // final host is fine (the later placement is the live one).
  // THE LEG-START SENTINEL (Q8 sec H1). Exactly one token sentinel (and at most
  // one wrapper `measured` marker). Launcher lines are parsed ONLY before the
  // token sentinel; a `[trestle-run] ` line AFTER it can only come from the tree
  // under test, and it is IGNORED for host attribution — forgery is closed
  // because every launcher admit/refuse/reroute line precedes the command, so
  // nothing the command prints can add, supersede or replace a placement; and
  // ignoring (rather than UND) avoids a false UNDETERMINED on any leg whose own
  // output happens to contain launcher-shaped text (a shell-gate leg runs this
  // suite's fixtures). A forged post-start placement therefore never conflicts
  // with the footer: it is never collected at all.
  // EXACTLY ONE token sentinel, preceded at most once by the wrapper's
  // `measured` marker: heavyScript composes measuredScript(signoffScript(...)),
  // so every sign-off leg carries BOTH — the first cut of this check saw the
  // marker first and UND'd every leg with "unexpected token" (measured in the
  // suite). Any other sentinel line, before or after, is UND.
  const MARKER = 'CSQ_PREFLIGHT_LEG_START measured';
  const EXPECTED = `CSQ_PREFLIGHT_LEG_START ${token}`;
  const sentinelLines = [];
  for (let i = 0; i < stderr.length; i += 1) {
    if (/^CSQ_PREFLIGHT_LEG_START \S+$/.test(stderr[i])) sentinelLines.push({ line: stderr[i], index: i });
  }
  for (const s of sentinelLines) {
    if (s.line !== MARKER && s.line !== EXPECTED) return { und: 'leg-start sentinel carries an unexpected token' };
  }
  if (sentinelLines.filter((s) => s.line === MARKER).length > 1) return { und: 'duplicate leg-start marker' };
  const tokenSentinels = sentinelLines.filter((s) => s.line === EXPECTED);
  if (!tokenSentinels.length) return { und: 'missing leg-start sentinel' };
  if (tokenSentinels.length > 1) return { und: 'duplicate leg-start sentinel' };
  const sentinelIndex = tokenSentinels[0].index;
  // LINES AFTER THE SENTINEL ARE IGNORED FOR HOST ATTRIBUTION (ROOT's final
  // ruling): a leg whose output contains launcher-shaped text must not be
  // FORCED UNDETERMINED (this suite's own fixtures are such text), and ignoring
  // is already forgery-closed because EVERY launcher admit/refuse/reroute line
  // precedes the command — a post-start placement is never collected, so it can
  // neither be attributed nor conflict with the footer. Only the terminal footer
  // (last line) and the most recent remote footer (above) are read from the
  // post-sentinel region, and the remote-footer rule below keeps even that
  // corroboration from standing alone.
  const pre = stderr.slice(0, sentinelIndex);
  const placements = [];
  for (let i = 0; i < pre.length; i += 1) {
    const line = pre[i];
    const placement = /^\[trestle-run\] host=([A-Za-z0-9_.-]+) \((remote|local,[^\r\n]*)\)(?: |$)/.exec(line);
    if (placement) { placements.push({ host: placement[1], kind: placement[2] === 'remote' ? 'remote' : 'local', index: i, refused: false, reroutedTo: null, rerouteIndex: -1 }); continue; }
    const refused = /^\[trestle-run\] host=([A-Za-z0-9_.-]+) REFUSED this run\b/.exec(line);
    if (refused) {
      const open = [...placements].reverse().find((p) => p.host === refused[1] && !p.refused);
      if (!open) return { und: 'launcher REFUSED a host with no open placement' };
      open.refused = true;
      continue;
    }
    const reroute = /^\[trestle-run\] rerouting to host=([A-Za-z0-9_.-]+)(?: |$)/.exec(line);
    if (reroute) {
      const open = [...placements].reverse().find((p) => p.refused && p.reroutedTo === null);
      if (!open) return { und: 'launcher rerouted with no refused placement' };
      open.reroutedTo = reroute[1];
      open.rerouteIndex = i;
    }
  }
  // ONLY WHEN THE LAUNCHER PRINTED PLACEMENTS does the refusal logic apply. A
  // run with NO placement line (the terminal footer's host is then the sole
  // launcher-owned observation) is the pre-existing legitimate shape — the
  // fixture's plain red/green modes are exactly that, and an earlier cut of
  // this fix turned every one of them UNDETERMINED. An UNPAIRED REFUSED is
  // still caught above, in the scan, whether or not a placement exists.
  let liveKind = null;
  if (placements.length) {
    for (const p of placements) {
      if (p.refused && p.reroutedTo === null) return { und: 'launcher refused a placement and never rerouted' };
      if (p.refused && p.reroutedTo !== null
        && !placements.some((q) => q.host === p.reroutedTo && q.index > p.rerouteIndex)) {
        return { und: 'launcher reroute target was never placed after the reroute' };
      }
    }
    const livePlacements = placements.filter((p) => !p.refused);
    // UNREACHABLE BACKSTOP (kept on purpose): if a placement exists, the checks
    // above force every refused placement's reroute target to be placed LATER,
    // so the last placement in the chain cannot itself have been refused.
    if (!livePlacements.length) return { und: 'no launcher placement survived its refusals' };
    if (livePlacements.length > 1) return { und: 'two live launcher placements' };
    const live = livePlacements[0];
    liveKind = live.kind;
    observations.push({ host: live.host, source: 'launcher-placement' });
  }
  // REMOTE FOOTER SELECTION. Under a live REMOTE placement the remote footer is
  // the MOST RECENT `[trestle-remote-run] exit=` line anywhere before the
  // terminal footer, with no positional or prefix requirement on the lines in
  // between (the engine's own WARNING and `| ` lines follow its footer). Under a
  // LOCAL placement or none, no real remote footer is ever written after the
  // leg starts, so a `[trestle-remote-run] exit=` line AFTER the leg-start
  // sentinel is the command's own output (this suite's fixtures print such
  // lines) and is ignored; one before the sentinel still counts, and the
  // contradiction checks below refuse it.
  // WHAT A FORGED REMOTE FOOTER CAN DO: under a remote placement, the leg's own
  // output can print `[trestle-remote-run] exit=0 command host=<placed host>`.
  // If trestle placed the leg remotely but wrote NO genuine remote footer, that
  // line satisfies the pairing check below and turns its UNDETERMINED into
  // GREEN. It cannot fabricate a pass on its own: the terminal footer's code
  // must equal the real process status, and this leg's own RC token line and
  // in-run TREE/PORCELAIN measurements are still required. Otherwise it can
  // only mislabel the host (a conflicting observation is UNDETERMINED) or fail
  // the fail-closed checks: it must be a command footer, its tree (when
  // present) must match, and a remote non-zero under a terminal `exit=0
  // command` is UNDETERMINED; a remote 0 under a terminal non-zero is simply
  // not green (the terminal wins).
  const remoteScanEnd = liveKind === 'remote' ? stderr.length - 2 : sentinelIndex - 1;
  let previous;
  for (let i = remoteScanEnd; i >= 0; i -= 1) {
    if (stderr[i].startsWith('[trestle-remote-run] exit=')) { previous = stderr[i]; break; }
  }
  if (previous !== undefined) {
    const remote = parseFooter(previous);
    if (!remote || remote.kind !== 'command' || (footer.code === 0 && remote.code !== 0)) return { und: 'inconsistent preceding remote footer' };
    if (remote.tree !== undefined && remote.tree !== tree) return { und: 'preceding remote footer tree mismatch' };
    remoteSeen = true;
    remoteHost = remote.host || null;
  }
  // A REMOTE placement implies the remote-run wrapper ran the leg, so its
  // footer must appear somewhere before the terminal footer (Q8 sec L2): a
  // remote placement with no remote footer anywhere is an unpaired observation.
  if (liveKind === 'remote' && !remoteSeen) {
    return { und: 'remote placement without a preceding remote footer' };
  }
  // A REMOTE FOOTER IS CORROBORATION, NEVER THE SOLE OBSERVATION (Q8 R2 sec M1).
  // The tree can print `[trestle-remote-run] … host=X` after its sentinel, and
  // counting it alone promoted UND ("no launcher-owned observed host") to ok
  // with a forged host. Without a remote placement such a line is now ignored
  // (REMOTE FOOTER SELECTION); a pre-sentinel one may still contribute a host
  // only when a terminal-footer host already anchors the attribution, and a
  // LIVE (local, …) placement beside it is contradictory outright.
  if (liveKind === 'local' && remoteSeen) return { und: 'live local placement with a remote footer' };
  if (remoteSeen && liveKind !== 'remote' && !footer.host) {
    return { und: 'remote footer is the only launcher observation' };
  }
  if (remoteHost && (liveKind === 'remote' || footer.host)) {
    observations.push({ host: remoteHost, source: 'preceding-remote-footer' });
  }
  if (!observations.length) return { und: 'no launcher-owned observed host' };
  if (new Set(observations.map((observation) => observation.host)).size !== 1) return { und: 'conflicting launcher-owned host observations' };
  const lines = stdout.filter((line) => line.startsWith(`CSQ_PREFLIGHT_LEG_RC ${token} `));
  const match = lines.length === 1 && /^CSQ_PREFLIGHT_LEG_RC [a-z0-9-]+ ([0-9]{1,3})$/.exec(lines[0]);
  if (!match || Number(match[1]) !== footer.code) return { und: 'missing or inconsistent own leg RC line' };
  return { ok: footer.code === 0, leg_rc: footer.code, host: observations[0].host,
    host_provenance: observations.map((observation) => observation.source), tree, porcelain: 0 };
}
// PER-LEG SCCACHE SERVER. The sccache server is per-user, shared across legs
// and outlives the leg that started it; on a Darwin host whose legs are not
// contained, a later leg inherited a server whose TMPDIR had been reaped
// (`error writing dependencies to …/.tmp/<leg>/sccache…/deps.d: No such file`).
// Each leg therefore talks to its OWN server over a Unix socket
// (SCCACHE_SERVER_UDS) in a fresh 0700 `mktemp -d` under the leg's TMPDIR (or
// /tmp when that path would overflow sun_path), started ONCE up front by an
// explicit bounded (10s) `sccache --start-server` and stopped at leg end. It
// is never left to the leg's first client: `--show-stats` does not start a
// server, so cargo's parallel `sccache rustc` clients raced to start it and a
// loser's bind hit the winner's socket — `sccache: error: Server startup
// failed: File exists (os error 17)` (dev preflight 2026-10-24, sign-off
// darwin lib-bins, LEG_RC=101). Measured 2026-10-24, 12 parallel rustc from a
// fresh socket dir per trial: one macOS host, sccache 0.14.0, 20 trials
// each, 24 of 240 compiles failed so with the lazy start and 0 of 240 with the
// up-front start; first repro on another macOS host, sccache 0.18.0, 1 failure
// in one 12-client trial. A failed start prints CSQ_CACHE_START_FAILED, makes a
// bounded stop attempt and takes the logged cache-unavailable path below.
// SERVER LIFETIME. SCCACHE_IDLE_TIMEOUT counts seconds since the server's last
// request; 5400 (90 min) exceeds the longest leg the caller allows — 65 min
// (LEG_CALLER_TIMEOUT_MS), 75 min on the retry attempt — by 15 min, so a server
// cannot idle out and be raced back up mid-leg. Reaping is NOT left to that
// timer: the EXIT trap (reached on TERM/INT/HUP through their traps) runs a
// bounded `sccache --stop-server` (TRAP_STOP_TIMEOUT_MS + TRAP_STOP_KILL_AFTER_MS,
// asserted under CALLER_KILL_GRACE_MS at load) while SCCACHE_SERVER_UDS is
// still set, then removes the socket dir. Measured 2026-10-24 (see the commit): the
// daemonized server leaves the starting shell's process group and session, so
// a group kill of the leg never reaches it and the trap is what reaps it. A
// server is left running when the leg dies without running its trap (SIGKILL),
// or when a stop attempt itself fails or is cut at its bound (reported as
// CSQ_CACHE_STOP_UNDETERMINED); such a server exits on its own within 90 min of
// its last request, and its socket dir is removed, so no later leg reaches it. A TERM sent only to the
// leg shell is handled once its foreground command returns (bash defers traps
// while waiting); a group TERM ends that command at once. A socket in a 0700 directory admits
// only this UID, unlike a TCP port. Any inherited SCCACHE_SERVER_UDS/PORT is
// unset first. Probed 2026-10-24: sccache 0.18.0 (linux) and 0.14.0 (darwin)
// both listen on and answer --show-stats over SCCACHE_SERVER_UDS. The end-of-leg
// stop is best effort and bounded (3s), and is ALWAYS attempted, whatever the
// after-stats result: skipping it on a failed stats call, then unsetting the
// socket (which disarms the trap's stop), left a live server for its full idle
// timeout. A failed stats call prints CSQ_CACHE_STATS_UNDETERMINED; only a
// failed stop prints CSQ_CACHE_STOP_UNDETERMINED; neither replaces the leg's
// exit status. After that stop the socket is unset, so the EXIT trap never
// repeats it (even when the dir removal fails and the trap still runs).
// TEST COVERAGE (scripts/tests/dev-preflight-runtime.test.sh): the TERM, HUP
// and INT traps, the always-attempted end stop, and the post-stop unset (via a
// failing `rm`) each have a row that REDs when removed. The
// socket directory is removed at leg end either way, so a server left running
// is unreachable by any later leg; an EXIT trap removes it on any other exit.
// When sccache is unavailable (no client, or no private socket dir), every
// inherited or config-file wrapper is cleared with EMPTY env values — measured
// 2026-10-24 on linux, cargo 1.98.1: a config build.rustc-wrapper stub ran 4
// times, 0 with RUSTC_WRAPPER= CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=
// — so cargo can never reach the shared default server.
export function cachedScript(command, { targetBudget = null } = {}) {
  // Opt in at the whole-leg boundary, once for helper build plus workload.
  // Callers export their final Cargo environment before invoking this shell.
  let payload = command;
  if (targetBudget !== null) {
    if (typeof targetBudget !== 'object' || Array.isArray(targetBudget)) throw new Error('invalid target budget options');
    const { capBytes } = targetBudget;
    if (capBytes !== undefined && (!Number.isSafeInteger(capBytes) || capBytes <= 0)) throw new Error('invalid target budget cap');
    const quoted = "'" + command.replace(/'/g, "'\\''") + "'";
    payload = `bash scripts/ci/cargo-target-highwater.sh --workspace "$PWD"${capBytes === undefined ? '' : ` --cap-bytes ${capBytes}`} -- bash -c ${quoted}`;
  }
  return `cache=""; csq_sccache_dir=""; unset SCCACHE_SERVER_UDS SCCACHE_SERVER_PORT SCCACHE_IDLE_TIMEOUT; if command -v timeout >/dev/null 2>&1 && command -v sccache >/dev/null 2>&1 && timeout --signal=TERM --kill-after=1s 3s sccache --version >/dev/null 2>&1; then csq_sccache_base="\${TMPDIR:-/tmp}"; case "$csq_sccache_base" in /*) ;; *) csq_sccache_base=/tmp ;; esac; [ "\${#csq_sccache_base}" -le 70 ] || csq_sccache_base=/tmp; if csq_sccache_dir=$(mktemp -d "$csq_sccache_base/csq-sccache.XXXXXX") && trap '[ -z "$csq_sccache_dir" ] || { [ -z "\${SCCACHE_SERVER_UDS:-}" ] || timeout --signal=TERM --kill-after=${trapSeconds(TRAP_STOP_KILL_AFTER_MS)} ${trapSeconds(TRAP_STOP_TIMEOUT_MS)} sccache --stop-server >/dev/null 2>&1 || echo CSQ_CACHE_STOP_UNDETERMINED >&2; rm -rf -- "$csq_sccache_dir"; }' EXIT && trap 'exit 143' TERM && trap 'exit 130' INT && trap 'exit 129' HUP && chmod 700 "$csq_sccache_dir"; then export SCCACHE_SERVER_UDS="$csq_sccache_dir/s" SCCACHE_IDLE_TIMEOUT=5400; if timeout --signal=TERM --kill-after=1s 10s sccache --start-server >&2; then cache="$(command -v sccache)"; export RUSTC_WRAPPER="$cache" CARGO_INCREMENTAL=0; printf '%s\\n' 'CSQ_CACHE_BEFORE' >&2; timeout --signal=TERM --kill-after=1s 3s sccache --show-stats >&2 || printf '%s\\n' 'CSQ_CACHE_STATS_UNDETERMINED' >&2; else printf '%s\\n' 'CSQ_CACHE_START_FAILED' >&2; timeout --signal=TERM --kill-after=1s 3s sccache --stop-server >/dev/null 2>&1 || printf '%s\\n' 'CSQ_CACHE_STOP_UNDETERMINED' >&2; { rm -rf -- "$csq_sccache_dir" && csq_sccache_dir=""; } || printf '%s\\n' 'CSQ_CACHE_SOCKET_CLEANUP_UNDETERMINED' >&2; unset SCCACHE_SERVER_UDS SCCACHE_IDLE_TIMEOUT; export RUSTC_WRAPPER='' CARGO_BUILD_RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=''; printf '%s\\n' 'CSQ_CACHE_UNAVAILABLE' >&2; fi; else [ -z "$csq_sccache_dir" ] || rm -rf -- "$csq_sccache_dir"; csq_sccache_dir=""; export RUSTC_WRAPPER='' CARGO_BUILD_RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=''; printf '%s\\n' 'CSQ_CACHE_UNAVAILABLE' >&2; fi; else export RUSTC_WRAPPER='' CARGO_BUILD_RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=''; printf '%s\\n' 'CSQ_CACHE_UNAVAILABLE' >&2; fi\n( ${payload}\n); rc=$?; if [[ -n "$cache" ]]; then printf '%s\\n' 'CSQ_CACHE_AFTER' >&2; timeout --signal=TERM --kill-after=1s 3s sccache --show-stats >&2 || printf '%s\\n' 'CSQ_CACHE_STATS_UNDETERMINED' >&2; timeout --signal=TERM --kill-after=1s 3s sccache --stop-server >&2 || printf '%s\\n' 'CSQ_CACHE_STOP_UNDETERMINED' >&2; unset SCCACHE_SERVER_UDS; fi; [ -z "$csq_sccache_dir" ] || { rm -rf -- "$csq_sccache_dir" && csq_sccache_dir=""; } || printf '%s\\n' 'CSQ_CACHE_SOCKET_CLEANUP_UNDETERMINED' >&2; exit "$rc"`;
}
export function aggregateExit(rows) {
  if (rows.some((r) => r.state === 'RED')) return 1;
  if (rows.some((r) => r.state === 'UNDETERMINED')) return 2;
  return 0;
}
export async function runGateWorkers(names, { script, cwd, env, fingerprint, onComplete, timeoutMs = 35 * 60 * 1000 }) {
  const children = new Set();
  const fleetEnv = env.CSQ_PREFLIGHT_FLEET_DIR ? env : { ...env, ...(defaultFleetScope ||= createFleetScope()) };
  // Every worker is ADOPTED by the one supervisor: liveness (exit-keyed), the
  // group probe and the KILL backstop are owned there, and the process-wide
  // stop handlers drain this set too (D237 R3 — this site's own timer/probe
  // logic is deleted).
  const launch = (name) => new Promise((resolve) => {
    const token = randomUUID(), started = performance.now();
    const childEnv = { ...fleetEnv, DEV_PREFLIGHT_ONLY: name, CSQ_PREFLIGHT_WORKER_TOKEN: token,
      CSQ_PREFLIGHT_PARENT_FINGERPRINT: fingerprint, CSQ_PREFLIGHT_CANONICAL_WORKER: env.DEV_PREFLIGHT_ONLY ? '0' : '1' };
    if (!env.DEV_PREFLIGHT_ONLY) {
      for (const key of ['DEV_PREFLIGHT_SELFTEST_LOCAL','CSQ_PREFLIGHT_LOCAL','DEV_PREFLIGHT_SELFTEST_CEILING_MS','DEV_PREFLIGHT_SELFTEST_PER_TEST_MS','DEV_PREFLIGHT_FORCE_NO_BASH','DEV_PREFLIGHT_FORCE_WINGNU','DEV_PREFLIGHT_FORCE_NO_WINGNU','DEV_PREFLIGHT_LEG_TIMEOUT_MS']) delete childEnv[key];
    }
    const child = fork(script, [], { cwd, env: childEnv, execArgv: [], stdio: ['ignore', 'pipe', 'pipe', 'ipc'], detached: process.platform !== 'win32' });
    const supervised = adopt(child, { graceMs: WORKER_KILL_GRACE_MS });
    children.add(child);
    let stdout = '', stderr = '', bytes = 0, frame = null, error = null, duplicate = false, watchdog, drainTimer = null, settleTimer = null,
      settled = false, exited = false, exitStatus = null, exitSignal = null, ipcClosed = false, stdioClosed = false;
    // SETTLEMENT waits for the IPC channel to disconnect (bounded by the drain)
    // before it reads the worker's frame. The old drain could fire first with
    // the frame still queued behind a blocked loop, which both dropped the
    // verdict and mislabeled the row pipe_held; a closed IPC channel means no
    // message can still arrive.
    //
    // PIPE DIVISION (the runTrestleBounded rule in dev-preflight.mjs, one level
    // up): settle on the worker's 'exit', NOT 'close'. A child the worker itself
    // spawned can inherit its stdout/stderr and hold them open after the worker
    // is gone, so 'close' may never fire — the row would hang with no bound.
    // `pipe_held` is set ONLY when the IPC channel is closed AND our stdio ends
    // are still open (a stream that ENDED is not holding the pipe, even if its
    // 'close' event has not fired yet). The holder is the worker's descendant,
    // not ours, so destroying our ends does not signal it.
    const stdioOpen = () => !stdioClosed && !(child.stdout?.readableEnded && child.stderr?.readableEnded);
    const settle = (status, signal, pipeHeld) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog); if (drainTimer) clearTimeout(drainTimer); if (settleTimer) clearTimeout(settleTimer);
      // The supervisor already removed this child from the stop set on 'exit'
      // (exit IS the removal); dispose() here is settle-time uniformity with
      // capture()/runTrestleBounded and keeps an armed backstop owned.
      supervised.dispose();
      child.stdout?.destroy(); child.stderr?.destroy();
      let row = frame?.gate;
      if (duplicate || error || signal || !row || !['GREEN','RED','UNDETERMINED','SKIPPED','NOT_APPLICABLE'].includes(row.state) || status !== aggregateExit([row])) {
        row = { name, state: 'UNDETERMINED', detail: 'gate worker did not return one consistent, source-bound verdict' };
      }
      if (error?.code === 'OUTPUT_LIMIT') {
        row.detail = (row.detail || '') + `; worker output exceeded the ${Math.round(OUTPUT_CAP_CHARS / (1024 * 1024))} Mi captured-output cap — the worker was stopped`;
      }
      const r = { status, signal, error, stdout, stderr, elapsed_ms: performance.now() - started };
      try { row.worker_output_evidence = retainOutput(r, name); } catch { if (row.state !== 'RED') row.state = 'UNDETERMINED'; row.detail = (row.detail || '') + '; could not retain worker output'; }
      if (pipeHeld) {
        row.pipe_held_after_exit = true;
        row.detail = (row.detail || '') + '; worker stdio still open after exit and IPC disconnect — trailing worker output not captured';
      }
      row.elapsed_ms = r.elapsed_ms;
      // Evidence is NOT released here: the worker's verdict is not final until the parent
      // has checked the end-of-run fingerprint (dev-preflight.mjs releases GREEN rows there).
      onComplete?.(row);
      resolve(row);
    };
    const doSettleNow = () => { if (!settled) settle(exitStatus, exitSignal, ipcClosed && stdioOpen()); };
    watchdog = setTimeout(() => { error = { code: 'WORKER_TIMEOUT' }; supervised.stop('SIGTERM'); }, timeoutMs);
    // CAPPED (D237 R1 M3): an uncapped collector is one RangeError away from
    // crashing the supervising worker; over the cap the worker is stopped and
    // the row is UNDETERMINED with the named cause.
    const collectWorker = (which, chunk) => {
      bytes += chunk.length;
      if (bytes > OUTPUT_CAP_CHARS) {
        if (!error) error = { code: 'OUTPUT_LIMIT' };
        supervised.stop('SIGTERM');
        return;
      }
      if (which === 'stdout') stdout += chunk.toString(); else stderr += chunk.toString();
    };
    child.stdout.on('data', (d) => collectWorker('stdout', d));
    child.stderr.on('data', (d) => collectWorker('stderr', d));
    // A spawn failure with no pid (ENOENT) emits 'error' and never 'exit';
    // settle there with the named cause rather than waiting out the watchdog.
    child.on('error', (e) => { error = { code: e.code ?? 'SPAWN_ERROR' }; if (child.pid === undefined) settle(null, null, false); });
    child.on('message', (m) => {
      if (frame) duplicate = true;
      if (m && m.token === token && m.gate?.name === name && m.fingerprint === fingerprint && m.no_receipt === true) frame = m;
      else duplicate = true;
    });
    child.on('exit', (status, signal) => {
      exited = true; exitStatus = status; exitSignal = signal;
      children.delete(child); clearTimeout(watchdog);
      // The supervisor's exit handler owns the empty-group backstop cancel
      // (exit-keyed, shared with every other site).
      // Settlement waits for the IPC 'disconnect' (see the handler below); this
      // timer is the last-resort bound for a channel that never closes.
      if (!settleTimer) settleTimer = setTimeout(doSettleNow, IPC_SETTLE_BOUND_MS);
    });
    child.on('disconnect', () => {
      ipcClosed = true;
      // The IPC channel is closed, so every queued frame has been delivered.
      // Wait one short drain before reading stdio: if our ends are still open,
      // the worker left a descendant holding them (pipe_held); otherwise the
      // 'end' events are already in flight and land inside this window.
      if (stdioClosed) doSettleNow();
      else if (!drainTimer) drainTimer = setTimeout(doSettleNow, 250);
    });
    child.on('close', () => { stdioClosed = true; children.delete(child); if (exited && ipcClosed) doSettleNow(); });
  });
  return Promise.all(names.map(launch));
}
