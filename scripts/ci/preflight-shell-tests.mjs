import { readdirSync, existsSync, realpathSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, join, delimiter, basename, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { capture, parseFooter, retainOutput, LEG_QUEUE_WAIT_S, LEG_ATTEMPTS, attemptMsFor, budgetDeadlineMsFor, admissionWaitMsFor } from './preflight-runtime.mjs';
import { installStopHandlers, exitAfterBackstops, stopSignal } from './child-supervisor.mjs';

// ── ALLOWLIST-ONLY OUTPUT HELPERS (shared with dev-preflight.mjs) ─────────────
// Operator-facing preflight text is a fixed vocabulary plus values that pass one
// of these allowlists. A value that fails is replaced by a fixed phrase, never
// printed partially or redacted (redaction of free text always left a bypass).
const EVIDENCE_PATH_RE = /^\/[A-Za-z0-9._\/-]{1,1024}$/;
const EVIDENCE_DIR_RE = /^csq-preflight-output-[A-Za-z0-9]{6}$/;
const REL_PATH_RE = /^[A-Za-z0-9_.\/-]{1,200}$/;
const IDENT_RE = /^[A-Za-z0-9_]{1,64}$/;
export const SHA256_RE = /^[0-9a-f]{64}$/;
// $HOME prefix -> `~` on a path WE built (structured prefix replace on a known
// path field, never a scan of free text).
// Both the lexical $HOME and its realpath are matched: a path we built from a
// physical directory (tmpdir, git worktree list) starts with the realpath when
// $HOME is, or sits under, a symlink.
export function homeTilde(path) {
  const home = (process.env.HOME || '').replace(/\/+$/, '');
  if (!home || typeof path !== 'string') return path;
  const homes = [home];
  // An unresolvable $HOME (absent, dangling) has no realpath to match; the
  // lexical prefix above is then the only form, and the path prints unchanged
  // when neither matches — a fail-safe direction (no text is invented).
  try { const real = realpathSync(home); if (real !== home && real !== '/') homes.push(real); } catch { /* lexical form only */ }
  for (const h of homes) {
    if (path === h) return '~';
    if (path.startsWith(h + '/')) return '~' + path.slice(h.length);
  }
  return path;
}
// An identifier-only cause: `e.code ?? e.name` if it is an identifier, else
// `unknown`. Never the message.
export function errIdent(e) {
  const id = e?.code ?? e?.name;
  return (typeof id === 'string' || typeof id === 'number') && IDENT_RE.test(String(id)) ? String(id) : 'unknown';
}
// Our own retainOutput artifact: <tmpdir>/csq-preflight-output-XXXXXX/output.json,
// restricted to a conservative charset with no `..` segment.
export function isOwnEvidencePath(path) {
  return typeof path === 'string' && EVIDENCE_PATH_RE.test(path)
    && !path.split('/').includes('..')
    && basename(path) === 'output.json'
    && EVIDENCE_DIR_RE.test(basename(dirname(path)));
}
export function shownEvidencePath(path) {
  return isOwnEvidencePath(path) ? homeTilde(path) : 'evidence path not recognised';
}
// A repo-relative path (test script name, shellcheck file): no leading `/`, no
// `..` segment, conservative charset.
export function isRelPath(p) {
  return typeof p === 'string' && REL_PATH_RE.test(p) && !p.startsWith('/') && !p.split('/').includes('..');
}
export function shownTestName(n) {
  return isRelPath(n) ? n : 'test name not recognised';
}

export function testNames(root) {
  return readdirSync(join(root, 'scripts/tests')).filter((n) => n.endsWith('.test.sh')).sort();
}
function exitState(rows) {
  // A LATCHED STOP IS NEVER GREEN (D237 R2 sec L5). A stop that lands after
  // every started row has passed left exitState with no non-GREEN row, so the
  // run printed GREEN although it was interrupted and the remaining work never
  // ran. A real RED still wins; otherwise a stop is UNDETERMINED.
  if (stopSignal()) return rows.some((r) => r.state === 'RED') ? 'RED' : 'UNDETERMINED';
  if (rows.some((r) => r.state === 'RED')) return 'RED';
  if (rows.some((r) => r.state === 'UNDETERMINED')) return 'UNDETERMINED';
  if (rows.some((r) => r.state === 'SKIPPED')) return 'SKIPPED';
  return 'GREEN';
}
// A wrapper's verdict lines name its failing tests; stdout's FIRST line is
// merely whichever test printed first (verbose runners list one line per test
// before the verdict, and that line reads like a pass). SINCE 2026-10-17 the
// RED line prints only the COUNT of these names (allowlist-only output); the
// names, and the first-line fallback, are no longer printed — the retained
// file carries them. The history below explains why the count is name-based.
// Reproduced 2026-10-11: the old slice(0,100) summary named
// test_actual_shard_setup_failure_... on a Linux red whose failing set was
// four other tests, which hid the real failures from every reader.
// FOUR verdict dialects reach this gate, enumerated 2026-10-11 across every
// scripts/tests/*.test.sh as a positive allowlist (counts are emitted-string
// literals, not files):
//   1. python unittest:   `FAIL: test_x (__main__.T)` / `ERROR: test_y (…)`  (4)
//   2. bash two-space:    `  FAIL  <check name> — expected exit N, got M`   (78)
//   3. bash em-dash:      `  FAIL — case 3: <detail>`  — name follows the
//      dash and ends at the first colon                              (8)
//   4. bash single-space: `  FAIL <name>: <detail>` (~30) and column-0
//      `FAIL <name>` from printf formats                              (5)
// Matching only dialect 1 silently fell back to first-line blame for exactly
// the affected wrapper family. The INDENT anchors are load-bearing
// and exact (`^ {2}FAIL {2}`, never `^\s*`): wrappers print their subject's
// output between checks, so an unanchored pattern (or one accepting
// `ERROR:root:`-style logging) names lines inside that output as extra
// failures (review R1 LOW-1). BEST-EFFORT by design: banner/cell shapes like
// `[  FAIL  ]`. The column-0 arm also names column-0 FAIL lines printed INSIDE
// a wrapper's dumped nested output — accepted, bounded by the exact anchors
// (review R2 LOW-4). Padded printf rows (`FAIL %-52s want…`,
// `  FAIL %-62s want=…`) are matched with the name column cut at the first
// colon, ` -- `, or a run of 2+ spaces, so the padding and detail stay out of
// the summary (review R2 LOW-2); a name containing a literal double space
// would be truncated with it. The two-space arm cuts ` -- ` and 2+ spaces
// only — its names keep colons (`shellcheck: …`).
// The name-column cut for the padded printf dialects (`FAIL %-52s want…`,
// `  FAIL %-62s want=…`): stop the captured name at the first detail
// separator — a colon, ` -- `, or a run of 2+ spaces (review R2 LOW-2; a
// name containing a literal double space is truncated with the padding,
// accepted).
const cutName = (s) => s.replace(/:.*$/, '').replace(/ -- .*$/, '').replace(/ {2,}.*$/, '');
function failingTestNames(out) {
  const names = [];
  for (const line of String(out || '').split('\n')) {
    let name = null;
    let m;
    if ((m = line.match(/^(?:FAIL|ERROR): (\S.*)$/))) name = m[1].replace(/ \(.*$/, '').replace(/ -- .*$/, '');
    else if ((m = line.match(/^ {2}FAIL {2}(\S.*)$/))) name = m[1].replace(/ -- .*$/, '').replace(/ {2,}.*$/, '');
    else if ((m = line.match(/^ {2}FAIL — (\S.*)$/))) name = cutName(m[1]);
    else if ((m = line.match(/^ {2}FAIL (\S.*)$/))) name = cutName(m[1]);
    else if ((m = line.match(/^FAIL (\S.*)$/))) name = cutName(m[1]);
    if (name === null) continue;
    const dash = name.indexOf(' — ');
    if (dash !== -1) name = name.slice(0, dash);
    name = name.trim();
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}
// One RED row's summary line: its script name, exit code and failing-check
// COUNT (the names and any output line stay in the retained file — allowlist-only
// output), then a retained-output path the READER can actually open. On a
// canonical run the worker's retained `evidence.path` names a file on the
// offload host, so prefer the local replay (retainLocalReplay) — and when the
// replay ITSELF failed, say so and mark the foreign path as such, instead of
// silently handing the operator an unreadable path (review R1 MED-1). A row
// with no `out` at all (a malformed worker frame) counts zero rather than
// throwing TypeError out of the gate (review R2 LOW-5).
// ALLOWLIST-ONLY: the script name (allowlisted path), its exit code (digits)
// and the BUCKETED count of recognised failing-check lines. The names themselves are free
// text a wrapper (or output it dumps) printed, so they stay in the retained file.
// The failing-check count is derived from the wrapper's own output, so it is
// attacker-steerable: print it BUCKETED (0 / 1 / 2-9 / 10-99 / 100+), never exact.
function countBucket(n) {
  return n <= 0 ? '0' : n === 1 ? '1' : n <= 9 ? '2-9' : n <= 99 ? '10-99' : '100+';
}
export function redFailureLine(r) {
  const count = countBucket(failingTestNames(r.out).length);
  const rc = Number.isInteger(r.rc) ? String(r.rc) : 'none';
  const evidence = r.local_evidence ?? r.evidence;
  let retained = evidence?.path ? ` (full output: ${shownEvidencePath(evidence.path)})` : '';
  if (r.local_evidence_error)
    retained = ` (local replay failed: ${/^[a-z-]{1,64}$/.test(String(r.local_evidence_error)) ? r.local_evidence_error : 'cause not recognised'}; worker-host path: ${r.evidence?.path ? shownEvidencePath(r.evidence.path) : 'none'})`;
  return `${shownTestName(r.n)}: rc=${rc}, ${count} failing check line(s)${retained}`;
}
// Canonical runs offload each shard to a Linux host, so the worker's retained
// `evidence.path` names a file on THAT host — unreadable where the operator
// reads the verdict (a macOS push gate). Replay every failing wrapper's full
// output into a LOCAL retained file and name that path in the RED line instead
// (the full failing output must survive somewhere the next
// reader can actually open). Idempotent; entries already carrying a replay are
// left alone.
export function retainLocalReplay(results) {
  for (const r of results) {
    if (r.state !== 'RED' || r.local_evidence) continue;
    try {
      r.local_evidence = retainOutput({ status: r.rc, signal: null, error: null,
        elapsed_ms: r.ms, stdout: r.out ?? '', stderr: '' }, r.n);
    } catch {
      r.local_evidence_error = 'output-replay-write-failed';
    }
  }
  return results;
}
// A bound that kills MUST say what it killed (the 2026-10-19 generate-artifacts
// row was killed at 600 s with an EMPTY output stream — nothing named its cause).
// Runs from capture's onTimeout while the child is still alive and before the
// first signal, so the process tree and its open files are observable. It is
// synchronous by contract, self-bounded to <5 s (ps 1.5 s + up to 3 lsof at
// 0.8 s + /proc reads), and every line carries one CSQ_STUCK prefix so the
// retained evidence for a killed row answers "what was it waiting on".
export function stuckDiagnostics(child) {
  const pid = child?.pid;
  if (!Number.isInteger(pid)) return 'CSQ_STUCK no_child_pid';
  const lines = [`CSQ_STUCK timeout_kill pid=${pid}`];
  // `ok:false` means the tool did not run (absent, or hit its bound) — a fact
  // recorded below, never folded into "it printed nothing".
  const run = (cmd, args, ms) => {
    try {
      const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: ms, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
      return { ok: !r.error, lines: r.error ? [] : String(r.stdout ?? '').split('\n').filter(Boolean) };
    } catch { return { ok: false, lines: [] }; }
  };
  // The child is spawned detached, so its pid is also its process-group id.
  // A ps that did not run is NAMED: reporting processes_in_group=0 in that
  // case would read as "the child had no processes", the opposite fact.
  const group = [];
  const psr = run('ps', ['-A', '-o', 'pid=,ppid=,pgid=,stat=,etime=,comm='], 1500);
  if (!psr.ok) lines.push('CSQ_STUCK ps=unavailable');
  for (const line of psr.lines) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    if (f[2] === String(pid) || f[0] === String(pid)) {
      group.push({ pid: f[0], ppid: f[1], stat: f[3], etime: f[4], comm: f.slice(5).join(' ') });
    }
  }
  if (psr.ok) {
    lines.push(`CSQ_STUCK processes_in_group=${group.length}`);
    for (const g of group.slice(0, 12)) {
      lines.push(`CSQ_STUCK proc pid=${g.pid} ppid=${g.ppid} stat=${g.stat} etime=${g.etime} comm=${g.comm}`);
    }
    if (group.length > 12) lines.push(`CSQ_STUCK proc_truncated=${group.length - 12}`);
  }
  // Open files of the group leader and up to two children: a lock shared with
  // another leg, a FIFO, or a socket names itself in the path column. The
  // descriptor SELECTION (not a row cap) is what keeps the held file visible:
  // cwd/txt/mem/rtd rows are boilerplate (one process has dozens of txt rows),
  // and a plain `-p PID` capped at six rows showed nothing but those. `-n -P`
  // skip DNS/port lookups and `-b` avoids a helper fork that could orphan on a
  // hung mount; all three keep the call inside its 800 ms bound.
  let lsofUnavailable = false;
  for (const g of group.slice(0, 3)) {
    const r = run('lsof', ['-n', '-P', '-w', '-b', '-a', '-p', g.pid, '-d', '^cwd,^txt,^mem,^rtd'], 800);
    if (!r.ok) lsofUnavailable = true;
    const files = r.lines.slice(1)
      .map((l) => l.trim().split(/\s+/).slice(8).join(' ')).filter(Boolean).slice(0, 6);
    if (files.length) lines.push(`CSQ_STUCK lsof pid=${g.pid} ${files.join(' ')}`);
  }
  if (lsofUnavailable) lines.push('CSQ_STUCK lsof=unavailable');
  // Linux-only: the kernel wait channel. A blocked flock/read/pipe names its
  // cause here even when no file is held; absent on macOS (not evidence, just
  // unavailable).
  for (const g of group.slice(0, 3)) {
    try {
      const w = readFileSync(`/proc/${g.pid}/wchan`, 'utf8').trim();
      lines.push(`CSQ_STUCK wchan pid=${g.pid} ${w || 'running'}`);
    } catch { /* not Linux, or the process vanished: unavailable */ }
  }
  return lines.slice(0, 20).join('\n');
}
// `perTestMs` is ONE wrapper's bound, deliberately distinct from the whole-set
// ceiling its caller names: it is what actually kills a wedged wrapper, and it
// is RECORDED on every row so each downstream detail names the bound that
// fired rather than a bound the run never reached.
export async function runLocalTests(root, names, perTestMs, { env = process.env, stopWhen = () => false } = {}) {
  // A stop must not be followed by a new detached wrapper: every start is
  // gated on the caller's latch, and capture() registers each child with the
  // stop set (D237 R2 HIGH-1/MED-A).
  if (stopWhen()) return names.map((n) => ({ n, state: 'UNDETERMINED', rc: null, ms: 0, executed: false, out: 'stopped by signal before this test started' }));
  const policy = await capture('python3', ['scripts/ci/undetermined-allowlist.py'], { cwd: root, env, stopWhen });
  const allowed = new Map();
  if (policy.status === 0 && !policy.error && !policy.signal) {
    for (const line of policy.stdout.split('\n')) {
      const [kind, path, token] = line.split('\t');
      if (kind === 'ALLOW' && /^scripts\/tests\/[A-Za-z0-9_.-]+\.test\.sh$/.test(path) && token) allowed.set(path.slice(14), token);
    }
  }
  const results = [];
  for (const n of names) {
    if (stopWhen()) { results.push({ n, state: 'UNDETERMINED', rc: null, ms: 0, executed: false, out: 'stopped by signal before this test started' }); continue; }
    if (!existsSync(join(root, 'scripts/tests', n))) { results.push({ n, state: 'UNDETERMINED', rc: null, ms: 0, executed: false, out: 'missing enumerated test' }); continue; }
    const testEnv = { ...env, DEV_PREFLIGHT_IN_SELFTEST: '1' };
    for (const key of ['CSQ_PREFLIGHT_WORKER_TOKEN','CSQ_PREFLIGHT_PARENT_FINGERPRINT','CSQ_PREFLIGHT_CANONICAL_WORKER','DEV_PREFLIGHT_ONLY']) delete testEnv[key];
    const r = await capture('bash', [join(root, 'scripts/tests', n)], { cwd: root, env: testEnv, timeoutMs: perTestMs, onTimeout: (child) => stuckDiagnostics(child), stopWhen });
    const out = r.stdout + r.stderr + (r.timeout_diagnostics ? `\n${r.timeout_diagnostics}\n` : '');
    let state = r.error || r.signal || r.timedOut ? 'UNDETERMINED' : r.status === 0 ? 'GREEN' : 'RED';
    if ((r.evidence_error || !r.evidence) && state === 'GREEN') state = 'UNDETERMINED';
    const token = allowed.get(n);
    if (r.status === 2 && token && out.split('\n').some((l) => l.startsWith(`UNDETERMINED[${token}]`))) state = 'SKIPPED';
    results.push({ n, state, rc: r.status, ms: r.elapsed_ms, executed: !r.error || r.status !== null, out,
      timedOut: r.timedOut, per_test_ms: perTestMs, timeout_diagnostics: r.timeout_diagnostics, evidence: r.evidence, evidence_error: r.evidence_error });
  }
  return results;
}
// The full repository always prepares its pinned tools. Small transport fixtures
// without repository markers prepare only when they contain a known subject.
export async function prepareShellTools(root, names, { env = process.env } = {}) {
  const subjects = new Set(['auto-format-hook.test.sh', 'post-edit-dispatch.test.sh',
    'citation-resolution.test.sh', 'oauth-replay-toolchain.test.sh', 'shell-gate-undetermined.test.sh',
    'job-budget-audit.test.sh', 'dev-preflight.test.sh']);
  const helper = join(root, 'scripts/ci/prepare-preflight-shell-tools.sh');
  const needed = existsSync(join(root, 'CLAUDE.md')) || existsSync(join(root, 'package.json')) || names.some((n) => subjects.has(n));
  if (!existsSync(helper)) return needed ? { error: 'required shell-tool preparation helper missing' } : { env };
  const r = await capture('bash', [helper, root, ...names], { cwd: root, env, timeoutMs: 305000 });
  const evidence = r.evidence;
  if (r.status !== 0 || r.error || r.signal || r.timedOut || r.evidence_error || !evidence)
    return { error: 'shell-tool preparation failed or unmeasured', evidence };
  let frame;
  try { frame = JSON.parse(r.stdout); } catch { return { error: 'shell-tool preparation frame malformed', evidence }; }
  if (frame.schema !== 'csq.preflight_shell_tools.v1' || JSON.stringify(frame.test_names) !== JSON.stringify(names) ||
      !['READY','NONE'].includes(frame.state) || (needed && frame.state !== 'READY') || !Array.isArray(frame.path_prefixes) ||
      frame.path_prefixes.some((p) => typeof p !== 'string' || !p.startsWith(resolve(root) + '/') || p.includes('..') || p.includes(delimiter)) ||
      (frame.python_bin !== undefined && (typeof frame.python_bin !== 'string' || frame.python_bin !== join(root, 'target/.csq-preflight-shell-tools/venv/bin/python3'))))
    return { error: 'shell-tool preparation identity mismatch', evidence };
  return { env: { ...env, PATH: [...frame.path_prefixes, env.PATH || ''].join(delimiter),
    ...(frame.python_bin ? { PYTHON_BIN: frame.python_bin, PYTHONPATH: '', PYTHONNOUSERSITE: '1' } : {}) }, evidence, setup: frame };
}
// TWO bounds, and the difference is the point of naming both. `ceilingMs` is
// the caller's whole-set budget: it stays cap-validated (finite, > 0, ≤900000)
// and it is an UPPER bound on `perTestMs`, so the per-test bound can never
// exceed it. It is NOT enforced as a wall-clock bound on the set (the set is
// time-boxed by what its members cost); the bound that actually kills anything
// is the per-test one. Before the split, one number had to serve both roles, so
// a 900s "ceiling" was also each wrapper's 900s bound and a single wedged
// wrapper consumed the whole set budget. The `perTestMs = ceilingMs` default
// keeps the pre-split single-bound contract for callers that name only a
// ceiling (scripts/tests drive this module directly with one number).
// ONE source for the shard count: the CI step's SHARD_TOTAL in test.yml. A
// local/CI drift in the split is a D237 rule-9 parity gap even when the test
// SET is identical (the 2026-10-22 review found this module splitting 2 ways
// while CI split 3). Refuse to guess if the declaration is unreadable.
// EXACTLY ONE declaration or no answer (D237 R2 LOW-1): a first-match read
// would silently follow whichever job happens to be printed first the moment a
// second SHARD_TOTAL is added — the parity drift this reader exists to stop.
function configuredShardTotal(root) {
  try {
    const text = readFileSync(join(root, '.github/workflows/test.yml'), 'utf8');
    const declarations = text.split('\n').filter((line) => /^[ \t]*SHARD_TOTAL:[ \t]*"[0-9]+"[ \t]*$/.test(line));
    if (declarations.length !== 1) return null;
    const n = Number(/"[0-9]+"/.exec(declarations[0])[0].slice(1, -1));
    return Number.isInteger(n) && n >= 2 ? n : null;
  } catch {
    return null;
  }
}

// Why a shard attempt produced no command verdict, in fixed vocabulary plus
// shape-checked footer fields only (parseFooter refuses free text), so a 116
// shard is reported as "nothing ran", never as a bare partial count.
function shardOffloadCause(r, f, attempt, boundMs) {
  const after = attempt ? ' after one retry' : '';
  if (r.timedOut) return `caller timeout at the ${Math.round(boundMs / 1000)}s shard bound${after}`;
  if (r.error?.code === 'FLEET_ADMISSION' && r.stderr === 'caller fleet admission deadline exhausted') return `no caller fleet slot freed while a full attempt still fit the shard's deadline budget (nothing ran)${after}`;
  if (r.error?.code) return `capture error ${r.error.code}${after}`;
  if (r.signal) return `trestle killed by ${r.signal}${after}`;
  if (!f) return `trestle exit ${r.status} with no terminal framed footer${after}`;
  const where = f.kind === 'engine' ? `engine:${f.engine}` : f.kind === 'arbiter' ? `arbiter:${f.arbiter}` : 'command';
  if (f.kind === 'command') return `footer exit=${f.code} command but trestle exited ${r.status}`;
  const what = [113, 104, 116].includes(f.code) ? 'nothing ran' : f.code === 114 ? 'outcome UNKNOWN' : 'offload failed';
  const extra = ['cause', 'lock', 'requirement'].filter((k) => f[k]).map((k) => ` ${k}=${f[k]}`).join('');
  return `trestle exit=${f.code} ${where}${extra} (${what})${after}`;
}
// A shard attempt's caller bound: the --wait-s it spends INSIDE trestle, the
// self-test ceiling the shard worker is launched with (--ceiling-ms), and room
// for tree shipping and node start-up. The old fixed 30 min was exactly
// trestle's 900 s default wait plus the 900 s ceiling, with no room.
const SHARD_TRANSPORT_MARGIN_MS = 15 * 60 * 1000;
export function shardCallerTimeoutMs(ceilingMs) {
  return attemptMsFor(ceilingMs + SHARD_TRANSPORT_MARGIN_MS);
}
// The shard's ONE deadline, with the same budget shape as a heavy gate's:
// each attempt's caller-slot admission share plus its full bound.
export function shardDeadlineMs(ceilingMs) {
  return budgetDeadlineMsFor(shardCallerTimeoutMs(ceilingMs));
}
// One shard attempt as runShellGate launches it: the trestle argv (EVERY
// attempt passes LEG_QUEUE_WAIT_S; trestle's default wait is shorter than its
// io cool-down), the caller bound, and the caller-slot wait derived from what
// remains of the shard's deadline (0 = no attempt fits). Pure and exported so
// the self-test asserts exactly what the call site uses.
export function shardAttemptFor({ shard, shards, ceilingMs, perTestMs, remainingMs }) {
  const boundMs = shardCallerTimeoutMs(ceilingMs);
  return {
    args: ['run', '--os', 'linux', '--wait-s', String(LEG_QUEUE_WAIT_S), '--', 'node',
      'scripts/ci/preflight-shell-tests.mjs', '--shard', String(shard), '--shards', String(shards),
      '--ceiling-ms', String(ceilingMs), '--per-test-ms', String(perTestMs)],
    timeoutMs: boundMs,
    admissionWaitMs: admissionWaitMsFor(remainingMs, boundMs),
  };
}
export async function runShellGate(root, { local = false, ceilingMs = 900000, perTestMs = ceilingMs, stopWhen = () => false } = {}) {
  const started = performance.now();
  let names;
  try { names = testNames(root); } catch { return { state: 'UNDETERMINED', detail: 'cannot enumerate scripts/tests/' }; }
  if (!names.length) return { state: 'UNDETERMINED', detail: 'glob scripts/tests/*.test.sh matched 0 files' };
  if (!Number.isFinite(ceilingMs) || ceilingMs <= 0 || ceilingMs > 900000) return { state: 'UNDETERMINED', detail: 'invalid self-test ceiling' };
  // A per-test bound that is not a usable number, or that exceeds the ceiling
  // the caller named, is a cannot-measure, never a pass: silently clamping it
  // would kill wrappers under a bound nobody asked for.
  if (!Number.isFinite(perTestMs) || perTestMs <= 0 || perTestMs > ceilingMs) return { state: 'UNDETERMINED', detail: 'invalid per-test bound (must be finite, > 0 and no larger than the ceiling)' };
  const evidence = [];
  let results;
  if (local) results = await runLocalTests(root, names, perTestMs, { stopWhen });
  else {
    const configured = configuredShardTotal(root);
    if (configured === null) return { state: 'UNDETERMINED', detail: 'test.yml declares no usable SHARD_TOTAL' };
    const shards = Math.min(configured, names.length);
    const parts = await Promise.all(Array.from({ length: shards }, async (_, shard) => {
      const label = `self-test shard ${shard + 1}/${shards}`;
      const deadline = performance.now() + shardDeadlineMs(ceilingMs);
      for (let attempt = 0; attempt < LEG_ATTEMPTS; attempt++) {
        // A stop during attempt 0 must never start attempt 1 (or a spawn that
        // outlives the stop): the retry path is where a detached group used to
        // be orphaned (D237 R2 HIGH-1/MED-A).
        if (stopWhen()) return { error: 'self-test shard stopped by signal' };
        // The caller-slot wait comes out of this shard's deadline (never a
        // fixed cap): it may last as long as a full attempt bound still fits.
        const plan = shardAttemptFor({ shard, shards, ceilingMs, perTestMs, remainingMs: deadline - performance.now() });
        if (plan.admissionWaitMs <= 0) return { error: `${label} deadline exhausted — no room for a full ${Math.round(plan.timeoutMs / 1000)}s attempt${attempt ? ' after one retry' : ''} (nothing ran)` };
        const r = await capture('trestle', plan.args, { cwd: root, timeoutMs: plan.timeoutMs, admissionWaitMs: plan.admissionWaitMs, stopWhen }); evidence.push(r.evidence);
        if (stopWhen()) return { error: 'self-test shard stopped by signal' };
        const f = parseFooter(r);
        // Same retry set as dev-preflight's runHeavy: 113/104/116 mean nothing
        // ran (engine OR arbiter footer), 114/2 engine footers are re-run once.
        if (attempt === 0 && f && f.kind !== 'command' && ([113,104,116].includes(f.code) || (f.kind === 'engine' && [2,114].includes(f.code))) && !stopWhen()) continue;
        if (r.error || r.signal || !f || f.kind !== 'command' || f.code !== r.status) return { error: `${label} offload did not return a command verdict — ${shardOffloadCause(r, f, attempt, plan.timeoutMs)}` };
        const frames = r.stdout.split('\n').filter((l) => l.startsWith('CSQ_SHELL_RESULT '));
        if (frames.length !== 1) return { error: 'self-test shard did not return one result frame' };
        let frame; try { frame = JSON.parse(frames[0].slice(17)); } catch { return { error: 'malformed self-test shard frame' }; }
        const assigned = names.filter((_, i) => i % shards === shard);
        if (frame.schema !== 'csq-shell-shard-v1' || frame.shard !== shard || frame.shards !== shards || JSON.stringify(frame.all_names) !== JSON.stringify(names) ||
          !Array.isArray(frame.results) || JSON.stringify(frame.results.map((x) => x.n)) !== JSON.stringify(assigned) ||
          frame.results.some((x) => typeof x.executed !== 'boolean' || !['GREEN','RED','UNDETERMINED','SKIPPED'].includes(x.state)) ||
          r.status !== (exitState(frame.results) === 'RED' ? 1 : exitState(frame.results) === 'UNDETERMINED' ? 2 : 0)) return { error: 'self-test shard membership or verdict mismatch' };
        return { results: frame.results, ...(r.evidence_error || !r.evidence ? { error: 'shard output evidence unavailable' } : {}) };
      }
      return { error: `${label} exhausted its retry` };
    }));
    results = parts.flatMap((p) => p.results || []).sort((a, b) => a.n.localeCompare(b.n));
    if (parts.some((p) => p.error)) {
      // A partial offload still names its failing tests and still replays their
      // output locally — a RED whose reader cannot open any file is the same
      // AC-1 gap on this path as on the complete path (review R1 MED-1). This
      // branch only exists for local:false, so the replay always applies.
      retainLocalReplay(results);
      const failed = results.filter((r) => r.state === 'RED');
      const failedDetail = failed.length ? ` — ${failed.map(redFailureLine).join(' | ')}` : '';
      return { state: results.some((r) => r.state === 'RED') ? 'RED' : 'UNDETERMINED', detail: `validated ${results.length}/${names.length} test results; ${parts.filter((p) => p.error).map((p) => p.error).join('; ')}${failedDetail}`, self_tests: results.map(({ out, ...r }) => r), heavy_output_evidence: evidence.filter(Boolean), execution_coverage: { executed: results.filter((r) => r.executed).length, enumerated: names.length } };
    }
  }
  const state = exitState(results), failed = results.filter((r) => r.state === 'RED');
  if (!local) retainLocalReplay(results);
  const und = results.filter((r) => r.state === 'UNDETERMINED'), skipped = results.filter((r) => r.state === 'SKIPPED');
  const slowest = results.reduce((a, r) => r.ms > a.ms ? r : a, results[0]);
  const timing = `ran ${results.filter((r) => r.executed).length} of ${results.length} self-test wrapper(s) in ${((performance.now()-started)/1000).toFixed(1)}s; slowest ${shownTestName(slowest.n)} at ${(slowest.ms/1000).toFixed(1)}s`;
  let detail = timing;
  if (failed.length) detail = `${failed.length}/${results.length} self-test(s) failed — ${failed.map(redFailureLine).join(' | ')} — ${timing}`;
  // A killed wrapper's bound is read off ITS OWN row (`per_test_ms`), so a
  // frame that was measured under a different bound than the caller asked for
  // reports the bound that actually fired. The `?? perTestMs` arm covers rows
  // that never reached a capture (the missing-test row above).
  if (und.length) detail += ` — ${und.map((r) => r.timedOut ? `${shownTestName(r.n)} exceeded the ${(r.per_test_ms ?? perTestMs)/1000}s per-test bound and was killed` : shownTestName(r.n)).join(', ')} could not finish`;
  if (skipped.length) detail += ` — ${skipped.length} UNDETERMINED (declared; wrapper invoked, subject not measured): ${skipped.map((r) => shownTestName(r.n)).join(', ')}`;
  return { state, detail, heavy_output_evidence: evidence.filter(Boolean),
    self_tests: results.map(({ out, ...r }) => r), execution_coverage: { executed: results.filter((r) => r.executed).length, enumerated: names.length }, elapsed_ms: performance.now()-started };
}
// REALPATHS on both sides: `resolve()` is lexical, but Node's ESM loader
// realpaths module files. On macOS every `mkdtemp` fixture under
// /var/folders/... aliases /private/var/folders/..., so the lexical form
// compared UNEQUAL and the CLI silently no-opped (exit 0, empty stdout) —
// caught by dev-preflight-runtime.test.sh's large-frame leg. A symlinked
// checkout path is the same class. try/catch: when this module is IMPORTED
// (not run), argv[1] can be the stdin marker `-` or absent, and realpath of a
// non-existent path throws — an import must never fail on the guard.
let invokedAsEntry = false;
if (process.argv[1]) {
  try { invokedAsEntry = realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url)); } catch {}
}
if (invokedAsEntry) {
  // ONE stop set (D237 R2 advisory LOW): the shard CLI runs supervised captures
  // but installed no handlers, so a SIGTERM killed the CLI and left every
  // wrapper it had started running, unsignalled. The handlers drain the captures
  // and the latch refuses new wrappers below.
  installStopHandlers({});
  const args = process.argv.slice(2), root = process.cwd();
  // TWO shapes, one contract, because the parent's argv must match this parser
  // EXACTLY or every offloaded shard dies on argv before printing a frame (a
  // fail-closed UNDETERMINED, but a silent one). The per-test form below is
  // what runShellGate emits; the 6-argument form is the pre-split shape, where
  // the ceiling doubled as each wrapper's bound, and is still accepted because
  // scripts/tests drive this entry directly with one number.
  const legacyShards = args.length === 6, perTestShards = args.length === 8;
  const shard = Number(args[1]), shards = Number(args[3]), ceilingMs = Number(args[5]);
  const perTestMs = legacyShards ? ceilingMs : Number(args[7]);
  // The shard CEILING is the same single source the parent reads (D237 R2 N1).
  // A literal `shards > 2` here refused the parent's SHARD_TOTAL=3 fan-out at
  // argv, so every offloaded shard exited 2 with NO frame, every offloaded shell
  // gate came back UNDETERMINED, and every dev push was refused — a fail-closed
  // gate with no way to pass that its own stub-trestle row could not see. A tree
  // with no usable declaration keeps the historical 2: the parent refuses to fan
  // out at all when configuredShardTotal is null, so no real run reaches this
  // fallback with a declaration the file failed to yield, and fixtures that drive
  // this CLI directly with one shard stay valid.
  const shardCeiling = configuredShardTotal(root) ?? 2;
  if ((!legacyShards && !perTestShards) || args[0] !== '--shard' || args[2] !== '--shards' || args[4] !== '--ceiling-ms' ||
      (perTestShards && args[6] !== '--per-test-ms') ||
      !Number.isInteger(shard) || !Number.isInteger(shards) || shards < 1 || shards > shardCeiling || shard < 0 || shard >= shards ||
      !Number.isFinite(ceilingMs) || ceilingMs <= 0 || ceilingMs > 900000 ||
      !Number.isFinite(perTestMs) || perTestMs <= 0 || perTestMs > ceilingMs) await exitAfterBackstops(2);
  const names = testNames(root), assigned = names.filter((_,i) => i % shards === shard);
  if (!assigned.length) await exitAfterBackstops(2);
  const prepared = await prepareShellTools(root, assigned);
  const results = prepared.error ? assigned.map((n) => ({ n, state: 'UNDETERMINED', rc: null, ms: 0, executed: false, out: prepared.error, setup_evidence: prepared.evidence })) : await runLocalTests(root, assigned, perTestMs, { env: prepared.env, stopWhen: () => !!stopSignal() });
  console.log('CSQ_SHELL_RESULT ' + JSON.stringify({ schema: 'csq-shell-shard-v1', shard, shards, all_names: names, results, prerequisite_evidence: prepared.evidence, prerequisite_setup: prepared.setup }));
  // Natural exit lets Node drain the complete JSON frame to a pipe.
  const state = exitState(results); process.exitCode = state === 'RED' ? 1 : state === 'UNDETERMINED' ? 2 : 0;
}
