import { fork, spawn } from 'node:child_process';
import { chmodSync, mkdtempSync, writeFileSync, mkdirSync, lstatSync, realpathSync, unlinkSync, rmdirSync, readdirSync, openSync, closeSync, fstatSync, readSync, constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';

export const FLEET_SHARE_CAP = 6;
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
async function acquireFleetSlot({ env, waitMs }) {
  if (!Number.isFinite(waitMs) || waitMs <= 0 || waitMs > 30 * 60 * 1000) throw new Error('invalid fleet admission deadline');
  const directory = fleetScope(env), deadline = performance.now() + waitMs;
  do {
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
  // Accept only launcher-owned fields, once each, on this terminal footer.
  const metadata = {};
  for (const field of m[6].trim().split(/ +/).filter(Boolean)) {
    const at = field.indexOf('='), key = field.slice(0, at), value = field.slice(at + 1);
    if (!['tree', 'host', 'wall', 'lock'].includes(key) || Object.hasOwn(metadata, key)) return null;
    if (key === 'tree' && !/^[0-9a-f]{40}$/.test(value)) return null;
    if (key === 'host' && !/^[A-Za-z0-9_.-]+$/.test(value)) return null;
    if (key === 'wall' && !/^[0-9]+(?:\.[0-9]+)?s$/.test(value)) return null;
    metadata[key] = value;
  }
  if ((output?.signal || output?.timedOut) && m[3] === 'command') return null;
  return { code: Number(m[2]), kind: m[3] === 'command' ? 'command' : m[4] ? 'engine' : 'arbiter',
    engine: m[4], arbiter: m[5], ...metadata };
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
function killOwned(child, signal) {
  try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, signal); } catch {}
}
export async function capture(command, args, { cwd, env = process.env, timeoutMs = 0, onTimeout = null } = {}) {
  const started = performance.now();
  let release;
  try { if (command === 'trestle') release = await acquireFleetSlot({ env, waitMs: Math.min(timeoutMs || 30 * 60 * 1000, 30 * 60 * 1000) }); }
  catch (e) {
    const r = { status: null, signal: null, error: { code: 'FLEET_ADMISSION' }, timedOut: false, stdout: '', stderr: String(e.message), elapsed_ms: performance.now() - started };
    try { r.evidence = retainOutput(r, command); } catch { r.evidence_error = 'output-evidence-write-failed'; }
    return r;
  }
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
    let stdout = '', stderr = '', error = null, timedOut = false, bytes = 0;
    let timeoutDiagnostics = '';
    let killTimer;
    const stop = () => { killOwned(child, 'SIGTERM'); if (!killTimer) killTimer = setTimeout(() => killOwned(child, 'SIGKILL'), 2000); };
    const collect = (which, chunk) => {
      bytes += chunk.length;
      if (bytes > 512 * 1024 * 1024) { error = { code: 'OUTPUT_LIMIT' }; stop(); return; }
      if (which === 'stdout') stdout += chunk.toString(); else stderr += chunk.toString();
    };
    child.stdout.on('data', (d) => collect('stdout', d)); child.stderr.on('data', (d) => collect('stderr', d));
    child.on('error', (e) => { error = { code: e.code ?? 'SPAWN_ERROR' }; });
    // The hook runs while the child is STILL ALIVE and before the first signal,
    // so a bound-kill can name what it killed (process tree, open files). It is
    // synchronous by contract (bounded internally) and never allowed to change
    // the verdict: a throwing or absent hook costs one fixed line, not a pass.
    const timer = timeoutMs ? setTimeout(() => {
      timedOut = true;
      if (typeof onTimeout === 'function') {
        try { timeoutDiagnostics = String(onTimeout(child) ?? ''); } catch { timeoutDiagnostics = 'CSQ_STUCK diagnostic_failed'; }
      }
      stop();
    }, timeoutMs) : null;
    child.on('close', (status, signal) => {
      if (timer) clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      try { release?.(); } catch { error = { code: 'FLEET_LEASE_RELEASE' }; }
      const r = { status, signal, error, timedOut, stdout, stderr, elapsed_ms: performance.now() - started, ...(timeoutDiagnostics ? { timeout_diagnostics: timeoutDiagnostics } : {}) };
      try { r.evidence = retainOutput(r, command); } catch { r.evidence_error = 'output-evidence-write-failed'; }
      resolve(r);
    });
  });
}
// Fixed shell wrapper inserts --locked before lint's `--` separator. Cargo fmt
// does not resolve a graph and deliberately receives no unsupported lock flag.
export function lockedScript(command) {
  const flat = command.replace(/\\\r?\n/g, ' ').trim();
  const direct = /^cargo(?:[ \t]+\+[A-Za-z0-9_.-]+)?[ \t]+(?:build|check|clippy|doc|test|run|metadata|tree|fetch|update|generate-lockfile|fmt|clean|help|--help|-h|--version|-V)(?:[ \t]+(?:[A-Za-z0-9_./:=,+@%+-]+|'[^'\r\n]*'|"[^"$`\\\r\n]*"))*[ \t]*$/;
  if (!direct.test(flat) && !(arguments[1]?.fixture && !/cargo|[$`]/i.test(flat))) throw new Error('unsupported command grammar: cannot prove direct locked Cargo argv');
  return `cargo() { local tc="" sub; if [[ "\${1:-}" == +* ]]; then tc="$1"; shift; fi; sub="\${1:-}"; shift || return 125; case "$sub" in build|check|clippy|doc|test|run|metadata|tree|fetch|update|generate-lockfile) if [[ -n "$tc" ]]; then command cargo "$tc" "$sub" --locked "$@"; else command cargo "$sub" --locked "$@"; fi ;; fmt|clean|help|--help|-h|--version|-V) if [[ -n "$tc" ]]; then command cargo "$tc" "$sub" "$@"; else command cargo "$sub" "$@"; fi ;; *) printf '%s\\n' 'UNDETERMINED: unsupported Cargo subcommand' >&2; return 125 ;; esac; };\n${command}`;
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
const BARE_SIGNOFF_SCRIPTS = new Set(['bash scripts/check-edition-leak.sh', 'bash scripts/check-third-party-licenses-fresh.sh', COMMUNITY_EXTRACTION_COMMAND]);
export function signoffScript(command, { token, buildStub = false, fixture = false }) {
  if (!/^[a-z0-9-]+$/.test(token)) throw new Error('invalid leg marker token');
  const body = BARE_SIGNOFF_SCRIPTS.has(command) ? command : lockedScript(command, { fixture });
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
  const previous = stderr.at(-2);
  if (previous?.startsWith('[trestle-remote-run] exit=')) {
    const remote = parseFooter(previous);
    if (!remote || remote.kind !== 'command' || remote.code !== footer.code) return { und: 'inconsistent preceding remote footer' };
    if (remote.tree !== undefined && remote.tree !== tree) return { und: 'preceding remote footer tree mismatch' };
    remoteSeen = true;
    remoteHost = remote.host || null;
  }
  // LAUNCHER PLACEMENTS, WITH REROUTES (Q8). A refused admission is rerouted:
  //   host=A (remote) slot=n ADMITTED
  //   host=A REFUSED this run (…)
  //   rerouting to host=B
  //   host=B (remote) slot=m ADMITTED
  // Counting every placement line made a refused-then-rerouted leg look like
  // TWO hosts and forced UNDETERMINED — measured on every linux leg while
  // the host's remote_run_root was unmounted and the launcher rerouted. A
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
  // (last line) and the remote footer (previous line) are read from the
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
    // A REMOTE placement implies the remote-run wrapper ran the leg, so its
    // footer must be the line before the terminal footer (Q8 sec L2): a remote
    // placement with no remote footer is an unpaired observation.
    if (live.kind === 'remote' && !remoteSeen) {
      return { und: 'remote placement without a preceding remote footer' };
    }
  }
  // A REMOTE FOOTER IS CORROBORATION, NEVER THE SOLE OBSERVATION (Q8 R2 sec M1).
  // The tree can print `[trestle-remote-run] … host=X` after its sentinel — on a
  // local leg with no other output it lands at -2 — and counting it alone
  // promoted UND ("no launcher-owned observed host") to ok with a forged host.
  // It may contribute a host only when a pre-sentinel (remote) placement or a
  // terminal-footer host already anchors the attribution; a LIVE (local, …)
  // placement beside a remote footer is contradictory outright.
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
export function cachedScript(command) {
  return `cache=""; if command -v timeout >/dev/null 2>&1 && command -v sccache >/dev/null 2>&1 && timeout --signal=TERM --kill-after=1s 3s sccache --version >/dev/null 2>&1; then cache="$(command -v sccache)"; export RUSTC_WRAPPER="$cache" CARGO_INCREMENTAL=0; printf '%s\\n' 'CSQ_CACHE_BEFORE' >&2; timeout --signal=TERM --kill-after=1s 3s sccache --show-stats >&2 || printf '%s\\n' 'CSQ_CACHE_STATS_UNDETERMINED' >&2; else printf '%s\\n' 'CSQ_CACHE_UNAVAILABLE' >&2; fi\n( ${command}\n); rc=$?; if [[ -n "$cache" ]]; then printf '%s\\n' 'CSQ_CACHE_AFTER' >&2; timeout --signal=TERM --kill-after=1s 3s sccache --show-stats >&2 || printf '%s\\n' 'CSQ_CACHE_STATS_UNDETERMINED' >&2; fi; exit "$rc"`;
}
export function aggregateExit(rows) {
  if (rows.some((r) => r.state === 'RED')) return 1;
  if (rows.some((r) => r.state === 'UNDETERMINED')) return 2;
  return 0;
}
export async function runGateWorkers(names, { script, cwd, env, fingerprint, onComplete, timeoutMs = 35 * 60 * 1000 }) {
  const children = new Set();
  const fleetEnv = env.CSQ_PREFLIGHT_FLEET_DIR ? env : { ...env, ...(defaultFleetScope ||= createFleetScope()) };
  const stop = () => { for (const child of children) killOwned(child, 'SIGTERM'); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  const launch = (name) => new Promise((resolve) => {
    const token = randomUUID(), started = performance.now();
    const childEnv = { ...fleetEnv, DEV_PREFLIGHT_ONLY: name, CSQ_PREFLIGHT_WORKER_TOKEN: token,
      CSQ_PREFLIGHT_PARENT_FINGERPRINT: fingerprint, CSQ_PREFLIGHT_CANONICAL_WORKER: env.DEV_PREFLIGHT_ONLY ? '0' : '1' };
    if (!env.DEV_PREFLIGHT_ONLY) {
      for (const key of ['DEV_PREFLIGHT_SELFTEST_LOCAL','CSQ_PREFLIGHT_LOCAL','DEV_PREFLIGHT_SELFTEST_CEILING_MS','DEV_PREFLIGHT_SELFTEST_PER_TEST_MS','DEV_PREFLIGHT_FORCE_NO_BASH','DEV_PREFLIGHT_FORCE_WINGNU','DEV_PREFLIGHT_FORCE_NO_WINGNU']) delete childEnv[key];
    }
    const child = fork(script, [], { cwd, env: childEnv, execArgv: [], stdio: ['ignore', 'pipe', 'pipe', 'ipc'], detached: process.platform !== 'win32' });
    children.add(child);
    let stdout = '', stderr = '', frame = null, error = null, duplicate = false, killTimer;
    const watchdog = setTimeout(() => { error = { code: 'WORKER_TIMEOUT' }; killOwned(child, 'SIGTERM'); killTimer = setTimeout(() => killOwned(child, 'SIGKILL'), 2000); }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d.toString(); }); child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (e) => { error = { code: e.code ?? 'SPAWN_ERROR' }; });
    child.on('message', (m) => {
      if (frame) duplicate = true;
      if (m && m.token === token && m.gate?.name === name && m.fingerprint === fingerprint && m.no_receipt === true) frame = m;
      else duplicate = true;
    });
    child.on('close', (status, signal) => {
      children.delete(child); clearTimeout(watchdog); if (killTimer) clearTimeout(killTimer);
      let row = frame?.gate;
      if (duplicate || error || signal || !row || !['GREEN','RED','UNDETERMINED','SKIPPED','NOT_APPLICABLE'].includes(row.state) || status !== aggregateExit([row])) {
        row = { name, state: 'UNDETERMINED', detail: 'gate worker did not return one consistent, source-bound verdict' };
      }
      const r = { status, signal, error, stdout, stderr, elapsed_ms: performance.now() - started };
      try { row.worker_output_evidence = retainOutput(r, name); } catch { if (row.state !== 'RED') row.state = 'UNDETERMINED'; row.detail = (row.detail || '') + '; could not retain worker output'; }
      row.elapsed_ms = r.elapsed_ms;
      onComplete?.(row);
      resolve(row);
    });
  });
  const pending = Promise.all(names.map(launch));
  try { return await pending; } finally { process.off('SIGTERM', stop); process.off('SIGINT', stop); }
}
