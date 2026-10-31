// The frontend leg has no Rust prerequisites. Keep its admission and private
// clone separate from locked Cargo argv and sccache, while runHeavy retains
// ownership of fleet admission, supervision, output and footer evidence.
export const SVELTE_GATE = 'Svelte tests — derived from test.yml';
export const SVELTE_STEPS = [
  { name: 'Install dependencies', command: 'npm ci', phase: 'install', minutes: 5 },
  { name: 'Type-check (svelte-check + tsc)', command: 'npm run check', phase: 'typecheck', minutes: 5 },
  { name: 'Run tests', command: 'npx vitest run', phase: 'vitest', minutes: 10 },
];

// Deliberately bounded YAML grammar: changed execution context must be admitted
// explicitly rather than silently running a different job under its old name.
export function deriveSvelteCommands(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim() && !/^\s*#/.test(l));
  const starts = lines.map((l, i) => /^  svelte-test:\s*$/.test(l) ? i : -1).filter(i => i >= 0);
  const err = 'Svelte CI command/context contract is unavailable or unsupported';
  if (starts.length !== 1 || lines.some(l => /^defaults:/.test(l))) return { err };
  // test.yml shares Rust/cache metadata with all jobs. Admit only its known
  // inert scalar forms; frontend execution uses no Rust and owns its TMPDIR.
  // A new npm, Node, shell or other execution input needs explicit admission.
  const envStarts = lines.map((l, i) => /^env:/.test(l) ? i : -1).filter(i => i >= 0);
  if (envStarts.length > 1) return { err };
  if (envStarts.length) {
    const at = envStarts[0];
    if (lines[at] !== 'env:') return { err };
    const seen = new Set();
    for (let i = at + 1; i < lines.length && /^\s/.test(lines[i]); i += 1) {
      const l = lines[i];
      if (!/^  (?:CARGO_TERM_COLOR: always|TMPDIR: \/tmp|RUST_BACKTRACE: 1|CARGO_NET_GIT_FETCH_WITH_CLI: "true"|RUST_VERSION: [0-9]+\.[0-9]+\.[0-9]+|CACHE_VERSION: v[0-9]+)$/.test(l)) return { err };
      const key = l.slice(2, l.indexOf(':'));
      if (seen.has(key)) return { err };
      seen.add(key);
    }
  }
  const start = starts[0];
  let end = start + 1;
  while (end < lines.length && !/^  \S/.test(lines[end])) end += 1;
  const job = lines.slice(start + 1, end);
  const stepsAt = job.findIndex(l => /^    steps:\s*$/.test(l));
  const context = job.slice(0, stepsAt);
  if (stepsAt < 0 || context.some(l => /^    (?:env|if|continue-on-error|container):/.test(l))) return { err };
  const defaultsAt = context.findIndex(l => /^    defaults:\s*$/.test(l));
  let defaultsEnd = defaultsAt + 1;
  while (defaultsEnd < context.length && /^      /.test(context[defaultsEnd])) defaultsEnd += 1;
  if (defaultsAt < 0 || context.slice(defaultsAt, defaultsEnd).join('\n') !==
      '    defaults:\n      run:\n        working-directory: csq/ui') return { err };
  const steps = [];
  for (const l of job.slice(stepsAt + 1)) {
    if (/^      - /.test(l)) steps.push([]);
    if (!steps.length) return { err };
    steps.at(-1).push(l);
  }
  const setup = steps.filter(s => s.some(l => /^        uses: actions\/setup-node@[^\s]+$/.test(l)) ||
    /^      - uses: actions\/setup-node@[^\s]+$/.test(s[0]));
  if (setup.length !== 1 || !setup[0].some(l => /^          node-version: ['"]?24['"]?\s*$/.test(l))) return { err };
  let previous = -1;
  const commands = [];
  for (const spec of SVELTE_STEPS) {
    const hits = steps.map((s, i) => s[0] === `      - name: ${spec.name}` ? i : -1).filter(i => i >= 0);
    if (hits.length !== 1 || hits[0] <= previous) return { err };
    previous = hits[0];
    const step = steps[hits[0]];
    if (step.length !== 3 || step[1] !== `        run: ${spec.command}` ||
        step[2] !== `        timeout-minutes: ${spec.minutes}`) return { err };
    commands.push(step[1].slice('        run: '.length));
  }
  return { commands };
}

const shellQuote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
// heavyScript's stage 0 has already removed every non-identifier name. The
// leg then re-execs through /usr/bin/env -i with an ALLOWLIST (the body later
// proves every surviving name is on it), so no exported function string,
// npm_config_* key or other host input reaches npm or its children. An exported
// SHELLOPTS/BASHOPTS is refused by name rather than silently dropped.
const ENV_BEFORE_EXPORTS = 'PATH PWD OLDPWD SHLVL _ LANG LC_ALL TMPDIR';
const ENV_AFTER_EXPORTS = `${ENV_BEFORE_EXPORTS} HOME USERPROFILE XDG_CONFIG_HOME TMP TEMP GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_TERMINAL_PROMPT CI NPM_CONFIG_USERCONFIG NPM_CONFIG_GLOBALCONFIG`;

export function svelteScript(commands, { token, tree, env }) {
  if (!/^[a-z0-9-]+$/.test(token)) throw new Error('invalid leg marker token');
  if (!/^[0-9a-f]{40}$/.test(tree)) throw new Error('invalid source fingerprint');
  // The leg owns its whole environment; a step env would be silently dropped.
  if (env && Object.keys(env).length) throw new Error('Svelte leg cannot carry step env');
  if (!Array.isArray(commands) || commands.length !== SVELTE_STEPS.length ||
      commands.some((c, i) => c !== SVELTE_STEPS[i].command)) throw new Error('unsupported Svelte commands');
  const phases = commands.map((command, i) => {
    const spec = SVELTE_STEPS[i];
    const [tool, ...args] = command.split(' ');
    // Markers start on a fresh line: tool output ending mid-line or in \r must
    // not merge with them. Timing goes to stderr, outside the phase oracle.
    return `printf '\\nCSQ_PREFLIGHT_SVELTE_PHASE ${token} ${spec.phase} START\\n'
csq_svelte_phase_start=$SECONDS
"$csq_svelte_timeout" --signal=TERM --kill-after=5s ${spec.minutes * 60}s "$csq_svelte_${tool}" ${args.join(' ')}
csq_svelte_command_rc=$?
printf '\\nCSQ_PREFLIGHT_SVELTE_TIMING ${token} ${spec.phase} %s\\n' "$((SECONDS - csq_svelte_phase_start))" >&2
printf '\\nCSQ_PREFLIGHT_SVELTE_PHASE ${token} ${spec.phase} RC %s\\n' "$csq_svelte_command_rc"
[ "$csq_svelte_command_rc" -eq 0 ] || exit "$csq_svelte_command_rc"`;
  }).join('\n');
  const body = `set -o pipefail
# -p imported no function; drop any defined anyway, then prove none survived,
# and that no exported-function string reaches a child.
for csq_svelte_fn in $(compgen -A function); do builtin unset -f -- "$csq_svelte_fn" || exit 125; done
[ -z "$(compgen -A function)" ] || exit 125
# Defined only after the function purge above, which would remove it.
# Every environment name must be on the allowlist (NUL-separated entries).
csq_svelte_env_only() {
  csq_svelte_env_seen=
  while IFS= read -r -d '' csq_svelte_entry; do
    case " $1 " in *" \${csq_svelte_entry%%=*} "*) ;; *) return 125 ;; esac
    csq_svelte_env_seen=1
  done < <(/usr/bin/env -0)
  [ -n "$csq_svelte_env_seen" ]
}
csq_svelte_env_only '${ENV_BEFORE_EXPORTS}' || exit 125
# Only absolute PATH entries: an empty or relative entry resolves a tool from
# the cwd, which is tree-controlled once the leg is inside the clone.
csq_svelte_path=
IFS=: read -r -a csq_svelte_entries <<< "$PATH"
for csq_svelte_entry in "\${csq_svelte_entries[@]}"; do
  case "$csq_svelte_entry" in /*) csq_svelte_path="\${csq_svelte_path:+$csq_svelte_path:}$csq_svelte_entry" ;; esac
done
[ -n "$csq_svelte_path" ] || exit 125
PATH=$csq_svelte_path
export PATH
csq_svelte_source=$(pwd -P) || exit 125
csq_svelte_tmp=
# Resolve a tool once, by absolute path. The REAL file (symlinks resolved) must
# lie outside the source and the private tree, and it and every ancestor up to
# / must be owned by root or this uid and not group/other-writable (a sticky
# directory such as /tmp is allowed: others cannot replace entries in it).
# find and realpath vouch for every other tool, so they never come from PATH
# (a planted find would certify itself): first executable of a fixed list.
csq_svelte_find= csq_svelte_realpath=
for csq_svelte_cand in /usr/bin/find /bin/find; do
  if [ -f "$csq_svelte_cand" ] && [ -x "$csq_svelte_cand" ]; then csq_svelte_find=$csq_svelte_cand; break; fi
done
for csq_svelte_cand in /usr/bin/realpath /bin/realpath; do
  if [ -f "$csq_svelte_cand" ] && [ -x "$csq_svelte_cand" ]; then csq_svelte_realpath=$csq_svelte_cand; break; fi
done
[ -n "$csq_svelte_find" ] && [ -n "$csq_svelte_realpath" ] || exit 125
csq_svelte_trusted() {
  csq_svelte_walk=$1
  while :; do
    csq_svelte_unsafe=$("$csq_svelte_find" "$csq_svelte_walk" -maxdepth 0 \\( \\( \\( -perm -020 -o -perm -002 \\) ! -perm -1000 \\) -o \\( ! -user 0 ! -user "$EUID" \\) \\) -print) || return 125
    [ -z "$csq_svelte_unsafe" ] || return 125
    [ "$csq_svelte_walk" != / ] || break
    csq_svelte_walk=\${csq_svelte_walk%/*}
    csq_svelte_walk=\${csq_svelte_walk:-/}
  done
}
csq_svelte_tool() {
  csq_svelte_found=$(type -P "$1") || return 125
  case "$csq_svelte_found" in /*) ;; *) return 125 ;; esac
  csq_svelte_real=$("$csq_svelte_realpath" "$csq_svelte_found") || return 125
  case "$csq_svelte_real" in /*) ;; *) return 125 ;; esac
  case "$csq_svelte_real" in "$csq_svelte_source"/*) return 125 ;; esac
  if [ -n "$csq_svelte_tmp" ]; then case "$csq_svelte_real" in "$csq_svelte_tmp"/*) return 125 ;; esac; fi
  csq_svelte_trusted "$csq_svelte_real" || return 125
  printf '%s' "$csq_svelte_found"
}
csq_svelte_trusted "$("$csq_svelte_realpath" "$csq_svelte_find")" && csq_svelte_trusted "$("$csq_svelte_realpath" "$csq_svelte_realpath")" || exit 125
csq_svelte_git=$(csq_svelte_tool git) && csq_svelte_mktemp=$(csq_svelte_tool mktemp) &&
  csq_svelte_rm=$(csq_svelte_tool rm) && csq_svelte_mkdir=$(csq_svelte_tool mkdir) &&
  csq_svelte_timeout=$(csq_svelte_tool timeout) || exit 125
for csq_svelte_git_key in \${!GIT_@}; do unset "$csq_svelte_git_key" || exit 125; done
csq_svelte_tree='${tree}'
umask 077
csq_svelte_tmpbase=\${TMPDIR:-/tmp}
# A SIGKILLed leg never reaches its cleanup. Reap this uid's private leg dirs
# older than a day (a live leg is bounded far below that); -H follows only the
# base, never an entry, and -type d skips symlinks.
"$csq_svelte_find" -H "$csq_svelte_tmpbase" -mindepth 1 -maxdepth 1 -type d -name 'csq-svelte.??????' -user "$EUID" -perm 700 -mmin +1440 -exec "$csq_svelte_rm" -rf -- {} + ||
  printf '\\nCSQ_PREFLIGHT_SVELTE_NOTE ${token} PRUNE_INCOMPLETE\\n'
csq_svelte_tmp=$("$csq_svelte_mktemp" -d "$csq_svelte_tmpbase/csq-svelte.XXXXXX") || exit 125
trap 'csq_svelte_rc=$?; "$csq_svelte_rm" -rf -- "$csq_svelte_tmp" || exit 125; exit "$csq_svelte_rc"' EXIT
# Compare physical paths on both sides, including Darwin's /var -> /private/var.
csq_svelte_physical_tmp=$(cd "$csq_svelte_tmp" && pwd -P) || exit 125
csq_svelte_tmp="$csq_svelte_physical_tmp"
"$csq_svelte_mkdir" -m 700 "$csq_svelte_tmp/home" "$csq_svelte_tmp/tmp" || exit 125
while IFS= read -r csq_svelte_env; do
  case "$csq_svelte_env" in PATH|PWD|LANG|LC_ALL|TERM) ;; *) unset "$csq_svelte_env" || exit 125 ;; esac
done < <(compgen -e)
export HOME="$csq_svelte_tmp/home" USERPROFILE="$csq_svelte_tmp/home" XDG_CONFIG_HOME="$csq_svelte_tmp/home/.config"
export TMPDIR="$csq_svelte_tmp/tmp" TMP="$csq_svelte_tmp/tmp" TEMP="$csq_svelte_tmp/tmp"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
# GitHub Actions sets CI=true; Vitest then fails on a missing snapshot rather than writing it.
export CI=true
# npm refuses to load the same config path in both user and global scopes.
# Fresh HOME plus umask 077 gives these distinct empty files private modes.
{ : > "$HOME/.npmrc" && : > "$HOME/.npmrc-global"; } || { printf '%s\\n' 'CSQ_PREFLIGHT_SVELTE_CONFIG_UNAVAILABLE' >&2; exit 125; }
export NPM_CONFIG_USERCONFIG="$HOME/.npmrc" NPM_CONFIG_GLOBALCONFIG="$HOME/.npmrc-global"
csq_svelte_env_only '${ENV_AFTER_EXPORTS}' || exit 125
# Trestle's carried HEAD may be synthetic; the parent's tree is authoritative.
csq_svelte_head=$("$csq_svelte_git" rev-parse --verify HEAD^{commit}) || exit 125
csq_svelte_source_guard() {
  [ "$("$csq_svelte_git" -C "$csq_svelte_source" rev-parse --show-toplevel)" = "$csq_svelte_source" ] || return 125
  [ "$("$csq_svelte_git" -C "$csq_svelte_source" rev-parse --verify HEAD^{commit})" = "$csq_svelte_head" ] || return 125
  [ "$("$csq_svelte_git" -C "$csq_svelte_source" rev-parse --verify HEAD^{tree})" = "$csq_svelte_tree" ] || return 125
  csq_svelte_status=$("$csq_svelte_git" -C "$csq_svelte_source" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) || return 125
  [ -z "$csq_svelte_status" ] || return 125
}
csq_svelte_config() { "$csq_svelte_git" -C "$1" config --null --show-origin --list | "$csq_svelte_git" hash-object --stdin; }
csq_svelte_source_guard || exit 125
csq_svelte_source_config=$(csq_svelte_config "$csq_svelte_source") || exit 125
csq_svelte_cleanup() {
  csq_svelte_rc=$?
  csq_svelte_source_guard || csq_svelte_rc=125
  [ "$(csq_svelte_config "$csq_svelte_source")" = "$csq_svelte_source_config" ] || csq_svelte_rc=125
  if [ -n "\${csq_svelte_clone_config:-}" ]; then
    [ "$(csq_svelte_config "$csq_svelte_tmp/tree")" = "$csq_svelte_clone_config" ] || csq_svelte_rc=125
    [ "$("$csq_svelte_git" -C "$csq_svelte_tmp/tree" rev-parse HEAD^{commit})" = "$csq_svelte_head" ] || csq_svelte_rc=125
    [ "$("$csq_svelte_git" -C "$csq_svelte_tmp/tree" rev-parse HEAD^{tree})" = "$csq_svelte_tree" ] || csq_svelte_rc=125
    csq_svelte_clone_status=$("$csq_svelte_git" -C "$csq_svelte_tmp/tree" status --porcelain=v1 --untracked-files=all --ignore-submodules=none) || csq_svelte_rc=125
    [ -z "$csq_svelte_clone_status" ] || csq_svelte_rc=125
  fi
  cd "$csq_svelte_source" || csq_svelte_rc=125
  "$csq_svelte_rm" -rf -- "$csq_svelte_tmp" || csq_svelte_rc=125
  exit "$csq_svelte_rc"
}
trap csq_svelte_cleanup EXIT
# One commit is all the leg needs; the clone is bounded like every phase.
"$csq_svelte_timeout" --signal=TERM --kill-after=5s 300s "$csq_svelte_git" clone --quiet --no-local --depth 1 --no-checkout "$csq_svelte_source" "$csq_svelte_tmp/tree" || exit 125
cd "$csq_svelte_tmp/tree" || exit 125
"$csq_svelte_git" checkout --quiet --detach "$csq_svelte_head" || exit 125
[ "$("$csq_svelte_git" rev-parse HEAD^{tree})" = "$csq_svelte_tree" ] && [ -z "$("$csq_svelte_git" status --porcelain --untracked-files=all)" ] || exit 125
csq_svelte_clone_config=$(csq_svelte_config "$csq_svelte_tmp/tree") || exit 125
csq_svelte_source_guard || exit 125
[ "$(csq_svelte_config "$csq_svelte_source")" = "$csq_svelte_source_config" ] || exit 125
cd csq/ui || exit 125
[ "$(pwd -P)" = "$csq_svelte_tmp/tree/csq/ui" ] || exit 125
csq_svelte_node=$(csq_svelte_tool node) && csq_svelte_npm=$(csq_svelte_tool npm) && csq_svelte_npx=$(csq_svelte_tool npx) || exit 125
[ "$("$csq_svelte_node" -p 'process.versions.node.split(".")[0]')" = 24 ] || exit 125
${phases}`;
  return `( printf '\\nCSQ_PREFLIGHT_LEG_START ${token}\\n' >&2
( csq_svelte_keep=("PATH=$PATH" "TMPDIR=\${TMPDIR:-/tmp}")
[ -z "\${LANG+x}" ] || csq_svelte_keep+=("LANG=$LANG")
[ -z "\${LC_ALL+x}" ] || csq_svelte_keep+=("LC_ALL=$LC_ALL")
while IFS= read -r -d '' csq_svelte_entry; do
  case "\${csq_svelte_entry%%=*}" in SHELLOPTS|BASHOPTS) printf '\\nCSQ_PREFLIGHT_SVELTE_REFUSED ${token} %s\\n' "\${csq_svelte_entry%%=*}"; exit 125 ;; esac
done < <(/usr/bin/env -0)
exec /usr/bin/env -i "\${csq_svelte_keep[@]}" /bin/bash --noprofile --norc -p -c ${shellQuote(body)} csq-svelte-leg
); csq_leg_rc=$?; printf '\\nCSQ_PREFLIGHT_LEG_RC ${token} %s\\n' "$csq_leg_rc"; exit "$csq_leg_rc"
)`;
}

export function svelteResult(result, { token }) {
  const out = String(result.out || '');
  const refused = out.split(/\r?\n/).find(l => l.startsWith(`CSQ_PREFLIGHT_SVELTE_REFUSED ${token} `))?.split(' ')[2];
  const note = out.split(/\r?\n/).includes(`CSQ_PREFLIGHT_SVELTE_NOTE ${token} PRUNE_INCOMPLETE`)
    ? '; stale csq-svelte temp prune incomplete (see retained output)' : '';
  let und = result.und || (/^(SHELLOPTS|BASHOPTS)$/.test(refused || '') ? `Svelte leg refused an exported ${refused}` : null) ||
    ([124, 125, 126, 127].includes(result.leg_rc) || result.leg_rc >= 128
    ? 'Svelte prerequisites, source guards or bounded execution unavailable' : null);
  let failed = null;
  // Missing, duplicated or out-of-order phase evidence cannot vouch for work.
  // Match only this attempt's fixed-vocabulary markers; raw diagnostics stay
  // in retained output and never enter the operator-facing gate detail.
  if (!und) {
    const actual = out.split(/\r?\n/).filter(l => l.startsWith('CSQ_PREFLIGHT_SVELTE_PHASE '));
    const expected = [];
    for (const spec of SVELTE_STEPS) {
      expected.push(`CSQ_PREFLIGHT_SVELTE_PHASE ${token} ${spec.phase} START`);
      const rcLine = actual[expected.length];
      const rcPrefix = `CSQ_PREFLIGHT_SVELTE_PHASE ${token} ${spec.phase} RC `;
      if (!rcLine?.startsWith(rcPrefix) || !/^(0|[1-9][0-9]{0,2})$/.test(rcLine.slice(rcPrefix.length))) break;
      expected.push(rcLine);
      if (Number(rcLine.slice(rcPrefix.length)) !== 0) break;
    }
    const last = expected.at(-1);
    if (actual.length !== expected.length || actual.some((l, i) => l !== expected[i]) ||
        !last?.endsWith(` RC ${result.leg_rc}`) || (result.ok && expected.length !== 6))
      und = 'Svelte phase evidence missing or inconsistent';
    // The last phase that ran is the failing one. A failed dependency install
    // measures the registry, network or lockfile fetch, not the frontend.
    else if (!result.ok) failed = SVELTE_STEPS[expected.length / 2 - 1].phase;
    if (failed === 'install') und = 'Svelte dependency install (npm ci) failed: registry/network or lockfile mismatch; not scored; see retained output';
  }
  return { state: und ? 'UNDETERMINED' : result.ok ? 'GREEN' : 'RED',
    detail: (und || (result.ok ? `Svelte install/typecheck/vitest LEG_RC=${result.leg_rc}` : `Svelte ${failed} phase failed LEG_RC=${result.leg_rc}`)) + note,
    leg: { platform: 'linux', host: result.host ?? null, host_provenance: result.host_provenance ?? [],
      wall_ms: result.wall_ms ?? null, rc: result.leg_rc ?? null, tree: result.tree ?? null, porcelain: result.porcelain ?? null } };
}
