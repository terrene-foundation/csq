#!/usr/bin/env node
// dev-preflight — the ONLY check that exists before a push to `dev`.
//
// `dev` is CI-free by construction: every push trigger under .github/workflows
// is `branches: [main]` or tags-only, verified via the runs API (delta 0 runs
// across six separate pushes), not by reading trigger config. That is what makes
// the trunk reachable for free — and it means nothing downstream will catch a bad
// push. This runs first, and writes a RECEIPT keyed to the exact commit it
// checked. The push guard refuses unless a green receipt matching HEAD exists.
//
// A receipt is bound to a SHA, never to "ran recently": amending, rebasing, or
// adding one more commit invalidates it. That is the point — a receipt that
// survives the change it was meant to vouch for is not evidence.
//
// WHERE THE RECEIPT LIVES, and why not `.git/`: the `.git` admin subtree is a
// protected path in this repo (loom#1470 — `.git/config` can re-point a guard's
// repo identity and `.git/hooks/*` runs arbitrary code on checkout), so tooling
// does not write there. It goes at the repo root, gitignored.
//
// EXIT CODES — three outcomes (durable-instruments.md MUST-2)
//   0  GREEN         every gate passed; receipt written
//   1  RED           a gate failed; no receipt written
//   2  UNDETERMINED  a gate could not run (missing tool, unreadable ref).
//                    NEVER folded into 0 — "I could not check" and "it is
//                    clean" are different claims, and on a trunk with no CI
//                    that difference is the entire safety margin.
//
// TWO FURTHER per-gate states exist alongside the three exit codes, and they
// are DELIBERATELY DISTINCT — collapsing them into one was this file's own
// first-draft defect (dev-push-guard.sh's reader only ever recognised GREEN,
// so a receipt carrying either one REFUSED every push that produced it —
// caught by executing the guard against a receipt, not by reading it):
//
//   NOT_APPLICABLE  the gate's subject is out of scope for THIS push (e.g. no
//                   relevant files changed). A PROVEN negative — the diff
//                   cannot contain the defect class this gate checks for.
//                   Silent: no operator noise, folds into exit 0.
//
//   SKIPPED         the gate's toolchain or environment is absent on THIS
//                   host. This is NOT a proof of absence — it is "could not
//                   check", the exact claim UNDETERMINED exists to flag. It
//                   folds into exit 0 anyway (CI on `main` still covers it,
//                   and a developer without the toolchain must still be able
//                   to push), but the gap MUST be surfaced loudly — every
//                   reader of the receipt (this file's own summary AND
//                   dev-push-guard.sh at push time) prints it by name, never
//                   silently. Folding this into UNDETERMINED would refuse
//                   the push on every host that lacks the toolchain, which
//                   is most dev machines, most of the time — the opposite
//                   failure from folding it into GREEN with no trace.
//
// Both states are recorded in the receipt so the disposition stays auditable
// instead of invisible; only their NOISE differs.
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function sh(cmd, args, cwd, extraEnv) {
  return execFileSync(cmd, args, {
    encoding: "utf8",
    cwd,
    env: extraEnv ? { ...process.env, ...extraEnv } : process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

const ROOT = sh("git", ["rev-parse", "--show-toplevel"], process.cwd()).trim();
const RECEIPT = join(ROOT, ".csq-dev-preflight.json");

// The receipt must describe the state the gates ACTUALLY RAN AGAINST.
// Reading HEAD only at the END let a run bind its receipt to a commit made
// DURING it: measured 2026-09-24, a run started on face6473 wrote a receipt for
// d6731259 while most of its gates had tested a half-edited tree — and the push
// guard, which compares only the SHA, would have honoured it
// (artifact-identity.md MUST-2). So the tree is fingerprinted at START and
// re-checked at the end; any change means no receipt.
//
// The fingerprint is a git TREE hash built in a throwaway index from HEAD plus
// `git add -A`: it covers committed, staged, unstaged AND untracked-not-ignored
// content in one value. `git status` alone would miss an edit to a file that
// was already dirty at the start.
// ONE throwaway index for the whole run: seeded from HEAD once, then each
// fingerprint is just `git add -A` + `write-tree`. `add -A` syncs the index to
// the working tree completely (adds, edits AND deletions), so the tree hash
// describes the working tree regardless of what the index held before — and
// git's stat cache makes every call after the first cheap. Re-seeding per call
// measured 2.4-5.4 s each, which made a per-gate check cost about a minute.
const FP_INDEX = join(
  tmpdir(),
  `csq-preflight-idx-${process.pid}-${Date.now()}`,
);
process.on("exit", () => {
  try {
    unlinkSync(FP_INDEX);
  } catch {
    // never created (read-tree failed) or already gone; nothing to clean
  }
});
let fpSeeded = false;
function treeFingerprint() {
  const env = { GIT_INDEX_FILE: FP_INDEX };
  if (!fpSeeded) {
    sh("git", ["read-tree", "HEAD"], ROOT, env);
    fpSeeded = true;
  }
  sh("git", ["add", "-A"], ROOT, env);
  const tree = sh("git", ["write-tree"], ROOT, env).trim();
  const head = sh("git", ["rev-parse", "HEAD"], ROOT).trim();
  return `${head}:${tree}`;
}
const START_FINGERPRINT = treeFingerprint();

function tryRun(cmd, args, extraEnv) {
  try {
    return { ok: true, out: sh(cmd, args, ROOT, extraEnv) };
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

// TEST HOOK. DEV_PREFLIGHT_ONLY=<substring> runs only the gates whose name
// contains it, so the self-test can exercise one gate against a fixture repo
// without a cargo toolchain or a workflow tree. It NEVER writes a receipt — see
// the bottom of this file. A filter matching nothing exits 2 rather than 0: a
// selector that silently selected zero gates and reported green is the same
// fail-open this whole file is built against.
const ONLY = process.env.DEV_PREFLIGHT_ONLY || "";
let selected = 0;

const gates = [];
let treeMovedAfter = null; // name of the first gate after which the tree differed
function gate(name, fn) {
  if (ONLY && !name.includes(ONLY)) return;
  selected += 1;
  process.stdout.write(`  ${name} ... `);
  let r;
  try {
    r = fn();
  } catch (e) {
    r = { state: "UNDETERMINED", detail: String((e && e.message) || e) };
  }
  gates.push({ name, ...r });
  process.stdout.write(`${r.state}${r.detail ? ` — ${r.detail}` : ""}\n`);
  // Checked after EVERY gate, not only at the two ends: a tree edited and then
  // restored mid-run (A -> B -> A) fingerprints identically at start and end,
  // yet some gates tested B (round-3 security review). A per-gate check closes
  // every window except one that opens and shuts inside a single gate.
  if (!treeMovedAfter && treeFingerprint() !== START_FINGERPRINT)
    treeMovedAfter = name;
}

// TEST HOOK. DEV_PREFLIGHT_SHOW_DERIVED=<step name> prints the command
// deriveStepCommand() derives for that step, against THIS repo's real
// .github/workflows/test.yml, and exits — without probing a toolchain and
// without ever RUNNING the command. This exists so the self-test can assert
// the parser reads the real, multi-line, block-scalar windows-cfg step
// correctly, without paying for the 30-minute cross-compile that running it
// for real would cost every time the self-test runs.
if (process.env.DEV_PREFLIGHT_SHOW_DERIVED) {
  const d = deriveStepCommand(process.env.DEV_PREFLIGHT_SHOW_DERIVED);
  if (d.err) {
    console.error(d.err);
    process.exit(2);
  }
  console.log(d.cmd);
  process.exit(0);
}

console.log("dev-preflight — the only check before a CI-free push\n");

gate("cargo fmt", () => {
  const r = tryRun("cargo", ["fmt", "--all", "--", "--check"]);
  return r.ok
    ? { state: "GREEN" }
    : { state: "RED", detail: "formatting differs" };
});

gate("run-ci-gates", () => {
  // PBS_TRUNK=HEAD: promotion-base-staleness reads a REMOTE trunk ref by
  // declaration, which is right at promotion time and wrong here. Pre-push, the
  // trunk-to-be is the local commit about to leave, so reading the already-pushed
  // tip makes that gate refuse the very push whose remediation it prints — the
  // same "structurally cannot go green" shape this file has now shipped twice.
  // Pointing it at HEAD asks the question a pre-push caller can act on.
  const r = tryRun("bash", ["scripts/run-ci-gates.sh"], { PBS_TRUNK: "HEAD" });
  if (r.ok) return { state: "GREEN" };
  const unmeasured = /COULD NOT MEASURE/.test(r.out);
  return {
    state: unmeasured ? "UNDETERMINED" : "RED",
    detail: unmeasured
      ? "a gate could not measure"
      : "a gate reported findings",
  };
});

// THE GAP THIS CLOSES, measured: promotion an internal ticket (dev -> main) went RED on
// three required checks — Clippy, Sink conformance, CI gate — from ONE cause. A
// test helper returning `(Arc<Mutex<HashMap<u16, Instant>>>, ...)` trips
// clippy::type_complexity. It was verified locally with `cargo clippy -p csq-core
// --lib`, and `--lib` DOES NOT COMPILE #[cfg(test)] MODULES, so the lint never
// saw the code that had just been written. The preflight was green while `dev`
// carried a compile-breaking lint, and the first thing to notice was a promotion
// gate run.
//
// The defect was NOT "no clippy" — clippy ran. It ran a NARROWER invocation than
// CI's, so it could not fail on the thing that changed.
//
// AND THE FIRST FIX FOR THAT WAS ITSELF THE BUG, one level up. It pasted CI's
// command into an array here, "character for character", which reads like the
// obvious repair for "mine was narrower than CI's" and is not: nothing on that
// path ever READ test.yml, so the moment someone edits the real step — one more
// feature, a changed lint level, a new flag — this keeps running the old command
// and reports GREEN while CI goes red. an internal ticket names the class ("an
// instrument must DERIVE the value it checks against from the source of truth,
// never restate it"); this shipped as its fifth instance. A restated literal is
// a claim about one moment in history, and it goes stale silently.
//
// So the command is READ from the workflow, from the `clippy:` job that backs
// the required `Clippy` context. Anything that stops that read from being
// unambiguous — job gone, step renamed, an `env:` block or a ${{ }} expression
// this process cannot reproduce — is UNDETERMINED. There is deliberately NO
// fallback to a hardcoded invocation: falling back to a stale literal is exactly
// the failure being removed, and it would present as a green.
//
// WHAT IT STILL DOES NOT COVER, stated because a GREEN here must not be read as
// more than it is: `Sink conformance` lints csq-core across six SEPARATE sink
// feature sets, test-windows/native-harness lint other targets and features
// again, and nothing here RUNS the tests. No single local invocation stands in
// for those, so the coverage line at the end of this run names the gap. That
// block is PROSE describing a gap, not an instrument acting on a literal.
// GENERALIZED from a one-step `deriveClippyCommand()` — an internal ticket's own
// class caught this file a second time: hardcoding a SECOND cargo line for the
// windows-cfg step (rather than deriving it, exactly like the first) would
// have been the fifth instance of the pattern this comment block already
// names below, one paragraph down, restated word for word. `stepName` is
// matched literally (regex-escaped), never interpreted as a pattern, so a
// step name containing parens or commas — like the windows-cfg step's — is
// matched exactly rather than partially.
// Parses a YAML `env:` block starting at `startIdx` (the line carrying `env:`).
// Returns the KEY→VALUE map, or an `err` when the block cannot be reproduced
// faithfully — an unresolvable `${{ }}` expression, or a nested/complex form
// this bound grammar does not cover. A partially-parsed env would produce a
// DIFFERENT command wearing the same text, which is the failure this whole
// helper exists to avoid, so anything not plainly a scalar pair is an error.
function parseEnvBlock(lines, startIdx) {
  const env = {};
  const baseIndent = lines[startIdx].search(/\S/);
  for (let j = startIdx + 1; j < lines.length; j++) {
    const l = lines[j];
    if (!l.trim()) continue;
    const ind = l.search(/\S/);
    if (ind <= baseIndent) break;
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/.exec(l);
    if (!m)
      return {
        err: `unparsed \`env:\` entry at line ${j + 1}: ${l.trim().slice(0, 60)}`,
      };
    const raw = m[2]
      .trim()
      .replace(/^"(.*)"$/, "$1")
      .replace(/^'(.*)'$/, "$1");
    // A `secrets.*` expression is the ONE unresolvable form that is safe to
    // drop: it is a credential, so it changes whether a private dependency can
    // be FETCHED, never what the lint asserts. Dropping it lets the derivation
    // reach the run, where an unfetchable graph is reported SKIPPED — an
    // accurate "could not check" — instead of collapsing the whole gate to
    // UNDETERMINED before it can look. Every OTHER `${{ }}` form (${{ env.X }},
    // ${{ github.X }}, ${{ matrix.X }}) can change the COMMAND, so those stay
    // fatal: dropping one would produce a different command wearing the same
    // text, the failure this parser exists to prevent.
    if (/\$\{\{\s*secrets\./.test(raw)) continue;
    if (raw.includes("${{")) {
      return {
        err: `\`env:\` entry \`${m[1]}\` contains a \${{ }} expression this preflight cannot resolve`,
      };
    }
    env[m[1]] = raw;
  }
  return { env };
}

// `jobKey` is a workflow JOB KEY, not a display name: the key is what the step
// lives under, and binding to it keeps a caller pinned to a specific job rather
// than to whichever step happens to match first. Both the plain-clippy step and
// the windows-cfg step live under test.yml's `clippy:` job; the docs gate lives
// under test.yml's `docs:` job and test-enterprise.yml's
// `rust-test-enterprise:` job.
function deriveStepCommand(
  stepName,
  jobKey = "clippy",
  workflow = ".github/workflows/test.yml",
) {
  const wf = join(ROOT, workflow);
  let lines;
  try {
    lines = readFileSync(wf, "utf8").split("\n");
  } catch {
    return { err: `cannot read ${wf}` };
  }
  let ji = lines.findIndex((l) => new RegExp(`^ {2}${jobKey}:\\s*$`).test(l));
  if (ji < 0) return { err: `no \`${jobKey}:\` job in ${workflow}` };
  let jend = lines.length;
  for (let j = ji + 1; j < lines.length; j++) {
    if (/^ {2}\S/.test(lines[j])) {
      jend = j;
      break;
    }
  }
  const body = lines.slice(ji + 1, jend);

  // Job-level `env:` IS part of CI's invocation. test.yml's `docs:` job carries
  // `RUSTDOCFLAGS: -D rustdoc::broken_intra_doc_links` here rather than on the
  // step — so a derivation that dropped it would run `cargo doc` WITHOUT the
  // deny flag and report GREEN on a tree that fails in CI. That is a gate that
  // cannot go red (instrument-discipline.md MUST-1), so the env is captured and
  // passed to the subprocess rather than silently discarded.
  //
  // SCOPE — this search MUST be anchored to the job level. `body` spans the
  // WHOLE job, steps included, so an unanchored search returns the first
  // `env:` of EITHER scope. GitHub resolves `env:` by where it SITS: a
  // job-level block is a sibling of `steps:` and applies to every step in the
  // job, while a step-level block is a sibling of that step's `run:` and
  // applies to that step alone (see the step capture below, where the two are
  // merged job-under-step — GitHub's precedence). The `steps:` key's own
  // indentation is the anchor: it is a direct key of any job a step can be
  // derived from, and every step key is indented deeper than it. parseEnvBlock
  // then stops at the first line indented at or above that anchor, so the
  // block ends where the job's next direct key begins.
  //
  // Unanchored, an EARLIER unrelated step's `env:` was attributed to the job:
  // its values were merged into the derived step's invocation (which CI never
  // does), and an unresolvable value in that unrelated step collapsed this
  // whole derivation to UNDETERMINED — a gate refusing to measure a step it
  // could have measured, which is the shape that trains operators to override
  // it (tooling-self-verification.md Rule 5).
  //
  // `#`-tolerant because a trailing comment on the `steps:` key is ordinary
  // YAML; a strict match would silently find no anchor, and silently dropping
  // a real job-level `env:` is the fail-open direction this whole block exists
  // to prevent. No anchor ⇒ no `steps:` ⇒ the step search below reports the
  // derivation UNDETERMINED, so that path cannot pass unmeasured either.
  const stepsIdx = body.findIndex((l) => /^\s*steps:\s*(#.*)?$/.test(l));
  const jobIndent = stepsIdx < 0 ? -1 : body[stepsIdx].search(/\S/);
  const jobEnvIdx =
    jobIndent < 0
      ? -1
      : body.findIndex(
          (l) => l.search(/\S/) === jobIndent && /^\s*env:\s*$/.test(l),
        );
  const jobEnv = jobEnvIdx < 0 ? { env: {} } : parseEnvBlock(body, jobEnvIdx);
  if (jobEnv.err) return { err: `job \`${jobKey}\`: ${jobEnv.err}` };

  const escaped = stepName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const isStep = (l) =>
    new RegExp(`^\\s*-\\s+name:\\s*${escaped}\\s*$`).test(l);
  const hits = body.filter(isStep).length;
  if (hits === 0)
    return { err: `the \`${jobKey}:\` job has no step named \`${stepName}\`` };
  // Ambiguity is not determinable, and picking the first would be a guess.
  if (hits > 1)
    return { err: `${hits} steps named '${stepName}' in the ${jobKey} job` };

  const si = body.findIndex(isStep);
  const stepIndent = body[si].search(/\S/);
  let se = body.length;
  for (let j = si + 1; j < body.length; j++) {
    if (!body[j].trim()) continue;
    if (body[j].search(/\S/) <= stepIndent) {
      se = j;
      break;
    }
  }
  const step = body.slice(si, se);

  // Step-level `env:` overrides the job level, as GitHub Actions resolves it.
  // Captured for the same reason as the job-level block above. (This was
  // previously an outright rejection — "an env this process cannot reproduce" —
  // which was true when the value could not be passed through. It can: the
  // derived command runs under a shell with these merged over process.env, so
  // the invocation reproduces CI's rather than diverging from it.)
  const stepEnvIdx = step.findIndex((l) => /^\s*env:\s*$/.test(l));
  const stepEnv =
    stepEnvIdx < 0 ? { env: {} } : parseEnvBlock(step, stepEnvIdx);
  if (stepEnv.err) return { err: `step \`${stepName}\`: ${stepEnv.err}` };

  const ri = step.findIndex((l) => /^\s*run:\s*/.test(l));
  if (ri < 0) return { err: `the \`${stepName}\` step has no \`run:\`` };

  let cmd = /^\s*run:\s*(.*)$/.exec(step[ri])[1].trim();
  if (/^[|>][-+]?$/.test(cmd)) {
    // Block scalar: take the indented body under `run:`.
    const runIndent = step[ri].search(/\S/);
    const block = [];
    for (let j = ri + 1; j < step.length; j++) {
      if (!step[j].trim()) {
        block.push("");
        continue;
      }
      if (step[j].search(/\S/) <= runIndent) break;
      block.push(step[j]);
    }
    const filled = block.filter((l) => l.trim());
    if (!filled.length)
      return { err: `the \`${stepName}\` step's \`run:\` block is empty` };
    const strip = Math.min(...filled.map((l) => l.search(/\S/)));
    cmd = block
      .map((l) => l.slice(strip))
      .join("\n")
      .trim();
  }
  if (!cmd) return { err: `the \`${stepName}\` step's \`run:\` is empty` };
  if (cmd.includes("${{")) {
    return {
      err: `the \`${stepName}\` command contains a \${{ }} expression this preflight cannot resolve`,
    };
  }
  return { cmd, env: { ...jobEnv.env, ...stepEnv.env } };
}

gate("clippy — derived from test.yml", () => {
  const d = deriveStepCommand("Run clippy");
  if (d.err) {
    return {
      state: "UNDETERMINED",
      detail: `${d.err} — NOT falling back to a hardcoded invocation`,
    };
  }
  // Run it through a shell, the way the workflow does, so a multi-line or
  // pipeline `run:` executes as CI executes it rather than as a tokenised guess.
  const shown = d.cmd.replace(/\s+/g, " ").slice(0, 120);
  const r = tryRun("bash", ["-c", d.cmd], d.env);
  if (r.ok) return { state: "GREEN", detail: `clean; ran: ${shown}` };
  // A toolchain that could not RUN is not a lint finding and must not be
  // reported as one.
  if (!r.out.trim() || /command not found|ENOENT/i.test(r.out)) {
    return { state: "UNDETERMINED", detail: `could not run: ${shown}` };
  }
  // The derived command is echoed on EVERY path, RED included. It is the thing
  // under test here — a reader who cannot see which command produced a finding
  // cannot tell a real lint from a derivation that went wrong.
  const first = (r.out.split("\n").find((l) => /^error/.test(l)) || "findings")
    .trim()
    .slice(0, 140);
  return { state: "RED", detail: `${first} — ran: ${shown}` };
});

// THE GAP THIS SECOND CLIPPY GATE CLOSES: test.yml's `clippy:` job carries a
// SECOND step, `Clippy (windows cfg, cross-compiled)` (added 2026-09-01,
// test.yml:288-318), which lints the workspace cross-compiled for
// `x86_64-pc-windows-gnu` — the same code `#[cfg(windows)]` selects on real
// Windows, moved off billed windows-latest because the lint needs no Windows
// host (see that file's comment for the cost rationale). The gate above only
// ever derived the step literally named `Run clippy`, so this preflight has
// been blind to the ENTIRE windows-cfg lint since the day it shipped: a push
// could carry a #[cfg(windows)] lint regression straight through to `dev`
// with a GREEN receipt, and the first signal would be a red required
// `Clippy` context on the `dev` -> `main` promotion PR — the exact shape of
// gap `user-path-verification.md` and this file's own header exist to close.
//
// Scope, stated so a GREEN, NOT_APPLICABLE, or SKIPPED here is never
// over-read: this is LINT coverage only. `test-windows.yml` already recorded
// (2026-05-xx) that cross-compiled clippy did NOT catch an internal ticket's
// tokio-runtime panic — a RUNTIME defect only a real Windows execution can
// catch. This gate closes the lint gap; it says nothing about runtime
// behaviour on msvc.
//
// TWO conditions make this gate legitimately not run the cross-compile, and
// NEITHER is a lint finding, so neither is RED — but they are NOT the same
// claim, and get DIFFERENT states (see the header comment's NOT_APPLICABLE
// vs SKIPPED split; conflating them was this file's own first-draft defect,
// caught by executing dev-push-guard.sh against a receipt carrying each):
//
//   (a) the push does not touch Rust surface — `**/*.rs`, `**/Cargo.toml`,
//       `**/Cargo.lock`, `rust-toolchain.toml` — mirroring test-windows.yml's
//       own path filter (:14-18). This gate is materially heavier than every
//       sibling gate here (CI budgets the cross-compile 30 minutes cold), so
//       it is relevance-gated rather than run unconditionally on every push.
//       A PROVEN negative: the diff cannot contain a cfg(windows) lint
//       regression. -> NOT_APPLICABLE.
//
//   (b) the host lacks the `x86_64-pc-windows-gnu` sysroot or `mingw-w64` — a
//       missing TOOLCHAIN, not a missing pass. `-D warnings` is baked into
//       the derived command, so a genuine lint finding and an absent
//       toolchain MUST be distinguishable: the toolchain check is a POSITIVE
//       pre-probe (sysroot dir exists AND the mingw binary resolves), run
//       BEFORE anything executes — never inferred from a failure string,
//       or a real lint finding whose stderr happened to read like "not
//       found" would be swallowed as a skip (instrument-discipline.md
//       MUST-1: a check that cannot discriminate is not a check). This is
//       "could not check", NOT a proof of absence. -> SKIPPED, and every
//       reader of the receipt MUST surface it by name rather than silently.
//
// Neither produces UNDETERMINED: UNDETERMINED blocks the push
// (dev-push-guard.sh), and lacking this cross toolchain is the NORMAL state
// of most dev machines, most of the time — folding (b) into UNDETERMINED
// would make such a host structurally unable to ever push. Both fold into
// exit 0, and both are written into the receipt so neither is silently
// dropped — only their operator-facing NOISE differs.
function probeWindowsCrossToolchain() {
  // TEST SEAMS, mirroring the DEV_PREFLIGHT_ONLY hook above: the real probe
  // below depends on what happens to be installed on THIS host, which is not
  // a fact the self-test may depend on (a CI runner with no mingw must pin
  // the SAME cannot-measure case a dev laptop with mingw pins). Unset in
  // every real invocation.
  if (process.env.DEV_PREFLIGHT_FORCE_NO_WINGNU) {
    return {
      ok: false,
      reason:
        "forced unavailable via DEV_PREFLIGHT_FORCE_NO_WINGNU (test seam)",
    };
  }
  if (process.env.DEV_PREFLIGHT_FORCE_WINGNU) {
    return { ok: true };
  }
  const sysroot = tryRun("rustc", ["--print", "sysroot"]);
  if (!sysroot.ok)
    return { ok: false, reason: "`rustc --print sysroot` failed" };
  const target = join(
    sysroot.out.trim(),
    "lib",
    "rustlib",
    "x86_64-pc-windows-gnu",
    "lib",
  );
  let hasTarget = false;
  try {
    hasTarget = statSync(target).isDirectory();
  } catch {
    hasTarget = false;
  }
  const mingw = tryRun("which", ["x86_64-w64-mingw32-gcc"]);
  if (hasTarget && mingw.ok) return { ok: true };
  const missing = [];
  if (!hasTarget)
    missing.push(`x86_64-pc-windows-gnu target (expected ${target})`);
  if (!mingw.ok)
    missing.push(
      "x86_64-w64-mingw32-gcc (mingw-w64; e.g. brew install mingw-w64)",
    );
  return { ok: false, reason: missing.join("; ") };
}

function touchesRustSurface() {
  // Mirrors test-windows.yml:14-18's path filter exactly, so "is this push
  // relevant" answers the same question CI's own Windows path-gate answers.
  const diff = tryRun("git", ["diff", "--name-only", "origin/main", "HEAD"]);
  if (!diff.ok) return { err: "could not diff HEAD against origin/main" };
  const files = diff.out.split("\n").filter(Boolean);
  const hit = files.find(
    (f) =>
      f.endsWith(".rs") ||
      /(^|\/)Cargo\.toml$/.test(f) ||
      /(^|\/)Cargo\.lock$/.test(f) ||
      f === "rust-toolchain.toml",
  );
  return { files, hit };
}

gate("windows-cfg cross-lint — derived from test.yml", () => {
  const rel = touchesRustSurface();
  if (rel.err) return { state: "UNDETERMINED", detail: rel.err };
  if (!rel.hit) {
    return {
      state: "NOT_APPLICABLE",
      detail: `not relevant — no .rs/Cargo.{toml,lock}/rust-toolchain.toml in the ${rel.files.length}-file diff vs origin/main`,
    };
  }

  const probe = probeWindowsCrossToolchain();
  if (!probe.ok) {
    return {
      state: "SKIPPED",
      detail: `windows-gnu cross toolchain unavailable on this host: ${probe.reason} — push proceeds; CI's windows-cfg lint step is the backstop`,
    };
  }

  const d = deriveStepCommand("Clippy (windows cfg, cross-compiled)");
  if (d.err) {
    return {
      state: "UNDETERMINED",
      detail: `${d.err} — NOT falling back to a hardcoded invocation`,
    };
  }
  const shown = d.cmd.replace(/\s+/g, " ").slice(0, 120);
  const r = tryRun("bash", ["-c", d.cmd], d.env);
  if (r.ok) return { state: "GREEN", detail: `clean; ran: ${shown}` };
  if (!r.out.trim() || /command not found|ENOENT/i.test(r.out)) {
    return { state: "UNDETERMINED", detail: `could not run: ${shown}` };
  }
  const first = (r.out.split("\n").find((l) => /^error/.test(l)) || "findings")
    .trim()
    .slice(0, 140);
  return { state: "RED", detail: `${first} — ran: ${shown}` };
});

// THE GAP THIS GATE CLOSES — and why it lives HERE rather than as a new CI job.
//
// A broken intra-doc link behind `#[cfg(feature = "enterprise")]` was gated by
// nothing on the trunk where work actually lands. The two CI lints that exist
// are both `branches: [main]` and path-filtered to `**/*.rs`:
//   test.yml            `docs:`                -> community feature set only
//   test-enterprise.yml `rust-test-enterprise:` -> the enterprise form, a STEP
//                       in a job that is not a required context
// `dev` is CI-free BY CONSTRUCTION (see this file's header), so neither runs on
// the branch every landing goes to. A broken link therefore accumulates
// invisibly on `dev` and is first seen when `dev` is promoted to `main` — the
// shape that let ~30 sites pile up.
//
// Placing the gate here rather than in `.github/workflows/` is deliberate and
// is what makes it self-funding: it adds ZERO PR-reachable job instances, so
// `ci-job-budget.md` MUST-1 (which governs jobs added to a `pull_request`
// workflow) is not merely satisfied — it is not reached. No offsetting job has
// to be relevance-gated, no capacity is added to the org-shared pool, and no
// ruleset change is needed (unlike making a new job a required context).
//
// Both feature sets are checked because they are two different doc graphs: the
// community build never compiles the Phase-2b / kailash-trust seam, so a link
// that resolves in one can dangle in the other.
gate("docs — derived from test.yml + test-enterprise.yml", () => {
  const rel = touchesRustSurface();
  if (rel.err) return { state: "UNDETERMINED", detail: rel.err };
  if (!rel.hit) {
    return {
      state: "NOT_APPLICABLE",
      detail: `not relevant — no .rs/Cargo.{toml,lock}/rust-toolchain.toml in the ${rel.files.length}-file diff vs origin/main`,
    };
  }

  const targets = [
    {
      label: "community",
      jobKey: "docs",
      workflow: ".github/workflows/test.yml",
      step: "Build workspace docs (fails on any broken intra-doc link)",
    },
    {
      label: "enterprise",
      jobKey: "rust-test-enterprise",
      workflow: ".github/workflows/test-enterprise.yml",
      step: "Docs (broken-link lint, enterprise feature set)",
    },
  ];

  const ran = [];
  for (const t of targets) {
    const d = deriveStepCommand(t.step, t.jobKey, t.workflow);
    if (d.err) {
      return {
        state: "UNDETERMINED",
        detail: `${t.label}: ${d.err} — NOT falling back to a hardcoded invocation`,
      };
    }
    // The derived command is echoed in the detail on every path, RED included:
    // it is the thing under test, and a reader who cannot see which command
    // produced a finding cannot tell a real broken link from a bad derivation.
    const shown = `${t.label}: ${d.cmd.replace(/\s+/g, " ").slice(0, 100)}`;
    const r = tryRun("bash", ["-c", d.cmd], d.env);
    if (r.ok) {
      ran.push(shown);
      continue;
    }
    // RUSTDOCFLAGS is what makes the lint DENY rather than warn. Without it the
    // command is green on a tree that fails CI, so an empty/absent value is a
    // cannot-measure, never a pass.
    if (
      !d.env ||
      !d.env.RUSTDOCFLAGS ||
      !d.env.RUSTDOCFLAGS.includes("broken_intra_doc_links")
    ) {
      return {
        state: "UNDETERMINED",
        detail: `${t.label}: derived env carries no broken_intra_doc_links deny flag — the lint would warn, not fail; NOT scoring it`,
      };
    }
    if (!r.out.trim() || /command not found|ENOENT/i.test(r.out)) {
      return { state: "UNDETERMINED", detail: `could not run ${shown}` };
    }
    // A dependency that could not be FETCHED is "I could not check", not a doc
    // finding. The enterprise graph resolves one dependency from a PRIVATE git
    // remote, which a host without FOUNDATION_PAT cannot fetch — reporting that
    // as RED would refuse every push on such a host and teach the operator to
    // override the gate (instrument-discipline.md MUST-1).
    //
    // KEEP THIS GENERIC. Name the private remote here and leak-check-3 in
    // scripts/extract-community-edition.sh fails the community publish: that
    // check scans the PUBLISHED tree for the remote's repo name and a family of
    // other private-access markers, and this file ships (scripts/ci dev tooling
    // is not in the strip list). A comment is enough to block the release —
    // which is exactly how this comment came to need rewriting.
    if (
      /could not (read|fetch|find) |failed to (load|fetch|get) |network failure|Authentication failed|could not resolve/i.test(
        r.out,
      )
    ) {
      return {
        state: "SKIPPED",
        detail: `${t.label}: dependency graph unavailable on this host — CI's doc lint on the dev->main promotion PR is the backstop`,
      };
    }
    const first = (
      r.out.split("\n").find((l) => /^error/.test(l)) || "findings"
    )
      .trim()
      .slice(0, 140);
    return { state: "RED", detail: `${first} — ran: ${shown}` };
  }

  return { state: "GREEN", detail: `clean; ran: ${ran.join(" | ")}` };
});

// NOT a plain delegation to check-worktree-drift.sh, and the difference is a
// defect this file shipped with for one commit.
//
// That gate answers "does work exist only on this disk", and counts UNPUSHED
// COMMITS ON THIS BRANCH as drift. Correct for its own purpose — and fatal
// here, because a pre-push check runs at exactly the moment that condition is
// true by construction. Delegating wholesale made this preflight structurally
// incapable of ever going green, i.e. a gate that always refuses, which is
// worth precisely as much as one that always passes.
//
// What genuinely disqualifies a push is work that the push will NOT carry:
//   - uncommitted or untracked files in this tree (they stay behind)
//   - another worktree holding local-only work (this push does not ship it)
// Unpushed commits on the branch being pushed are the PAYLOAD, not drift.
gate("tree clean (push carries everything)", () => {
  const st = tryRun("git", ["status", "--porcelain"]);
  if (!st.ok) return { state: "UNDETERMINED", detail: "git status failed" };
  const dirty = st.out.split("\n").filter(Boolean);
  if (dirty.length) {
    return {
      state: "RED",
      detail: `${dirty.length} uncommitted/untracked path(s) the push will leave behind`,
    };
  }
  // OTHER WORKTREES — and here "dirty" alone is NOT the question. An earlier
  // version of this gate refused any push while ANY sibling worktree was dirty,
  // and it fired on a live parallel wave: a peer agent was mid-task in its own
  // worktree, on its own branch, which it would push itself. That is worktree
  // isolation working exactly as designed, reported as drift.
  //
  // The gate's stated question is "does this push leave work behind?", and a
  // sibling on a DIFFERENT branch is not behind — it is beside, and it lands on
  // its own push. Conflating "this push does not ship it" with "nothing will"
  // is the same "structurally cannot go green in the context it runs" shape this
  // file has now shipped twice, so the branch comparison is the discriminator:
  //   different branch          -> not this push's problem      -> excused
  //   same branch as this push  -> genuinely stranded           -> RED
  //   detached HEAD + dirty     -> no branch will carry it      -> RED
  //   branch undeterminable     -> UNDETERMINED, never excused
  const wt = tryRun("git", ["worktree", "list", "--porcelain"]);
  if (!wt.ok)
    return { state: "UNDETERMINED", detail: "could not enumerate worktrees" };
  const entries = [];
  let cur = null;
  for (const line of wt.out.split("\n")) {
    if (line.startsWith("worktree ")) {
      cur = {
        path: line.slice("worktree ".length),
        branch: null,
        detached: false,
      };
      entries.push(cur);
    } else if (!cur) {
      continue;
    } else if (line.startsWith("branch ")) {
      cur.branch = line.slice("branch ".length).replace(/^refs\/heads\//, "");
    } else if (line.trim() === "detached") {
      cur.detached = true;
    }
  }
  const here = ROOT;
  const others = entries.filter((e) => e.path !== here);

  // Read this tree's branch from git directly rather than from the list above:
  // `git worktree list` reports resolved paths, so on macOS (/tmp -> /private/tmp)
  // the ROOT entry can fail to match and the branch would come back null.
  const br = tryRun("git", ["symbolic-ref", "--quiet", "--short", "HEAD"]);
  const pushBranch = br.ok && br.out.trim() ? br.out.trim() : null;

  const stranded = [];
  let excused = 0;
  for (const e of others) {
    let o;
    try {
      o = sh("git", ["-C", e.path, "status", "--porcelain"], ROOT);
    } catch {
      return {
        state: "UNDETERMINED",
        detail: `could not read worktree ${e.path}`,
      };
    }
    if (!o.trim()) continue;
    if (e.detached || !e.branch) {
      stranded.push(`${e.path} (detached HEAD, uncommitted work)`);
      continue;
    }
    if (pushBranch === null) {
      return {
        state: "UNDETERMINED",
        detail: `${e.path} is dirty on ${e.branch}, but this tree is on a detached HEAD so the two branches cannot be compared`,
      };
    }
    if (e.branch === pushBranch) {
      stranded.push(`${e.path} (same branch '${e.branch}')`);
    } else {
      excused += 1;
    }
  }
  if (stranded.length) {
    return {
      state: "RED",
      detail: `work this push would strand: ${stranded.join(", ")}`,
    };
  }
  return {
    state: "GREEN",
    detail: `clean; ${others.length} other worktree(s), ${excused} dirty on their own branch (they land on their own push)`,
  };
});

// THE TRAP THIS EXISTS FOR, and it is not hypothetical: a branch copied a
// workflow file without renaming it, merged with ZERO conflicts because it
// rewrote the whole file, and silently deleted a CI job. `git merge-tree`
// cleanliness answers "do the texts conflict", NEVER "does the result still
// work". So compare the JOB SET, not the file list — a whole-file rewrite keeps
// the filename and loses the job, and a file-level diff shows nothing wrong.
gate("workflow job-set vs origin/main", () => {
  const jobsAt = (ref) => {
    const files = tryRun("git", [
      "ls-tree",
      "--name-only",
      ref,
      "--",
      ".github/workflows/",
    ]);
    if (!files.ok) return null;
    const set = [];
    for (const f of files.out.split("\n").filter(Boolean)) {
      const body = tryRun("git", ["show", `${ref}:${f}`]);
      if (!body.ok) return null;
      let inJobs = false;
      for (const line of body.out.split("\n")) {
        if (/^jobs:\s*$/.test(line)) {
          inJobs = true;
          continue;
        }
        if (inJobs && /^\S/.test(line)) inJobs = false;
        const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
        if (inJobs && m) set.push(`${f}::${m[1]}`);
      }
    }
    return set;
  };
  const base = jobsAt("origin/main");
  const head = jobsAt("HEAD");
  if (!base || !head)
    return { state: "UNDETERMINED", detail: "could not read both job sets" };
  const lost = base.filter((j) => !head.includes(j));
  return lost.length
    ? {
        state: "RED",
        detail: `present on main and GONE here: ${lost.join(", ")}`,
      }
    : { state: "GREEN", detail: `${head.length} jobs, none lost` };
});

// THE GAP THIS GATE CLOSES. `scripts/tests/*.test.sh` is a large, already
// self-testing gate set — and on `dev` NOTHING RAN IT. CI does, via test.yml's
// `shell-gate-selftest` job (its "Run shell gate self-tests" step globs the
// same directory), but that job is `branches: [main]`, and `dev` is CI-free by
// construction (this file's header). So every one of those tests has been
// green-by-absence on the branch every landing goes to, and a defect they exist
// to catch surfaces only when `dev` is promoted.
//
// That is not hypothetical, and it is not old: executing this set by hand on
// 2026-09-20 found `scripts/tests/auto-format-hook.test.sh` — written the same
// day — failing against a live defect in the formatter hook (it repadded every
// markdown table, because `prettier` has no table option: 29 options, zero
// matching /table/i). The test existed, was correct, and had never been run on
// `dev`. A gate whose subject is never executed is not a gate; it is a file.
//
// WHY HERE AND NOT IN .github/workflows/. Identical reasoning to the docs gate
// above, and to 1f8859d3 which added it: this adds ZERO PR-reachable job
// instances, so `ci-job-budget.md` MUST-1 (which governs jobs added to a
// `pull_request` workflow) is not merely satisfied — it is NOT REACHED. No
// offsetting job has to be relevance-gated, no capacity is added to the
// org-shared pool, no ruleset change is needed. The audit is unchanged.
//
// THE TEST LIST IS GLOB-ED, never hand-written. A hand-list goes stale in
// silence — the exact failure `durable-instruments.md` MUST-1 exists for — and
// CI's own step globs for the same reason (its "a self-test added by another
// branch enrols itself" comment). A test file added by a concurrent branch is
// picked up by both, with no edit here and none there.
//
// WHY EVERY TEST RUNS EVEN THOUGH SOME ARE SLOW. The set is time-boxed, not
// truncated: the whole set runs, the wall time is measured, and the slowest
// test is NAMED rather than dropped. Silently running a subset would reproduce
// this file's original defect one level down — a green that vouches for work
// that never ran.
//
// PER-TEST CEILING, derived from two named outcomes rather than chosen
// (`tooling-self-verification.md` Rule 3 — a constant is correct only if it
// separates the outcomes it exists to separate, with a margin on each). Both
// numbers are MEASURED, 2026-09-20, on this host, with a parallel agent wave
// already loading it (`doc-property-claims.md` MUST-2: a measured value is a
// typical, and it is the TYPICAL side that is measured here):
//   - a HEALTHY test: `citation-resolution.test.sh` is the worst at 322s; then
//     `merge-added-files` 116s, `dev-preflight` 114s,
//     `enterprise-release-license-gate` 81s, `check-worktree-drift` 73s.
//   - a WEDGED test: unbounded. The realistic cause is a blocked read — stdin
//     (which stdio `ignore` below already removes) or a lock. Without a
//     ceiling the preflight hangs and the push blocks with NO verdict at all.
//
// 900s sits 2.8x above the worst healthy observation and is finite where a
// wedge is not, so the two outcomes are distinguishable with a wide margin on
// the side that matters: too LOW here kills a passing test and reports a false
// "could not measure", which blocks a push the operator cannot unblock by
// fixing anything. An earlier draft of this constant was 240s, derived from an
// incomplete sample taken two tests in — it would have killed
// `citation-resolution` mid-run. That is the mis-sized-constant failure this
// repo has shipped three times under passing probes; the sample, not the
// reasoning, was the defect.
//
// A test hitting the ceiling is UNDETERMINED, never RED: "it did not finish"
// and "it found something" are different claims (this file's header), and only
// the first is established by a kill.
const SELFTEST_CEILING_MS = 900_000;

// Runs the SAME shellcheck pass CI's "Shell gate self-tests" job runs, because
// that job has TWO steps and this file only ever mirrored one of them. Measured
// 2026-09-24: `dev` reported all 8 gates GREEN while the promotion PR's shell
// gate was RED on 11 shellcheck findings — the self-test set passed and the lint
// was never run here at all. A preflight that mirrors half a job reports on half
// a job, and the half it omits is the half that goes red (instrument-discipline
// MUST-1: name the falsifying result, and this gate could not produce one).
//
// EVERYTHING IS DERIVED FROM test.yml, nothing restated: the pinned version and
// the file array are read out of the workflow and the array is executed by bash,
// so the glob expands with CI's exact semantics. A restated copy would drift the
// moment someone adds a directory to CI's list, and drift in a gate that reads
// green is worse than no gate.
gate("shellcheck — derived from test.yml", () => {
  const wf = join(ROOT, ".github", "workflows", "test.yml");
  let yml;
  try {
    yml = readFileSync(wf, "utf8");
  } catch (e) {
    return {
      state: "UNDETERMINED",
      detail: `cannot read ${wf} (${e.code || e.message}) — the file list and version pin are derived from it, so this is a cannot-measure, never a pass`,
    };
  }

  const pin = yml.match(/SHELLCHECK_VERSION:\s*"([0-9][0-9.]*)"/);
  if (!pin) {
    return {
      state: "UNDETERMINED",
      detail:
        "no SHELLCHECK_VERSION pin found in test.yml — without it a local green cannot be claimed to predict CI's",
    };
  }

  // The `files=(...)` array, taken verbatim so bash expands it exactly as the
  // workflow does. Terminated by the first line that is only a closing paren.
  const lines = yml.split("\n");
  const start = lines.findIndex((l) => l.includes("files=("));
  if (start === -1) {
    return {
      state: "UNDETERMINED",
      detail:
        "no `files=(` array found in test.yml's shellcheck step — cannot derive the file set",
    };
  }
  // The array closes on a CONTENT line ("scripts/tests/*.test.sh)"), not on a
  // bare ")" — continuation lines end in a backslash, the last one does not.
  let end = -1;
  for (let i = start; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t.endsWith("\\") && t.endsWith(")")) {
      end = i;
      break;
    }
  }
  if (end === -1) {
    return {
      state: "UNDETERMINED",
      detail:
        "test.yml's `files=(` array is unterminated — cannot derive the file set",
    };
  }
  const arrayText = lines.slice(start, end + 1).join("\n");

  const have = tryRun("shellcheck", ["--version"]);
  if (!have.ok) {
    return {
      state: "SKIPPED",
      detail:
        "no `shellcheck` on PATH — CI's 'Shell gate self-tests' job is the backstop; install shellcheck to close this gap before pushing shell changes",
    };
  }
  const localVer = (have.out.match(/version:\s*([0-9][0-9.]*)/) || [])[1];
  if (localVer !== pin[1]) {
    // NOT a pass and NOT a failure: a different shellcheck emits a different
    // finding set (the runner's uncontrolled build emitted SC2317 false
    // positives — an internal journal entry), so neither a local green nor a local red
    // would tell you anything about CI's verdict.
    return {
      state: "SKIPPED",
      detail: `shellcheck ${localVer || "unknown"} locally vs ${pin[1]} pinned in test.yml — a different version reports a different finding set, so this run could not predict CI either way`,
    };
  }

  const script = `set -uo pipefail\nshopt -s nullglob\n${arrayText}\nif [ "\${#files[@]}" -lt 2 ]; then echo "FATAL: the derived glob matched \${#files[@]} file(s)" >&2; exit 64; fi\nprintf 'shellchecking %d file(s)\\n' "\${#files[@]}"\nshellcheck "\${files[@]}"\n`;
  const res = tryRun("bash", ["-c", script]);
  if (res.out.includes("FATAL: the derived glob matched")) {
    return {
      state: "UNDETERMINED",
      detail:
        "the file array derived from test.yml expanded to fewer than 2 files — a linter that lints nothing is not evidence",
    };
  }
  if (res.ok) {
    const n = (res.out.match(/shellchecking (\d+) file/) || [])[1] || "?";
    return {
      state: "GREEN",
      detail: `clean; ${n} file(s) at shellcheck ${pin[1]} (glob derived from test.yml)`,
    };
  }
  const findings = res.out
    .split("\n")
    .filter((l) => /SC\d+ \(/.test(l))
    .slice(0, 12);
  return {
    state: "RED",
    detail: `shellcheck reported findings (CI's job exits non-zero on ANY level, info included):\n    ${findings.join("\n    ")}`,
  };
});

gate("shell-gate self-tests (globbed from scripts/tests/)", () => {
  // RECURSION GUARD, and it is load-bearing rather than defensive decoration:
  // this gate spawns `scripts/tests/*.test.sh`, and one of them
  // (`dev-preflight.test.sh`) INVOKES THIS VERY FILE as its subject. It does so
  // through DEV_PREFLIGHT_ONLY today, so it selects a single other gate and
  // cannot re-enter this one — but that is a property of one test's CURRENT
  // implementation, not of the set. A future test that ran the preflight bare
  // would re-run the set, which would run that test, without bound. The flag is
  // set only in the environment of the spawned tests, so it cannot fire on a
  // real invocation.
  if (process.env.DEV_PREFLIGHT_IN_SELFTEST) {
    return {
      state: "UNDETERMINED",
      detail:
        "refusing to re-enter: a self-test invoked this preflight without DEV_PREFLIGHT_ONLY, and unguarded that recursion has no bound",
    };
  }

  // SKIPPED, not GREEN: a host with no `bash` cannot run the set at all, which
  // is "could not check" and MUST be named loudly — never folded into a pass
  // (header comment, "SKIPPED ... every reader of the receipt MUST surface it
  // by name").
  //
  // TEST SEAM, mirroring DEV_PREFLIGHT_FORCE_NO_WINGNU above for the same
  // reason: whether THIS host has bash is not a fact the self-test may depend
  // on (it always does here, and a host that lacks it could never run the
  // self-test either). Unset in every real invocation. The ceiling is
  // similarly injectable so the kill path can be exercised in ~2s rather than
  // the real 240s.
  const bash = process.env.DEV_PREFLIGHT_FORCE_NO_BASH
    ? { ok: false, out: "" }
    : tryRun("which", ["bash"]);
  if (!bash.ok || !bash.out.trim()) {
    return {
      state: "SKIPPED",
      detail:
        "no `bash` on PATH — the self-test set could not run on this host; CI's 'Shell gate self-tests' job on main is the backstop",
    };
  }
  const ceilingMs = process.env.DEV_PREFLIGHT_SELFTEST_CEILING_MS
    ? Number(process.env.DEV_PREFLIGHT_SELFTEST_CEILING_MS)
    : SELFTEST_CEILING_MS;

  const dir = join(ROOT, "scripts", "tests");
  let names;
  try {
    names = readdirSync(dir)
      .filter((f) => f.endsWith(".test.sh"))
      .sort();
  } catch (e) {
    // An unreadable/absent directory is a glob that matched NOTHING, and an
    // empty result set is UNDETERMINED — never a pass. CI's own step fails
    // closed on exactly this condition ("FATAL: no self-tests found under
    // scripts/tests/"), so the strict direction here is the one already
    // established upstream of this file.
    return {
      state: "UNDETERMINED",
      detail: `cannot enumerate ${dir} (${e.code || e.message}) — 0 tests found is a cannot-measure, never a pass`,
    };
  }
  if (!names.length) {
    return {
      state: "UNDETERMINED",
      detail:
        "glob scripts/tests/*.test.sh matched 0 files — a self-test runner that runs nothing is not evidence (CI's shell-gate-selftest job treats this as FATAL, not green)",
    };
  }

  const results = [];
  // Exit 2 is UNDETERMINED, not a failure (durable-instruments.md MUST-2).
  // Which tests may be UNDETERMINED is decided by ONE executable,
  // scripts/ci/undetermined-allowlist.py, which the CI step also runs — NOT
  // re-implemented here. A first version parsed the JSON in both places and the
  // copies disagreed on the day boundary (local vs UTC), on prefix-less entries,
  // and on malformed dates (guard-reader-writer-parity.md).
  // bare test name -> the token its exemption declares
  let undeterminedOk = new Map();
  try {
    const out = execFileSync(
      "python3",
      ["scripts/ci/undetermined-allowlist.py"],
      {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    for (const line of out.split("\n")) {
      const [kind, test, token] = line.split("\t");
      // Only ALLOW grants anything, and only for a path the helper validated
      // as scripts/tests/<safe-name>.test.sh. Keyed by bare file name because
      // that is what `names` holds (readdirSync of scripts/tests).
      if (
        kind === "ALLOW" &&
        test &&
        token &&
        test.startsWith("scripts/tests/")
      ) {
        undeterminedOk.set(test.slice("scripts/tests/".length), token);
      }
    }
  } catch {
    // Helper missing, python3 missing, or declaration unreadable (exit 2) ->
    // allow NOTHING. Fail closed: an unreadable policy must never widen.
    undeterminedOk = new Map();
  }
  const undetermined = [];
  for (const n of names) {
    const p = join(dir, n);
    // A file the glob enumerated but that is not on disk is a MISSING TEST
    // FILE — SKIPPED and named, never silently dropped from the set (a dropped
    // test reads as a pass, and the count would still look complete).
    if (!existsSync(p)) {
      return {
        state: "SKIPPED",
        detail: `${n} is not readable — could not check it; the remaining ${names.length - 1} ran, but a set that silently drops a member is not the set CI runs`,
      };
    }
    const t0 = Date.now();
    let ok = true;
    let out = "";
    let rc = 0;
    try {
      execFileSync("bash", [p], {
        cwd: ROOT,
        encoding: "utf8",
        timeout: ceilingMs,
        // stdin is /dev/null, not inherited: a test that reads stdin is the
        // most likely way for this loop to hang, and the ceiling below is the
        // backstop, not the first line of defense.
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, DEV_PREFLIGHT_IN_SELFTEST: "1" },
      });
    } catch (e) {
      ok = false;
      rc = typeof e.status === "number" ? e.status : -1;
      out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
      // A kill is "it did not finish", NOT "it found something" — see the
      // ceiling's derivation above. Named with the test and the elapsed time.
      if (e.signal || e.killed) {
        return {
          state: "UNDETERMINED",
          detail: `${n} exceeded the ${ceilingMs / 1000}s ceiling and was killed — it did not finish, which is not a finding; re-run it alone to see whether the host or the test is wedged`,
        };
      }
      // Declared UNDETERMINED: the test ran and reported that it could not
      // measure. Not a pass — it is surfaced in the detail on every path — but
      // it must not redden a gate for a dependency this host lacks.
      // Exit 2 alone is NOT "could not measure" — bash exits 2 on a syntax
      // error. The test must also print its declared token at the START of a
      // line, which a crash never does (round-3 security review).
      const tok = undeterminedOk.get(n);
      if (
        rc === 2 &&
        tok &&
        out.split("\n").some((l) => l.startsWith(`UNDETERMINED[${tok}]`))
      ) {
        undetermined.push(n);
        ok = true;
      }
    }
    results.push({ n, ok, rc, ms: Date.now() - t0, out });
  }

  const failed = results.filter((r) => !r.ok);
  const totalMs = results.reduce((a, r) => a + r.ms, 0);
  const slowest = results.reduce((a, r) => (r.ms > a.ms ? r : a), results[0]);
  // The timing is reported on EVERY path, including GREEN: it is the number
  // that decides whether this set stays bearable on every push, and a gate
  // whose cost is invisible is one nobody can make that call about.
  const timing = `ran ${results.length} self-test(s) in ${(totalMs / 1000).toFixed(1)}s; slowest ${slowest.n} at ${(slowest.ms / 1000).toFixed(1)}s`;

  const undetNote = undetermined.length
    ? ` — ${undetermined.length} UNDETERMINED (declared, did NOT run): ${undetermined.join(", ")}`
    : "";
  if (!failed.length) return { state: "GREEN", detail: timing + undetNote };

  // Name the failures AND the reason, so a reader is not sent to re-run a test
  // whose own output this run already has. First finding-shaped line only, and
  // only for the first three — the detail is a pointer, not a log.
  const why = failed
    .slice(0, 3)
    .map((f) => {
      const line = f.out
        .split("\n")
        .find((l) => /^\s*(FAIL|not ok|error)/i.test(l));
      const msg = (
        line ||
        f.out
          .split("\n")
          .filter((l) => l.trim())
          .pop() ||
        ""
      )
        .trim()
        .slice(0, 100);
      return msg ? `${f.n}: ${msg}` : f.n;
    })
    .join(" | ");
  const more = failed.length > 3 ? ` (+${failed.length - 3} more)` : "";
  // KEEP every failing test's FULL output. The detail above is a 100-character
  // pointer, and a failure that does not reproduce in isolation (an internal ticket:
  // a different test failed on each of three runs, each passing alone) cannot
  // be diagnosed from a pointer. Written to a fresh temp dir, named here.
  let logs = "";
  try {
    const dir = mkdtempSync(join(tmpdir(), "dev-preflight-selftests-"));
    for (const f of failed) {
      writeFileSync(join(dir, `${f.n}.log`), `exit ${f.rc}\n${f.out}`);
    }
    logs = ` — full output of each failing test kept in ${dir}`;
  } catch (e) {
    logs = ` — could not keep the failing output (${e.code || e.message})`;
  }
  return {
    state: "RED",
    detail: `${failed.length}/${results.length} self-test(s) failed — ${why}${more} — ${timing}${undetNote}${logs}`,
  };
});

const red = gates.filter((g) => g.state === "RED");
const und = gates.filter((g) => g.state === "UNDETERMINED");
// Two further dispositions, deliberately absent from both arrays above and
// deliberately DISTINCT from each other (see the header comment): both fold
// into the GREEN exit path, neither blocks, but they carry different claims
// and different operator-facing noise.
//   NOT_APPLICABLE — a PROVEN negative (out of scope for this push). Silent.
//   SKIPPED        — "could not check" (toolchain/environment absent). Loud:
//                    every reader of the receipt, including this file's own
//                    summary AND dev-push-guard.sh at push time, MUST name it.
const notApplicable = gates.filter((g) => g.state === "NOT_APPLICABLE");
const skipped = gates.filter((g) => g.state === "SKIPPED");
const sha = sh("git", ["rev-parse", "HEAD"], ROOT).trim();

console.log("");
// The state under test must be the state being vouched for. If HEAD moved or
// ANY file changed while the gates ran, their verdicts are about a mixture of
// states and describe no single commit — UNDETERMINED, never a receipt.
const END_FINGERPRINT = treeFingerprint();
if (treeMovedAfter && END_FINGERPRINT === START_FINGERPRINT) {
  console.log(
    `dev-preflight: UNDETERMINED — the tree changed during the run (first seen after '${treeMovedAfter}') and was later restored. No receipt written.`,
  );
  console.log(
    "  Some gates tested a different tree than the one being vouched for. Re-run on a quiet tree.",
  );
  process.exit(2);
}
if (END_FINGERPRINT !== START_FINGERPRINT) {
  const [sHead, sTree] = START_FINGERPRINT.split(":");
  const [eHead, eTree] = END_FINGERPRINT.split(":");
  console.log(
    "dev-preflight: UNDETERMINED — the tree changed while the gates were running. No receipt written.",
  );
  console.log(
    `    HEAD: ${sHead.slice(0, 8)} -> ${eHead.slice(0, 8)}${sHead === eHead ? " (unchanged)" : " (MOVED)"}`,
  );
  console.log(
    `    tree: ${sTree.slice(0, 8)} -> ${eTree.slice(0, 8)}${sTree === eTree ? " (unchanged)" : " (CHANGED)"}`,
  );
  console.log("  Re-run on a tree nobody is editing. This is NOT a pass.");
  process.exit(2);
}
// A filter that selected nothing must not read as "everything passed".
if (ONLY && selected === 0) {
  console.log(
    `dev-preflight: UNDETERMINED — DEV_PREFLIGHT_ONLY='${ONLY}' matched no gate.`,
  );
  process.exit(2);
}
if (red.length) {
  console.log(
    `dev-preflight: RED — ${red.length} gate(s) failed. No receipt written; the push guard will refuse.`,
  );
  red.forEach((g) => console.log(`    ${g.name}: ${g.detail}`));
  process.exit(1);
}
if (und.length) {
  console.log(
    `dev-preflight: UNDETERMINED — ${und.length} gate(s) could not run. No receipt written.`,
  );
  und.forEach((g) => console.log(`    ${g.name}: ${g.detail}`));
  console.log("  This is NOT a pass. Resolve the oracle and re-run.");
  process.exit(2);
}
// SKIPPED is loud by design ("could not check" — see header comment); a
// receipt carrying it must not read as silently clean.
if (skipped.length) {
  console.log(
    `dev-preflight: ${skipped.length} gate(s) SKIPPED — could not check, named in the receipt, push proceeds:`,
  );
  skipped.forEach((g) => console.log(`    ${g.name}: ${g.detail}`));
}
// NOT_APPLICABLE is a proven negative — deliberately quiet (no per-gate
// detail line), per the header comment's "no operator noise" contract.
if (notApplicable.length) {
  console.log(
    `dev-preflight: ${notApplicable.length} gate(s) NOT_APPLICABLE (out of scope for this push).`,
  );
}

// A SUBSET RUN IS NOT A RECEIPT. Writing one here would let a filtered
// invocation vouch for a commit whose other gates never ran — the push guard
// reads only the SHA and the gate states, and would honour it.
if (ONLY) {
  console.log(
    `dev-preflight: the '${ONLY}' subset passed (${selected} gate(s)). NO receipt written — a partial run is not evidence.`,
  );
  process.exit(0);
}

writeFileSync(
  RECEIPT,
  JSON.stringify({ sha, at: new Date().toISOString(), gates }, null, 2) + "\n",
);
console.log(`dev-preflight: GREEN — receipt written for ${sha.slice(0, 8)}.`);
console.log(`  ${RECEIPT}`);
// What this GREEN does NOT claim. Stated every run, not buried in a header: the
// receipt is what the push guard honours, so an over-read of it is an over-read
// of the only check `dev` has.
console.log("");
console.log(
  "  Covered here: fmt, clippy (derived from test.yml), windows-cfg cross-lint",
);
console.log(
  "  (derived from test.yml — NOT_APPLICABLE, silently, when the push doesn't touch",
);
console.log(
  "  Rust surface; SKIPPED, loudly, when this host lacks the windows-gnu cross",
);
console.log(
  "  toolchain — named above if so), the tree-scan gates, worktree spill, workflow",
);
console.log(
  "  job-set, and the scripts/tests/*.test.sh shell-gate self-test set (the same",
);
console.log(
  "  glob CI's 'Shell gate self-tests' job runs on main, which `dev` never reaches).",
);
console.log(
  "  NOT covered: the six sink feature combinations, the native-harness",
);
console.log(
  "  lint target, the windows-cfg lint when SKIPPED above, and the TEST RUN itself",
);
console.log(
  "  (incl. Windows RUNTIME behaviour — the windows-cfg gate is lint-only, per",
);
console.log(
  "  test-windows.yml's own an internal ticket note). Those first run at the dev -> main",
);
console.log("  promotion gate.");
process.exit(0);
