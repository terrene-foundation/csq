#!/usr/bin/env node
// dev-preflight — the ONLY check that exists before a push to `dev`.
// Quick local checks run first. Once they pass, neutral Linux Trestle heavy
// gates and shell self-test shards run concurrently; each retains its verdict.
//
// OUTPUT POLICY — what may reach stdout, stderr or the receipt. Three source
// classes, and only these:
//   1. Fixed vocabulary written in this file and preflight-shell-tests.mjs.
//   2. Values that pass an ALLOWLIST (gate names we registered, our own evidence
//      paths with $HOME -> ~, sha256 digests, footer fields, and — for libtest
//      final-list entries — ONLY atoms that are trusted on their own: the bare
//      `#[…test…]` fn identifier found in this repo's tracked source (module
//      path withheld) or the exact tracked doc-test file path plus line digits
//      (item withheld); a forged entry that is not a test in the tree never
//      prints, which closes the forged-trailer + `running N tests` residual R1
//      recorded. rustc codes; lint names only from a CLOSED list
//      (LINT_NAMES, in this file) in note context; shellcheck path:line:col
//      SC####, script names, git-reported paths/branches, identifier-only error
//      causes, the exact literal throw messages of preflight-runtime.mjs). A
//      value that fails is replaced by a fixed phrase or COUNTED — never printed
//      partially or redacted. This covers ALL test, tool and error text.
//   3. A SEPARATE, TRUSTED-SOURCE class that IS printed verbatim: text from this
//      repo's own workflow YAML — the derived command (`ran: …`, sliced), the
//      derivation errors (`d.err`, which quote a step/env line), and job names
//      (`lost`). It is repository content under review like any source file, not
//      output of anything the preflight runs. It is NOT allowlisted; it is
//      printed because its source is trusted.
// Retained evidence FILES (0600 in a 0700 mkdtemp dir) keep the full output.
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
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { randomUUID, createHash } from "node:crypto";
import { parseFooter, measuredScript, signoffScript, signoffVerdict, retainOutput, lockedScript, cachedScript, runGateWorkers, aggregateExit, createFleetScope, acquireFleetSlotSync, COMMUNITY_EXTRACTION_COMMAND } from "./preflight-runtime.mjs";
import { runShellGate, homeTilde, errIdent, isOwnEvidencePath, shownEvidencePath, isRelPath, SHA256_RE } from "./preflight-shell-tests.mjs";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  lstatSync,
  openSync,
  fstatSync,
  readSync,
  closeSync,
  constants as fsConstants,
  realpathSync,
  writeFileSync,
  writeSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(
    "usage: node scripts/ci/dev-preflight.mjs\n" +
      "  Runs csq's local push gate and writes .csq-dev-preflight.json on GREEN.\n" +
      "  Quick run-ci-gates, shellcheck and job-set checks run locally first; fmt is offloaded.\n" +
      "  After they pass, heavy cargo gates and shell self-test shards run\n" +
      "  concurrently through unpinned `trestle run --os linux --`.\n" +
      "  CSQ_PREFLIGHT_LOCAL=1 applies only to explicit fixture subsets;\n" +
      "  fixture subsets never write a canonical receipt.\n" +
      "  Exit: 0 GREEN, 1 RED, 2 UNDETERMINED.",
  );
  process.exit(0);
}

let activeGateCapture = null;
function sh(cmd, args, cwd, extraEnv) {
  const started = performance.now();
  const result = spawnSync(cmd, args, {
    encoding: "utf8", cwd,
    env: extraEnv ? { ...process.env, ...extraEnv } : process.env,
    stdio: ["ignore", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024,
  });
  result.elapsed_ms = performance.now() - started;
  if (activeGateCapture) {
    try { activeGateCapture.outputs.push(retainOutput(result, cmd)); }
    catch { activeGateCapture.failed = true; }
  }
  if (result.error || result.signal || result.status !== 0) {
    const error = result.error || new Error(`command failed with status ${result.status}`);
    error.stdout = result.stdout; error.stderr = result.stderr;
    error.status = result.status; error.signal = result.signal;
    throw error;
  }
  return result.stdout;
}

const ROOT = sh("git", ["rev-parse", "--show-toplevel"], process.cwd()).trim();
// Print-only requests need workflow bytes and argv construction. Route them
// before fleet-scope creation and tree fingerprinting, whose Git operations
// can block a read-only derivation behind unrelated checkout work.
const printStep = process.env.DEV_PREFLIGHT_SHOW_WRAPPED || process.env.DEV_PREFLIGHT_SHOW_DERIVED;
if (printStep) {
  const d = deriveStepCommand(printStep);
  if (d.err) {
    console.error(d.err);
    process.exit(2);
  }
  console.log(process.env.DEV_PREFLIGHT_SHOW_WRAPPED
    ? JSON.stringify(trestleArgv(d.cmd, d.env, { os: "linux" }))
    : d.cmd);
  process.exit(0);
}
// Preserve the print-only exception, then refuse recursive full preflight
// before creating a fleet scope or writing a fingerprint index.
const ONLY = process.env.DEV_PREFLIGHT_ONLY || "";
if (process.env.DEV_PREFLIGHT_IN_SELFTEST && !ONLY) { console.error("UNDETERMINED: refusing to re-enter preflight from a self-test without a subset"); process.exit(2); }
const RECEIPT = join(ROOT, ".csq-dev-preflight.json");
// A canonical parent creates its own scope; native workers inherit that scope.
const FLEET_ENV = process.env.CSQ_PREFLIGHT_WORKER_TOKEN ? process.env : { ...process.env, ...createFleetScope() };

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


// ── HEAVY STEPS RUN THROUGH `trestle run --`, NEVER PINNED ──────────────────
// The coordinator (this process) is local because it writes the tree-local
// receipt. Every heavy cargo step is NOT: launched as `trestle run -- <cmd>`
// with no --host and no --local (offload-discipline.md MUST-1), so the arbiter
// places it from live occupancy. Every heavy step adds `--os linux`, a
// platform REQUIREMENT; the windows-gnu mingw toolchain also lives there.
// `cargo fmt --check` also uses neutral Trestle and the shared six-job cap.
// Formatter placement is portable; lint/docs retain their Linux requirement.
//
// Exit reading (CLAUDE.md § Offloading): the footer is `exit=N command` (the
// command's OWN status) or `exit=N engine:<kind>` / `arbiter:<kind>`
// (the offload failed); only a framed terminal stderr line is accepted.
//   114 UNKNOWN            -> re-run once
//   116 nothing ran        -> retry once with --wait-s 600
//   2 (engine footer)      -> remote contention; retry once
//   anything else, or no parseable footer -> UNDETERMINED, never a pass
// No trestle on PATH is a FAILURE (UNDETERMINED), never a quiet local cargo run
// (zero-tolerance.md Rule 3). Fixture subsets may use CSQ_PREFLIGHT_LOCAL=1.
const HEAVY_LOCAL = process.env.CSQ_PREFLIGHT_LOCAL === "1" && !!process.env.DEV_PREFLIGHT_ONLY && process.env.CSQ_PREFLIGHT_CANONICAL_WORKER !== "1";
const HEAVY_RAN = HEAVY_LOCAL ? "local" : "trestle";
if (HEAVY_LOCAL) {
  console.log(
    "dev-preflight: *** CSQ_PREFLIGHT_LOCAL=1 — heavy steps (clippy, windows-cfg, docs) run LOCALLY on this machine, NOT through trestle. No canonical receipt is written for this fixture subset. ***\n",
  );
}

function onPath(bin) {
  for (const d of (process.env.PATH || "").split(delimiter)) {
    if (!d) continue;
    try {
      if (statSync(join(d, bin)).isFile()) return true;
    } catch {
      // not in this PATH entry
    }
  }
  return false;
}

function shq(v) {
  return `'${String(v).replace(/'/g, `'\\''`)}'`;
}

// bash -c script with the step's env exported first: trestle ships argv, not
// our process env, so the env a derived step needs must travel inside it.
function heavyScript(cmd, env, opts = {}) {
  const exports = Object.entries(env || {})
    .map(([k, v]) => `export ${k}=${shq(v)};`)
    .join(" ");
  const body = signoffScript(cmd, opts.leg || { token: randomUUID(), fixture: !!process.env.DEV_PREFLIGHT_ONLY && process.env.CSQ_PREFLIGHT_CANONICAL_WORKER !== "1" });
  return measuredScript(cachedScript(`${exports}\n${body}`));
}

// The argv handed to trestle. Pure, so the self-test can assert its shape.
function trestleArgv(cmd, env, { os, waitS, leg } = {}) {
  const a = ["run"];
  if (os) a.push("--os", os);
  if (waitS) a.push("--wait-s", String(waitS));
  a.push("--", "bash", "-c", heavyScript(cmd, env, { leg }));
  return a;
}

// A caught error is printed by an identifier-only cause, EXCEPT the exact fixed
// messages preflight-runtime.mjs throws (fixed vocabulary, exact-match only),
// which name a cause the operator can act on. Every one of them is a literal
// `throw new Error('…')` in that file; no message is matched by pattern.
const KNOWN_OWN_THROWS = new Set([
  "caller fleet admission deadline exhausted",
  "caller fleet identity changed during bounded read",
  "caller fleet identity mismatch",
  "caller fleet lease identity changed",
  "canonical worker missing caller fleet admission",
  "invalid caller fleet admission",
  "invalid fleet admission deadline",
  "invalid leg marker token",
  "unsafe caller fleet directory",
  "unsafe caller fleet identity",
  "unsupported command grammar: cannot prove direct locked Cargo argv",
]);
function ownThrowCause(e) {
  return typeof e?.message === "string" && KNOWN_OWN_THROWS.has(e.message) ? e.message : errIdent(e);
}
const heavyEvidence = [];
// Returns { ok, out } like tryRun, plus `und` (a string) when the step could
// not be measured. A gate seeing `und` MUST return UNDETERMINED.
function runHeavy(cmd, env, opts = {}) {
  if (opts.leg && HEAVY_LOCAL) return { und: "sign-off legs require trestle footer evidence; local fixture bypass is unavailable" };
  if (HEAVY_LOCAL) return tryRun("bash", ["-c", lockedScript(cmd, { fixture: !!process.env.DEV_PREFLIGHT_ONLY && process.env.CSQ_PREFLIGHT_CANONICAL_WORKER !== "1" })], env);
  opts = { ...opts, leg: { token: randomUUID(), fixture: !!process.env.DEV_PREFLIGHT_ONLY && process.env.CSQ_PREFLIGHT_CANONICAL_WORKER !== "1", ...opts.leg } };
  if (!onPath("trestle")) {
    return {
      ok: false,
      out: "",
      und: "trestle is not on PATH — heavy steps are NOT run locally. Install the launcher: node <trestle-checkout>/bin/trestle-install-launcher.mjs (or set CSQ_PREFLIGHT_LOCAL=1 on a machine with no trestle)",
    };
  }
  let waitS;
  let lastWhy = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    let release, r;
    try {
      release = acquireFleetSlotSync({ env: FLEET_ENV });
      const attemptStarted = performance.now();
      r = spawnSync("trestle", trestleArgv(cmd, env, { ...opts, waitS }), {
        encoding: "utf8", cwd: ROOT, env: FLEET_ENV, stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 512 * 1024 * 1024,
        timeout: 30 * 60 * 1000, killSignal: "SIGKILL",
      });
      r.elapsed_ms = performance.now() - attemptStarted;
    } catch (e) { return { ok: false, out: "", und: `caller fleet admission failed (${ownThrowCause(e)})` }; }
    finally { try { release?.(); } catch { r = { ...r, error: { code: "FLEET_LEASE_RELEASE" } }; } }
    const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
    const f = parseFooter(r);
    let evidence;
    try {
      evidence = retainOutput(r, "trestle");
      evidence.cache = { available: out.includes("CSQ_CACHE_BEFORE"), statistics_undetermined: out.includes("CSQ_CACHE_STATS_UNDETERMINED"),
        scope: "shared host cache counters before/after this command; concurrent processes may contribute" };
      heavyEvidence.push(evidence);
    } catch { return { ok: false, out, und: "could not retain heavy output" }; }
    if (!f) {
      return {
        ok: false,
        out,
        und: `trestle exit ${r.status} with no terminal framed stderr 'exit=N command|engine:<kind>|arbiter:<kind>' footer — unclassifiable, not scored`,
      };
    }
    if (f.kind === "command") {
      if (f.code !== r.status) {
        return { ok: false, out, und: `footer says exit=${f.code} command but trestle exited ${r.status} — inconsistent, not scored` };
      }
      const verdict = signoffVerdict(r, { token: opts.leg.token, tree: START_FINGERPRINT.split(":")[1] });
      evidence.leg = { host: verdict.host ?? null, host_provenance: verdict.host_provenance ?? [], tree: verdict.tree ?? null,
        porcelain: verdict.porcelain ?? null, rc: verdict.leg_rc ?? null, wall_ms: r.elapsed_ms };
      return { ...verdict, out, wall_ms: r.elapsed_ms };
    }
    if (attempt === 0 && [113, 104, 116].includes(f.code)) { waitS = 600; continue; }
    if (f.kind === "arbiter") return { ok: false, out, und: `offload arbiter:${f.arbiter} exit=${f.code} — NOT a command verdict; not retried` };
    // engine failure: the command's own verdict was never produced
    lastWhy = `engine:${f.engine} exit=${f.code}`;
    if (attempt === 0 && (f.code === 114 || f.code === 2)) continue;
    if (attempt === 0 && f.code === 116) {
      waitS = 600;
      continue;
    }
    return { ok: false, out, und: `offload failed (${lastWhy}) — NOT a verdict on the command; re-run` };
  }
  return { ok: false, out: "", und: `offload failed after one retry (${lastWhy})` };
}

// TEST HOOK. DEV_PREFLIGHT_ONLY=<substring> runs only the gates whose name
// contains it, so the self-test can exercise one gate against a fixture repo
// without a cargo toolchain or a workflow tree. It NEVER writes a receipt — see
// the bottom of this file. A filter matching nothing exits 2 rather than 0: a
// selector that silently selected zero gates and reported green is the same
// fail-open this whole file is built against.
let selected = 0;

const gates = [], registered = [];
let treeMovedAfter = null;
const worker = !!process.env.CSQ_PREFLIGHT_WORKER_TOKEN;
if (worker && typeof process.send !== "function") {
  console.error("UNDETERMINED: worker mode requires its parent's native IPC channel"); process.exit(2);
}
// ── RED EVIDENCE: ALLOWLIST-ONLY OUTPUT ─────────────────────────────────────
// What the RED summary prints about a failing gate's retained evidence. NOTHING
// here prints free-form text from a test, tool or error: every line is a fixed
// phrase plus values that matched a strict allowlist (our own gate names, our
// own mkdtemp artifact path, our own sha256, and test names matching the libtest
// shapes below). A candidate that fails the allowlist is never printed — not
// partially, not redacted — it is COUNTED. Redacting arbitrary text always left
// a bypass (three review rounds); an allowlist has no bypass class.
const ALL_GATE_NAMES = new Set();
const RED_TEST_NAME_LIMIT = 40;
// Printed numbers are BUCKETED, never exact: an exact count derived from test
// output is a covert channel (a token needs >=128 bits). Four buckets carry 2
// bits per printed number.
function countBucket(n) {
  return n <= 1 ? "1" : n <= 9 ? "2-9" : n <= 99 ? "10-99" : "100+";
}
// 16 MiB: the artifact is read and JSON-parsed whole, so the cap bounds the
// printer's memory well below anything that could abort the process (an OOM
// abort would turn the RED exit 1 into 134). Above it: a fixed phrase.
const RED_ARTIFACT_SCAN_BYTES = 16 * 1024 * 1024;
// Names come ONLY from libtest's harness-owned FINAL `failures:` list: the
// block between the last `failures:` header and a FINAL `test result:` trailer
// (one followed by EOF, the next binary's `running N tests`, or our own leg RC
// line). Progress lines and `---- … stdout ----` headers are never a source:
// captured test output sits between them and can carry any charset-legal line.
// A forged WHOLE trailer immediately followed by a forged `running N tests`
// line still yields a grammar-legal list, so grammar alone is not the gate:
// SOURCE MEMBERSHIP is (trustedAtom below). Repo source is trusted, test output
// is not — an entry is printed only as an ATOM trusted on its own: the bare
// `fn` identifier of a `#[…test…]` fn in a tracked `*.rs` file, or the exact
// tracked doc-test file path plus its line digits. Composite bytes (the `::`
// module path, the doc-test item) are never printed. A forged entry that is not
// a test in the tree is counted, never printed.
const RUST_SEGMENT = "[A-Za-z_][A-Za-z0-9_]{0,63}";
const UNIT_TEST_NAME_RE = new RegExp(`^${RUST_SEGMENT}(?:::${RUST_SEGMENT}){0,15}$`);
// rustdoc: `<repo-relative file> - <item> (line N)`; the item is absent for
// crate-level docs. The file path additionally passes isRelPath (no leading
// `/`, no `..` segment).
const DOCTEST_NAME_RE = new RegExp(`^([A-Za-z0-9_./-]{1,200}) - (?:${RUST_SEGMENT}(?:::${RUST_SEGMENT}){0,15} )?\\(line (\\d{1,7})\\)$`);
const TEST_RESULT_RE = /^test result: (?:ok|FAILED)\. \d{1,7} passed; (\d{1,7}) failed;/;
const RUNNING_RE = /^running \d{1,7} tests?$/;
// homeTilde / errIdent / isOwnEvidencePath / shownEvidencePath / isRelPath /
// SHA256_RE are shared with preflight-shell-tests.mjs (imported above).

// The RED detail's "first error" for clippy / windows-cfg / docs: allowlisted
// CODES only, never an excerpt of the line. Scans the first `^error` line and its
// continuation (until a blank line or the next error/warning, max 50 lines) for a
// rustc code `error[E####]` and lint names `[a-z][a-z0-9_-]{0,63}`, optionally
// `clippy::`/`rustdoc::`-prefixed, taken ONLY from rustc's lint-note contexts
// `` `-D <lint>` `` and `` `#[deny(<lint>)]` `` / `` `#[warn(<lint>)]` ``. `-D
// warnings` names the group, not the lint, and is skipped. rustc's `-D` notes
// print kebab-case; `-` is normalised to `_`. A candidate prints ONLY if it is in
// the CLOSED list LINT_NAMES (below, enumerated from the toolchain at
// authoring time); anything else is COUNTED.
// CLOSED LIST of lint names the RED "first error" detail may print (allowlist-
// only output: any other lint-shaped text is COUNTED, never printed). Names are
// underscore-normalised. GENERATED at authoring time, 2026-10-17, on a Linux
// fleet host via `trestle run --os linux`, by enumerating:
//   rustc -W help                      (rustc 1.98.1 (48a229cea 2026-09-01))
//   cargo clippy -q -- -W help          (clippy 0.1.98 (48a229ceae 2026-09-01)), in a fresh `cargo new --lib`
//   rustdoc -W help                    (rustdoc 1.98.1 (48a229cea 2026-09-01))
// taking the first column of every "Lint checks" and "Lint groups" row. A
// toolchain bump that adds a lint leaves it COUNTED (fail-safe) until this list
// is regenerated the same way. 1115 names.
const LINT_NAMES = Object.freeze(new Set([
  "aarch64_softfloat_neon", "absolute_paths_not_starting_with_crate", "ambiguous_associated_items",
  "ambiguous_derive_helpers", "ambiguous_glob_imported_traits", "ambiguous_glob_imports",
  "ambiguous_glob_reexports", "ambiguous_import_visibilities", "ambiguous_negative_literals",
  "ambiguous_panic_imports", "ambiguous_wide_pointer_comparisons", "anonymous_parameters",
  "arithmetic_overflow", "array_into_iter", "asm_sub_register", "async_fn_in_trait", "bad_asm_style",
  "bare_trait_objects", "binary_asm_labels", "bindings_with_variant_name", "boxed_slice_into_iter",
  "break_with_label_and_loop", "c_void_returns", "clashing_extern_declarations", "clippy::absolute_paths",
  "clippy::absurd_extreme_comparisons", "clippy::all", "clippy::alloc_instead_of_core",
  "clippy::allow_attributes", "clippy::allow_attributes_without_reason", "clippy::almost_complete_range",
  "clippy::almost_swapped", "clippy::approx_constant", "clippy::arbitrary_source_item_ordering",
  "clippy::arc_with_non_send_sync", "clippy::arithmetic_side_effects", "clippy::as_conversions",
  "clippy::as_pointer_underscore", "clippy::as_ptr_cast_mut", "clippy::as_underscore",
  "clippy::assert_is_empty", "clippy::assertions_on_constants", "clippy::assertions_on_result_states",
  "clippy::assign_op_pattern", "clippy::assigning_clones", "clippy::async_yields_async",
  "clippy::await_holding_invalid_type", "clippy::await_holding_lock", "clippy::await_holding_refcell_ref",
  "clippy::bad_bit_mask", "clippy::big_endian_bytes", "clippy::bind_instead_of_map",
  "clippy::blanket_clippy_restriction_lints", "clippy::block_scrutinee", "clippy::blocks_in_conditions",
  "clippy::bool_assert_comparison", "clippy::bool_comparison", "clippy::bool_to_int_with_if",
  "clippy::borrow_as_ptr", "clippy::borrow_deref_ref", "clippy::borrow_interior_mutable_const",
  "clippy::borrowed_box", "clippy::box_collection", "clippy::box_default", "clippy::boxed_local",
  "clippy::branches_sharing_code", "clippy::builtin_type_shadow", "clippy::by_ref_peekable_peek",
  "clippy::byte_char_slices", "clippy::bytes_count_to_len", "clippy::bytes_nth", "clippy::cargo",
  "clippy::cargo_common_metadata", "clippy::case_sensitive_file_extension_comparisons",
  "clippy::cast_abs_to_unsigned", "clippy::cast_enum_constructor", "clippy::cast_enum_truncation",
  "clippy::cast_lossless", "clippy::cast_nan_to_int", "clippy::cast_possible_truncation",
  "clippy::cast_possible_wrap", "clippy::cast_precision_loss", "clippy::cast_ptr_alignment",
  "clippy::cast_sign_loss", "clippy::cast_slice_different_sizes", "clippy::cast_slice_from_raw_parts",
  "clippy::cfg_not_test", "clippy::char_indices_as_byte_indices", "clippy::char_lit_as_u8",
  "clippy::chars_last_cmp", "clippy::chars_next_cmp", "clippy::checked_conversions",
  "clippy::chunks_exact_to_as_chunks", "clippy::clear_with_drain", "clippy::clone_on_copy",
  "clippy::clone_on_ref_ptr", "clippy::cloned_instead_of_copied", "clippy::cloned_ref_to_slice_refs",
  "clippy::cmp_null", "clippy::cmp_owned", "clippy::coerce_container_to_any", "clippy::cognitive_complexity",
  "clippy::collapsible_else_if", "clippy::collapsible_if", "clippy::collapsible_match",
  "clippy::collapsible_str_replace", "clippy::collection_is_never_read", "clippy::comparison_chain",
  "clippy::comparison_to_empty", "clippy::complexity", "clippy::confusing_method_to_numeric_cast",
  "clippy::const_is_empty", "clippy::copy_iterator", "clippy::correctness", "clippy::crate_in_macro_def",
  "clippy::create_dir", "clippy::crosspointer_transmute", "clippy::dbg_macro",
  "clippy::debug_assert_with_mut_call", "clippy::decimal_bitwise_operands",
  "clippy::decimal_literal_representation", "clippy::declare_interior_mutable_const",
  "clippy::default_constructed_unit_structs", "clippy::default_instead_of_iter_empty",
  "clippy::default_numeric_fallback", "clippy::default_trait_access", "clippy::default_union_representation",
  "clippy::definition_in_module_root", "clippy::deprecated_cfg_attr", "clippy::deprecated_clippy_cfg_attr",
  "clippy::deprecated_semver", "clippy::deref_addrof", "clippy::deref_by_slicing", "clippy::derivable_impls",
  "clippy::derive_ord_xor_partial_ord", "clippy::derive_partial_eq_without_eq",
  "clippy::derived_hash_with_manual_eq", "clippy::disallowed_fields", "clippy::disallowed_macros",
  "clippy::disallowed_methods", "clippy::disallowed_names", "clippy::disallowed_script_idents",
  "clippy::disallowed_types", "clippy::diverging_sub_expression", "clippy::doc_broken_link",
  "clippy::doc_comment_double_space_linebreaks", "clippy::doc_include_without_cfg",
  "clippy::doc_lazy_continuation", "clippy::doc_link_code", "clippy::doc_link_with_quotes",
  "clippy::doc_markdown", "clippy::doc_nested_refdefs", "clippy::doc_overindented_list_items",
  "clippy::doc_paragraphs_missing_punctuation", "clippy::doc_suspicious_footnotes",
  "clippy::double_comparisons", "clippy::double_ended_iterator_last", "clippy::double_must_use",
  "clippy::double_parens", "clippy::drain_collect", "clippy::drop_non_drop", "clippy::duplicate_mod",
  "clippy::duplicate_underscore_argument", "clippy::duplicated_attributes",
  "clippy::duration_suboptimal_units", "clippy::duration_subsec", "clippy::eager_transmute",
  "clippy::elidable_lifetime_names", "clippy::else_if_without_else", "clippy::empty_docs",
  "clippy::empty_drop", "clippy::empty_enum_variants_with_brackets", "clippy::empty_enums",
  "clippy::empty_line_after_doc_comments", "clippy::empty_line_after_outer_attr", "clippy::empty_loop",
  "clippy::empty_structs_with_brackets", "clippy::enum_clike_unportable_variant", "clippy::enum_glob_use",
  "clippy::enum_variant_names", "clippy::eq_op", "clippy::equatable_if_let", "clippy::erasing_op",
  "clippy::err_expect", "clippy::error_impl_error", "clippy::excessive_nesting", "clippy::excessive_precision",
  "clippy::exhaustive_enums", "clippy::exhaustive_structs", "clippy::exit", "clippy::expect_fun_call",
  "clippy::expect_used", "clippy::expl_impl_clone_on_copy", "clippy::explicit_auto_deref",
  "clippy::explicit_counter_loop", "clippy::explicit_deref_methods", "clippy::explicit_into_iter_loop",
  "clippy::explicit_iter_loop", "clippy::explicit_write", "clippy::extend_with_drain",
  "clippy::extra_unused_lifetimes", "clippy::extra_unused_type_parameters", "clippy::fallible_impl_from",
  "clippy::field_reassign_with_default", "clippy::field_scoped_visibility_modifiers",
  "clippy::filetype_is_file", "clippy::filter_map_bool_then", "clippy::filter_map_identity",
  "clippy::filter_map_next", "clippy::filter_next", "clippy::flat_map_identity", "clippy::flat_map_option",
  "clippy::float_arithmetic", "clippy::float_cmp", "clippy::float_cmp_const",
  "clippy::float_equality_without_abs", "clippy::fn_params_excessive_bools", "clippy::fn_to_numeric_cast",
  "clippy::fn_to_numeric_cast_any", "clippy::fn_to_numeric_cast_with_truncation", "clippy::for_kv_map",
  "clippy::for_unbounded_range", "clippy::forget_non_drop", "clippy::format_collect",
  "clippy::format_in_format_args", "clippy::format_push_string", "clippy::four_forward_slashes",
  "clippy::from_over_into", "clippy::from_raw_with_void_ptr", "clippy::from_str_radix_10",
  "clippy::future_not_send", "clippy::get_first", "clippy::get_last_with_len", "clippy::get_unwrap",
  "clippy::host_endian_bytes", "clippy::identity_op", "clippy::if_let_mutex", "clippy::if_not_else",
  "clippy::if_same_then_else", "clippy::if_then_some_else_none", "clippy::ifs_same_cond",
  "clippy::ignore_without_reason", "clippy::ignored_unit_patterns",
  "clippy::impl_hash_borrow_with_str_and_bytes", "clippy::impl_trait_in_params", "clippy::implicit_clone",
  "clippy::implicit_hasher", "clippy::implicit_return", "clippy::implicit_saturating_add",
  "clippy::implicit_saturating_sub", "clippy::implied_bounds_in_impls", "clippy::impossible_comparisons",
  "clippy::imprecise_flops", "clippy::incompatible_msrv", "clippy::inconsistent_digit_grouping",
  "clippy::inconsistent_struct_constructor", "clippy::index_refutable_slice", "clippy::indexing_slicing",
  "clippy::ineffective_bit_mask", "clippy::ineffective_open_options", "clippy::inefficient_to_string",
  "clippy::infallible_destructuring_match", "clippy::infallible_try_from", "clippy::infinite_iter",
  "clippy::infinite_loop", "clippy::inherent_to_string", "clippy::inherent_to_string_shadow_display",
  "clippy::init_numbered_fields", "clippy::inline_always", "clippy::inline_asm_x86_att_syntax",
  "clippy::inline_asm_x86_intel_syntax", "clippy::inline_fn_without_body", "clippy::inline_modules",
  "clippy::inline_trait_bounds", "clippy::inspect_for_each", "clippy::int_plus_one",
  "clippy::integer_division", "clippy::integer_division_remainder_used", "clippy::into_iter_on_ref",
  "clippy::into_iter_without_iter", "clippy::invalid_regex", "clippy::invalid_upcast_comparisons",
  "clippy::inverted_saturating_sub", "clippy::invisible_characters", "clippy::io_other_error",
  "clippy::ip_constant", "clippy::is_digit_ascii_radix", "clippy::items_after_statements",
  "clippy::items_after_test_module", "clippy::iter_cloned_collect", "clippy::iter_count",
  "clippy::iter_filter_is_ok", "clippy::iter_filter_is_some", "clippy::iter_kv_map", "clippy::iter_next_loop",
  "clippy::iter_next_slice", "clippy::iter_not_returning_iterator", "clippy::iter_nth",
  "clippy::iter_nth_zero", "clippy::iter_on_empty_collections", "clippy::iter_on_single_items",
  "clippy::iter_out_of_bounds", "clippy::iter_over_hash_type", "clippy::iter_overeager_cloned",
  "clippy::iter_skip_next", "clippy::iter_skip_zero", "clippy::iter_with_drain",
  "clippy::iter_without_into_iter", "clippy::iterator_step_by_zero", "clippy::join_absolute_paths",
  "clippy::just_underscores_and_digits", "clippy::large_const_arrays", "clippy::large_digit_groups",
  "clippy::large_enum_variant", "clippy::large_futures", "clippy::large_include_file",
  "clippy::large_stack_arrays", "clippy::large_stack_frames", "clippy::large_types_passed_by_value",
  "clippy::legacy_numeric_constants", "clippy::len_without_is_empty", "clippy::len_zero",
  "clippy::let_and_return", "clippy::let_underscore_future", "clippy::let_underscore_lock",
  "clippy::let_underscore_must_use", "clippy::let_underscore_untyped", "clippy::let_unit_value",
  "clippy::let_with_type_underscore", "clippy::lines_filter_map_ok", "clippy::linkedlist",
  "clippy::lint_groups_priority", "clippy::literal_string_with_formatting_args", "clippy::little_endian_bytes",
  "clippy::lossy_float_literal", "clippy::macro_metavars_in_unsafe", "clippy::macro_use_imports",
  "clippy::main_recursion", "clippy::manual_abs_diff", "clippy::manual_assert", "clippy::manual_assert_eq",
  "clippy::manual_async_fn", "clippy::manual_bit_width", "clippy::manual_bits",
  "clippy::manual_c_str_literals", "clippy::manual_checked_ops", "clippy::manual_clamp",
  "clippy::manual_clear", "clippy::manual_contains", "clippy::manual_dangling_ptr", "clippy::manual_div_ceil",
  "clippy::manual_filter", "clippy::manual_filter_map", "clippy::manual_find", "clippy::manual_find_map",
  "clippy::manual_flatten", "clippy::manual_hash_one", "clippy::manual_ignore_case_cmp",
  "clippy::manual_ilog2", "clippy::manual_inspect", "clippy::manual_instant_elapsed",
  "clippy::manual_is_ascii_check", "clippy::manual_is_finite", "clippy::manual_is_infinite",
  "clippy::manual_is_multiple_of", "clippy::manual_is_power_of_two", "clippy::manual_is_variant_and",
  "clippy::manual_isolate_lowest_one", "clippy::manual_let_else", "clippy::manual_main_separator_str",
  "clippy::manual_map", "clippy::manual_memcpy", "clippy::manual_midpoint", "clippy::manual_next_back",
  "clippy::manual_non_exhaustive", "clippy::manual_noop_waker", "clippy::manual_ok_err",
  "clippy::manual_ok_or", "clippy::manual_option_as_slice", "clippy::manual_option_zip",
  "clippy::manual_pattern_char_comparison", "clippy::manual_pop_if", "clippy::manual_range_contains",
  "clippy::manual_range_patterns", "clippy::manual_rem_euclid", "clippy::manual_repeat_n",
  "clippy::manual_retain", "clippy::manual_rotate", "clippy::manual_saturating_arithmetic",
  "clippy::manual_slice_fill", "clippy::manual_slice_size_calculation", "clippy::manual_split_once",
  "clippy::manual_str_repeat", "clippy::manual_string_new", "clippy::manual_strip", "clippy::manual_swap",
  "clippy::manual_take", "clippy::manual_try_fold", "clippy::manual_unwrap_or",
  "clippy::manual_unwrap_or_default", "clippy::manual_while_let_some", "clippy::many_single_char_names",
  "clippy::map_all_any_identity", "clippy::map_clone", "clippy::map_collect_result_unit", "clippy::map_entry",
  "clippy::map_err_ignore", "clippy::map_flatten", "clippy::map_identity", "clippy::map_or_identity",
  "clippy::map_unwrap_or", "clippy::map_with_unused_argument_over_ranges", "clippy::match_as_ref",
  "clippy::match_bool", "clippy::match_like_matches_macro", "clippy::match_overlapping_arm",
  "clippy::match_ref_pats", "clippy::match_result_ok", "clippy::match_same_arms",
  "clippy::match_single_binding", "clippy::match_str_case_mismatch", "clippy::match_wild_err_arm",
  "clippy::match_wildcard_for_single_variants", "clippy::maybe_infinite_iter", "clippy::mem_forget",
  "clippy::mem_replace_option_with_none", "clippy::mem_replace_option_with_some",
  "clippy::mem_replace_with_default", "clippy::mem_replace_with_uninit", "clippy::min_ident_chars",
  "clippy::min_max", "clippy::mismatched_bit_width_type", "clippy::mismatching_type_param_order",
  "clippy::misnamed_getters", "clippy::misrefactored_assign_op", "clippy::missing_assert_message",
  "clippy::missing_asserts_for_indexing", "clippy::missing_const_for_fn",
  "clippy::missing_const_for_thread_local", "clippy::missing_docs_in_private_items",
  "clippy::missing_enforced_import_renames", "clippy::missing_errors_doc", "clippy::missing_fields_in_debug",
  "clippy::missing_inline_in_public_items", "clippy::missing_panics_doc", "clippy::missing_safety_doc",
  "clippy::missing_spin_loop", "clippy::missing_trait_methods", "clippy::missing_transmute_annotations",
  "clippy::mistyped_literal_suffixes", "clippy::mixed_attributes_style", "clippy::mixed_case_hex_literals",
  "clippy::mixed_read_write_in_expression", "clippy::mod_module_files", "clippy::module_inception",
  "clippy::module_name_repetitions", "clippy::modulo_arithmetic", "clippy::modulo_one",
  "clippy::multi_assignments", "clippy::multiple_bound_locations", "clippy::multiple_crate_versions",
  "clippy::multiple_inherent_impl", "clippy::multiple_unsafe_ops_per_block", "clippy::must_use_candidate",
  "clippy::must_use_unit", "clippy::mut_from_ref", "clippy::mut_mut", "clippy::mut_mutex_lock",
  "clippy::mut_range_bound", "clippy::mutable_key_type", "clippy::mutex_atomic", "clippy::mutex_integer",
  "clippy::naive_bytecount", "clippy::needless_arbitrary_self_type", "clippy::needless_as_bytes",
  "clippy::needless_bitwise_bool", "clippy::needless_bool", "clippy::needless_bool_assign",
  "clippy::needless_borrow", "clippy::needless_borrowed_reference",
  "clippy::needless_borrows_for_generic_args", "clippy::needless_character_iteration",
  "clippy::needless_collect", "clippy::needless_continue", "clippy::needless_doctest_main",
  "clippy::needless_else", "clippy::needless_for_each", "clippy::needless_ifs", "clippy::needless_late_init",
  "clippy::needless_lifetimes", "clippy::needless_match", "clippy::needless_maybe_sized",
  "clippy::needless_option_as_deref", "clippy::needless_option_take",
  "clippy::needless_parens_on_range_literals", "clippy::needless_pass_by_ref_mut",
  "clippy::needless_pass_by_value", "clippy::needless_pub_self", "clippy::needless_question_mark",
  "clippy::needless_range_loop", "clippy::needless_raw_string_hashes", "clippy::needless_raw_strings",
  "clippy::needless_return", "clippy::needless_return_with_question_mark", "clippy::needless_splitn",
  "clippy::needless_type_cast", "clippy::needless_update", "clippy::neg_cmp_op_on_partial_ord",
  "clippy::neg_multiply", "clippy::negative_feature_names", "clippy::never_loop", "clippy::new_ret_no_self",
  "clippy::new_without_default", "clippy::no_effect", "clippy::no_effect_replace",
  "clippy::no_effect_underscore_binding", "clippy::no_mangle_with_rust_abi", "clippy::non_ascii_literal",
  "clippy::non_canonical_clone_impl", "clippy::non_canonical_partial_ord_impl", "clippy::non_minimal_cfg",
  "clippy::non_octal_unix_permissions", "clippy::non_send_fields_in_send_ty", "clippy::non_std_lazy_statics",
  "clippy::non_zero_suggestions", "clippy::nonminimal_bool", "clippy::nonnull_unchecked_on_box_ptr",
  "clippy::nonsensical_open_options", "clippy::nonstandard_macro_braces", "clippy::not_unsafe_ptr_arg_deref",
  "clippy::nursery", "clippy::obfuscated_if_else", "clippy::octal_escapes", "clippy::ok_expect",
  "clippy::only_used_in_recursion", "clippy::op_ref", "clippy::option_as_ref_cloned",
  "clippy::option_as_ref_deref", "clippy::option_env_unwrap", "clippy::option_filter_map",
  "clippy::option_if_let_else", "clippy::option_map_or_none", "clippy::option_map_unit_fn",
  "clippy::option_option", "clippy::or_fun_call", "clippy::or_then_unwrap", "clippy::out_of_bounds_indexing",
  "clippy::overly_complex_bool_expr", "clippy::owned_cow", "clippy::panic", "clippy::panic_in_result_fn",
  "clippy::panicking_overflow_checks", "clippy::panicking_unwrap", "clippy::partial_pub_fields",
  "clippy::partialeq_ne_impl", "clippy::partialeq_to_none", "clippy::path_buf_push_overwrite",
  "clippy::path_ends_with_ext", "clippy::pathbuf_init_then_push", "clippy::pattern_type_mismatch",
  "clippy::pedantic", "clippy::perf", "clippy::permissions_set_readonly_false", "clippy::pointer_format",
  "clippy::pointers_in_nomem_asm_block", "clippy::possible_missing_comma", "clippy::possible_missing_else",
  "clippy::precedence", "clippy::precedence_bits", "clippy::print_in_format_impl", "clippy::print_literal",
  "clippy::print_stderr", "clippy::print_stdout", "clippy::print_with_newline", "clippy::println_empty_string",
  "clippy::ptr_arg", "clippy::ptr_as_ptr", "clippy::ptr_cast_constness", "clippy::ptr_eq",
  "clippy::ptr_offset_by_literal", "clippy::ptr_offset_with_cast", "clippy::pub_underscore_fields",
  "clippy::pub_use", "clippy::pub_with_shorthand", "clippy::pub_without_shorthand", "clippy::question_mark",
  "clippy::question_mark_used", "clippy::range_minus_one", "clippy::range_plus_one",
  "clippy::range_zip_with_len", "clippy::rc_buffer", "clippy::rc_clone_in_vec_init", "clippy::rc_mutex",
  "clippy::read_line_without_trim", "clippy::read_zero_byte_vec", "clippy::readonly_write_lock",
  "clippy::recursive_format_impl", "clippy::redundant_allocation", "clippy::redundant_as_str",
  "clippy::redundant_async_block", "clippy::redundant_at_rest_pattern", "clippy::redundant_clone",
  "clippy::redundant_closure", "clippy::redundant_closure_call", "clippy::redundant_closure_for_method_calls",
  "clippy::redundant_comparisons", "clippy::redundant_else", "clippy::redundant_feature_names",
  "clippy::redundant_field_names", "clippy::redundant_guards", "clippy::redundant_iter_cloned",
  "clippy::redundant_locals", "clippy::redundant_pattern", "clippy::redundant_pattern_matching",
  "clippy::redundant_pub_crate", "clippy::redundant_slicing", "clippy::redundant_static_lifetimes",
  "clippy::redundant_test_prefix", "clippy::redundant_type_annotations", "clippy::ref_as_ptr",
  "clippy::ref_binding_to_reference", "clippy::ref_option", "clippy::ref_option_ref", "clippy::ref_patterns",
  "clippy::regex_creation_in_loops", "clippy::renamed_function_params", "clippy::repeat_once",
  "clippy::repeat_vec_with_capacity", "clippy::replace_box", "clippy::repr_packed_without_abi",
  "clippy::reserve_after_initialization", "clippy::rest_pat_in_fully_bound_structs",
  "clippy::rest_pattern_accessible_field", "clippy::restriction", "clippy::result_filter_map",
  "clippy::result_large_err", "clippy::result_map_or_into_option", "clippy::result_map_unit_fn",
  "clippy::result_unit_err", "clippy::return_and_then", "clippy::return_self_not_must_use",
  "clippy::reversed_empty_ranges", "clippy::same_functions_in_if_condition", "clippy::same_item_push",
  "clippy::same_length_and_capacity", "clippy::same_name_method", "clippy::search_is_some",
  "clippy::seek_from_current", "clippy::seek_to_start_instead_of_rewind", "clippy::self_assignment",
  "clippy::self_named_constructors", "clippy::self_named_module_files", "clippy::self_only_used_in_recursion",
  "clippy::semicolon_if_nothing_returned", "clippy::semicolon_inside_block", "clippy::semicolon_outside_block",
  "clippy::separated_literal_suffix", "clippy::serde_api_misuse", "clippy::set_contains_or_insert",
  "clippy::shadow_reuse", "clippy::shadow_same", "clippy::shadow_unrelated", "clippy::short_circuit_statement",
  "clippy::should_implement_trait", "clippy::should_panic_without_expect",
  "clippy::significant_drop_in_scrutinee", "clippy::significant_drop_tightening", "clippy::similar_names",
  "clippy::single_call_fn", "clippy::single_char_add_str", "clippy::single_char_lifetime_names",
  "clippy::single_char_pattern", "clippy::single_component_path_imports", "clippy::single_element_loop",
  "clippy::single_match", "clippy::single_match_else", "clippy::single_option_map",
  "clippy::single_range_in_vec_init", "clippy::size_of_in_element_count", "clippy::size_of_ref",
  "clippy::skip_while_next", "clippy::sliced_string_as_bytes", "clippy::slow_vector_initialization",
  "clippy::some_filter", "clippy::stable_sort_primitive", "clippy::std_instead_of_alloc",
  "clippy::std_instead_of_core", "clippy::str_split_at_newline", "clippy::str_to_string", "clippy::string_add",
  "clippy::string_add_assign", "clippy::string_extend_chars", "clippy::string_from_utf8_as_bytes",
  "clippy::string_lit_as_bytes", "clippy::string_lit_chars_any", "clippy::string_slice",
  "clippy::strlen_on_c_strings", "clippy::struct_excessive_bools", "clippy::struct_field_names",
  "clippy::style", "clippy::suboptimal_flops", "clippy::suspicious", "clippy::suspicious_arithmetic_impl",
  "clippy::suspicious_assignment_formatting", "clippy::suspicious_command_arg_space",
  "clippy::suspicious_doc_comments", "clippy::suspicious_else_formatting", "clippy::suspicious_map",
  "clippy::suspicious_op_assign_impl", "clippy::suspicious_open_options",
  "clippy::suspicious_operation_groupings", "clippy::suspicious_splitn", "clippy::suspicious_to_owned",
  "clippy::suspicious_unary_op_formatting", "clippy::suspicious_xor_used_as_pow", "clippy::swap_ptr_to_ref",
  "clippy::swap_with_temporary", "clippy::tabs_in_doc_comments", "clippy::temporary_assignment",
  "clippy::test_attr_in_doctest", "clippy::tests_outside_test_module", "clippy::to_digit_is_some",
  "clippy::to_string_in_format_args", "clippy::to_string_trait_impl", "clippy::todo",
  "clippy::too_long_first_doc_paragraph", "clippy::too_many_arguments", "clippy::too_many_lines",
  "clippy::toplevel_ref_arg", "clippy::trailing_empty_array", "clippy::trait_duplication_in_bounds",
  "clippy::transmute_bytes_to_str", "clippy::transmute_int_to_bool", "clippy::transmute_int_to_non_zero",
  "clippy::transmute_null_to_fn", "clippy::transmute_ptr_to_ptr", "clippy::transmute_ptr_to_ref",
  "clippy::transmute_undefined_repr", "clippy::transmutes_expressible_as_ptr_casts",
  "clippy::transmuting_null", "clippy::trim_split_whitespace", "clippy::trivial_regex",
  "clippy::trivially_copy_pass_by_ref", "clippy::try_err", "clippy::tuple_array_conversions",
  "clippy::type_complexity", "clippy::type_id_on_box", "clippy::type_repetition_in_bounds",
  "clippy::unbuffered_bytes", "clippy::unchecked_time_subtraction", "clippy::unconditional_recursion",
  "clippy::undocumented_unsafe_blocks", "clippy::unicode_not_nfc", "clippy::unimplemented",
  "clippy::uninhabited_references", "clippy::uninit_assumed_init", "clippy::uninit_vec",
  "clippy::uninlined_format_args", "clippy::unit_arg", "clippy::unit_cmp", "clippy::unit_hash",
  "clippy::unit_return_expecting_ord", "clippy::unnecessary_box_returns", "clippy::unnecessary_cast",
  "clippy::unnecessary_clippy_cfg", "clippy::unnecessary_debug_formatting",
  "clippy::unnecessary_fallible_conversions", "clippy::unnecessary_filter_map", "clippy::unnecessary_find_map",
  "clippy::unnecessary_first_then_check", "clippy::unnecessary_fold", "clippy::unnecessary_get_then_check",
  "clippy::unnecessary_join", "clippy::unnecessary_lazy_evaluations", "clippy::unnecessary_literal_bound",
  "clippy::unnecessary_literal_unwrap", "clippy::unnecessary_map_on_constructor", "clippy::unnecessary_map_or",
  "clippy::unnecessary_min_or_max", "clippy::unnecessary_mut_passed", "clippy::unnecessary_operation",
  "clippy::unnecessary_option_map_or_else", "clippy::unnecessary_owned_empty_strings",
  "clippy::unnecessary_rest_pattern", "clippy::unnecessary_result_map_or_else",
  "clippy::unnecessary_safety_comment", "clippy::unnecessary_safety_doc", "clippy::unnecessary_self_imports",
  "clippy::unnecessary_semicolon", "clippy::unnecessary_sort_by", "clippy::unnecessary_struct_initialization",
  "clippy::unnecessary_to_owned", "clippy::unnecessary_trailing_comma", "clippy::unnecessary_unwrap",
  "clippy::unnecessary_unwrap_unchecked", "clippy::unnecessary_wraps", "clippy::unneeded_field_pattern",
  "clippy::unneeded_struct_pattern", "clippy::unneeded_wildcard_pattern", "clippy::unnested_or_patterns",
  "clippy::unreachable", "clippy::unreadable_literal", "clippy::unsafe_derive_deserialize",
  "clippy::unsafe_removed_from_name", "clippy::unseparated_literal_suffix",
  "clippy::unsound_collection_transmute", "clippy::unused_async", "clippy::unused_async_trait_impl",
  "clippy::unused_enumerate_index", "clippy::unused_format_specs", "clippy::unused_io_amount",
  "clippy::unused_peekable", "clippy::unused_result_ok", "clippy::unused_rounding", "clippy::unused_self",
  "clippy::unused_trait_names", "clippy::unused_unit", "clippy::unusual_byte_groupings",
  "clippy::unwrap_in_result", "clippy::unwrap_or_default", "clippy::unwrap_used",
  "clippy::upper_case_acronyms", "clippy::use_debug", "clippy::use_self", "clippy::used_underscore_binding",
  "clippy::used_underscore_items", "clippy::useless_asref", "clippy::useless_attribute",
  "clippy::useless_borrows_in_formatting", "clippy::useless_concat", "clippy::useless_conversion",
  "clippy::useless_format", "clippy::useless_let_if_seq", "clippy::useless_nonzero_new_unchecked",
  "clippy::useless_transmute", "clippy::useless_vec", "clippy::vec_box", "clippy::vec_init_then_push",
  "clippy::vec_resize_to_zero", "clippy::verbose_bit_mask", "clippy::verbose_file_reads",
  "clippy::volatile_composites", "clippy::waker_clone_wake", "clippy::while_float",
  "clippy::while_immutable_condition", "clippy::while_let_loop", "clippy::while_let_on_iterator",
  "clippy::wildcard_dependencies", "clippy::wildcard_enum_match_arm", "clippy::wildcard_imports",
  "clippy::wildcard_in_or_patterns", "clippy::with_capacity_zero", "clippy::write_literal",
  "clippy::write_with_newline", "clippy::writeln_empty_string", "clippy::wrong_self_convention",
  "clippy::wrong_transmute", "clippy::zero_divided_by_zero", "clippy::zero_prefixed_literal",
  "clippy::zero_ptr", "clippy::zero_repeat_side_effects", "clippy::zero_sized_map_values",
  "clippy::zombie_processes", "clippy::zst_offset", "closure_returning_async_block", "coherence_leak_check",
  "conflicting_repr_hints", "confusable_idents", "const_evaluatable_unchecked",
  "const_item_interior_mutations", "const_item_mutation", "dangerous_implicit_autorefs",
  "dangling_pointers_from_locals", "dangling_pointers_from_temporaries", "dead_code",
  "dead_code_pub_in_binary", "default_overrides_default_fields", "dependency_on_unit_never_type_fallback",
  "deprecated", "deprecated_in_future", "deprecated_llvm_intrinsic", "deprecated_safe", "deprecated_safe_2024",
  "deprecated_where_clause_location", "deref_into_dyn_supertrait", "deref_nullptr", "double_negations",
  "drop_bounds", "dropping_copy_types", "dropping_references", "duplicate_features",
  "duplicate_macro_attributes", "duplicate_tools", "dyn_drop", "edition_2024_expr_fragment_specifier",
  "elided_lifetimes_in_associated_constant", "elided_lifetimes_in_paths", "ellipsis_inclusive_range_patterns",
  "enum_intrinsics_non_enums", "explicit_builtin_cfgs_in_flags", "explicit_outlives_requirements",
  "exported_private_dependencies", "ffi_unwind_calls", "float_literal_f32_fallback",
  "for_loops_over_fallibles", "forbidden_lint_groups", "forgetting_copy_types", "forgetting_references",
  "function_casts_as_integer", "function_item_references", "future_incompatible", "hidden_glob_reexports",
  "if_let_rescope", "ill_formed_attribute_input", "impl_trait_overcaptures", "impl_trait_redundant_captures",
  "implicit_provenance_casts", "improper_ctypes", "improper_ctypes_definitions", "improper_gpu_kernel_arg",
  "incomplete_features", "incomplete_include", "ineffective_unstable_trait_impl", "inline_no_sanitize",
  "integer_to_ptr_transmutes", "internal_eq_trait_method_impls", "internal_features",
  "invalid_atomic_ordering", "invalid_doc_attributes", "invalid_from_utf8", "invalid_from_utf8_unchecked",
  "invalid_macro_export_arguments", "invalid_nan_comparisons", "invalid_null_arguments",
  "invalid_reference_casting", "invalid_runtime_symbol_definitions", "invalid_type_param_default",
  "invalid_value", "irrefutable_let_patterns", "keyword_idents", "keyword_idents_2018", "keyword_idents_2024",
  "large_assignments", "late_bound_lifetime_arguments", "legacy_derive_helpers", "let_underscore",
  "let_underscore_drop", "let_underscore_lock", "linker_info", "linker_messages", "long_running_const_eval",
  "macro_expanded_macro_exports_accessed_by_absolute_paths", "macro_use_extern_crate",
  "malformed_diagnostic_attributes", "malformed_diagnostic_filters", "malformed_diagnostic_format_literals",
  "map_unit_fn", "meta_variable_misuse", "method_call_on_diverging_infer_var", "mismatched_lifetime_syntaxes",
  "misplaced_diagnostic_attributes", "missing_abi", "missing_copy_implementations",
  "missing_debug_implementations", "missing_docs", "missing_gpu_kernel_export_name",
  "missing_unsafe_on_extern", "mixed_script_confusables", "multiple_supertrait_upcastable", "must_not_suspend",
  "mutable_transmutes", "named_arguments_used_positionally", "named_asm_labels",
  "never_type_fallback_flowing_into_unsafe", "no_mangle_const_items", "no_mangle_generic_items",
  "non_ascii_idents", "non_camel_case_types", "non_contiguous_range_endpoints",
  "non_exhaustive_omitted_patterns", "non_fmt_panics", "non_local_definitions", "non_shorthand_field_patterns",
  "non_snake_case", "non_upper_case_globals", "nonstandard_style", "noop_method_call",
  "opaque_hidden_inferred_bound", "out_of_scope_macro_calls", "overflowing_literals",
  "overlapping_range_endpoints", "path_statements", "patterns_in_fns_without_body", "private_bounds",
  "private_interfaces", "proc_macro_derive_resolution_fallback", "ptr_to_integer_transmute_in_consts",
  "pub_use_of_private_extern_crate", "raw_borrows_via_references", "recursion_depth_exceeding_limit",
  "redundant_imports", "redundant_lifetimes", "redundant_semicolons", "refining_impl_trait",
  "refining_impl_trait_internal", "refining_impl_trait_reachable", "renamed_and_removed_lints",
  "repr_c_enums_larger_than_int", "resolving_to_items_shadowing_supertrait_items", "rtsan_nonblocking_async",
  "rust_2018_compatibility", "rust_2018_idioms", "rust_2021_compatibility",
  "rust_2021_incompatible_closure_captures", "rust_2021_incompatible_or_patterns",
  "rust_2021_prefixes_incompatible_syntax", "rust_2021_prelude_collisions", "rust_2024_compatibility",
  "rust_2024_guarded_string_incompatible_syntax", "rust_2024_incompatible_pat", "rust_2024_prelude_collisions",
  "rustdoc::all", "rustdoc::bare_urls", "rustdoc::broken_intra_doc_links",
  "rustdoc::invalid_codeblock_attributes", "rustdoc::invalid_html_tags", "rustdoc::invalid_rust_codeblocks",
  "rustdoc::missing_crate_level_docs", "rustdoc::missing_doc_code_examples", "rustdoc::private_doc_tests",
  "rustdoc::private_intra_doc_links", "rustdoc::redundant_explicit_links", "rustdoc::unescaped_backticks",
  "self_constructor_from_outer_item", "semicolon_in_expressions_from_macros",
  "semicolon_in_expressions_from_non_local_macros", "shadowing_supertrait_items", "single_use_lifetimes",
  "special_module_name", "stable_features", "static_mut_refs", "suspicious_double_ref_op",
  "suspicious_runtime_symbol_definitions", "tail_call_track_caller", "tail_expr_drop_order",
  "test_unstable_lint", "text_direction_codepoint_in_comment", "text_direction_codepoint_in_literal",
  "trivial_bounds", "trivial_casts", "trivial_numeric_casts", "type_alias_bounds", "tyvar_behind_raw_pointer",
  "uncommon_codepoints", "unconditional_panic", "unconditional_recursion", "uncovered_param_in_projection",
  "undropped_manually_drops", "unexpected_cfgs", "unfulfilled_lint_expectations",
  "ungated_async_fn_track_caller", "uninhabited_static", "unit_bindings", "unknown_crate_types",
  "unknown_diagnostic_attributes", "unknown_lints", "unknown_or_malformed_diagnostic_attributes",
  "unnameable_test_items", "unnameable_types", "unnecessary_transmutes",
  "unpredictable_function_pointer_comparisons", "unqualified_local_imports",
  "unreachable_cfg_select_predicates", "unreachable_code", "unreachable_patterns", "unreachable_pub",
  "unsafe_attr_outside_unsafe", "unsafe_code", "unsafe_op_in_unsafe_fn", "unstable_features",
  "unstable_name_collisions", "unstable_syntax_pre_expansion", "unsupported_calling_conventions", "unused",
  "unused_allocation", "unused_assignments", "unused_associated_type_bounds", "unused_attributes",
  "unused_braces", "unused_comparisons", "unused_crate_dependencies", "unused_doc_comments",
  "unused_extern_crates", "unused_features", "unused_import_braces", "unused_imports", "unused_labels",
  "unused_lifetimes", "unused_macro_rules", "unused_macros", "unused_must_use", "unused_mut", "unused_parens",
  "unused_qualifications", "unused_results", "unused_unsafe", "unused_variables", "unused_visibilities",
  "useless_deprecated", "useless_ptr_null_checks", "uses_power_alignment", "varargs_without_pattern",
  "variant_size_differences", "warnings", "while_true",
]));
const RUSTC_CODE_RE = /^error\[E\d{4}\]/;
const LINT_NOTE_RE = /(?:`-D |`#\[(?:deny|warn)\()((?:clippy::|rustdoc::)?[a-z][a-z0-9_-]{0,63})(?=`|\)\]`)/g;
function firstErrorCodes(out) {
  const lines = String(out).split("\n");
  const start = lines.findIndex((l) => /^error/.test(l));
  if (start === -1) return "first error not recognised; see artifact";
  const codes = [];
  let unknownLints = 0;
  const rc = RUSTC_CODE_RE.exec(lines[start]);
  if (rc) codes.push(rc[0]);
  for (let i = start; i < Math.min(lines.length, start + 50); i++) {
    if (i > start && (!lines[i].trim() || /^(error|warning)/.test(lines[i]))) break;
    for (const m of lines[i].matchAll(LINT_NOTE_RE)) {
      const lint = m[1].replace(/-/g, "_");
      if (lint === "warnings" || codes.includes(lint)) continue;
      if (LINT_NAMES.has(lint)) codes.push(lint); else unknownLints += 1;
    }
    if (codes.length >= 4) break;
  }
  const more = unknownLints ? ` (+${countBucket(unknownLints)} lint name(s) not recognised)` : "";
  // Lint names print sorted after the rustc code (order carries nothing).
  const shown = [...codes.filter((c) => c.startsWith("error[")), ...codes.filter((c) => !c.startsWith("error[")).sort()].slice(0, 4);
  return codes.length ? `first error: ${shown.join(" ")}${more}` : `first error not recognised; see artifact${more}`;
}

// ── TEST-SOURCE INDEX: built at most once per RED print, from the preflight's
// own ROOT: `git ls-files -z -- '*.rs'` (tracked paths), then one pass over
// those files collecting `fn <ident>` lines whose attribute block — the up to 3
// contiguous preceding lines that are attributes, doc/line comments or blank —
// carries a `#[<path containing test>…]` attribute (`#[test]`,
// `#[tokio::test(…)]`, …; `#[cfg(test)]` is not one: its path is `cfg`).
// A tracked path that is gone (ENOENT), a symlink (O_NOFOLLOW -> ELOOP) or not a
// regular file (fstat on the opened fd) is SKIPPED, not fatal. The pass is
// bounded by a BYTE budget: the fd's size is checked against the remaining
// budget and at most min(size, remaining) bytes are read from that fd; any
// other failure (git, a read, the budget) yields null and the printer prints
// counts only.
const TEST_INDEX_MAX_BYTES = 256 * 1024 * 1024;
const TEST_ATTR_RE = /^#\[[A-Za-z0-9_:]*test[A-Za-z0-9_:]*(?:\(.*\))?\]$/;
const FN_RE = /^(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b/;
function buildTestIndex() {
  const files = sh("git", ["ls-files", "-z", "--", "*.rs"], ROOT).split("\0").filter(Boolean);
  const fns = new Set(), tracked = new Set();
  let total = 0;
  for (const f of files) {
    const path = join(ROOT, f);
    let fd;
    // O_NOFOLLOW (where defined): a symlink fails ELOOP and is skipped, so the
    // file that is fstat'ed and read is the one opened — no lstat/read race.
    try { fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)); }
    catch (e) { if (e?.code === "ENOENT" || e?.code === "ELOOP") continue; throw e; }
    let text;
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) continue;
      const remaining = TEST_INDEX_MAX_BYTES - total;
      if (st.size > remaining) throw Object.assign(new Error("test index budget exceeded"), { code: "INDEX_BUDGET" });
      const want = Math.min(st.size, remaining), buf = Buffer.alloc(want);
      let off = 0;
      while (off < want) { const got = readSync(fd, buf, off, want - off, off); if (got === 0) break; off += got; }
      total += off;
      text = buf.subarray(0, off).toString("utf8");
    } finally { closeSync(fd); }
    tracked.add(f);
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = FN_RE.exec(lines[i].trim());
      if (!m) continue;
      for (let k = i - 1; k >= Math.max(0, i - 3); k--) {
        const t = lines[k].trim();
        if (t.startsWith("#[")) { if (TEST_ATTR_RE.test(t)) { fns.add(m[1]); break; } continue; }
        if (t === "" || t.startsWith("//")) continue;
        break;
      }
    }
  }
  return { files: tracked, fns };
}
// THE PRINTED ATOM. Only bytes that are trusted ON THEIR OWN are printed: for a
// unit test the bare `fn` identifier that is in the index (the `::` module path
// is never printed — a fixed suffix says it was withheld); for a doc test only
// the exact tracked file path that is in the index (item and line withheld). Returns null when the entry is not a
// test in the tree — the caller COUNTS it. The full-name grammar checks above
// stay as belt and braces.
function trustedAtom(n, index) {
  const doc = DOCTEST_NAME_RE.exec(n);
  const ident = doc ? null : n.split("::").at(-1);
  const known = doc ? index.files.has(doc[1]) : index.fns.has(ident);
  if (!known) return null;
  return doc ? `${doc[1]} (line withheld)` : `${ident}${n.includes("::") ? " (module path withheld)" : ""}`;
}

function isDocTestName(n) {
  const m = DOCTEST_NAME_RE.exec(n);
  return !!m && isRelPath(m[1]);
}
// Absolute ceiling on entries taken from one final list, whatever its trailer
// claims (`N failed` is capped at 7 digits by TEST_RESULT_RE).
const RED_LIST_ENTRY_CAP = 10000;
// Extraction from libtest stdout in ONE forward pass. A trailer is FINAL when
// the next non-empty line is EOF, the next binary's `running N tests`, or our
// own leg RC line — never more captured output. For a final trailer only the
// CONTIGUOUS block of 4-space-indented lines directly before it (after libtest's
// one blank line) is read, walking back at most min(`N failed`, the ceiling)+1
// lines, and it must sit directly under a `failures:` header; anything else is
// counted as `N failed` unrecognised entries. Each walk stops at the first
// non-indented line, and a trailer line is never indented, so two walks never
// cover the same lines: the whole pass is linear in the output.
function extractFailingTests(text, names, counts) {
  const lines = text.split("\n");
  const accept = (t) => {
    const failed = Number(TEST_RESULT_RE.exec(lines[t])[1]);
    if (!failed) return;
    const cap = Math.min(failed, RED_LIST_ENTRY_CAP);
    let k = t - 1;
    if (k >= 0 && lines[k] === "") k -= 1;
    const entries = [];
    while (k >= 0 && lines[k].startsWith("    ") && entries.length <= cap) { entries.push(lines[k].slice(4)); k -= 1; }
    if (entries.length !== failed || k < 0 || lines[k] !== "failures:") { counts.unrecognised += cap; return; }
    for (const n of entries.reverse()) {
      if (UNIT_TEST_NAME_RE.test(n) || isDocTestName(n)) names.add(n);
      else counts.unrecognised += 1;
    }
  };
  let pending = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (pending !== -1) {
      if (!l.trim()) continue;
      if (RUNNING_RE.test(l) || l.startsWith("CSQ_PREFLIGHT_LEG_RC ")) accept(pending);
      pending = -1;
    }
    if (TEST_RESULT_RE.test(l)) pending = i;
  }
  if (pending !== -1) accept(pending);
}

function gateEvidenceArtifacts(g) {
  const out = [];
  for (const e of [...(g.heavy_output_evidence || []), ...(g.command_output_evidence || []), g.worker_output_evidence]) {
    if (e && typeof e === "object") out.push(e);
  }
  return out;
}

function printRedEvidence(redGates) {
  let unknownGates = 0;
  let index;  // undefined = not built yet; null = unavailable (counts only)
  const testIndex = () => {
    if (index !== undefined) return index;
    try { index = buildTestIndex(); }
    catch (e) {
      index = null;
      console.log(`  test-source index unavailable (${errIdent(e)}); test names counted, not printed`);
    }
    return index;
  };
  for (const g of redGates) {
    if (!ALL_GATE_NAMES.has(g.name)) { unknownGates += 1; continue; }
    const artifacts = gateEvidenceArtifacts(g);
    if (!artifacts.length) continue;
    const names = new Set(), counts = { unrecognised: 0 }, seen = new Set();
    let badPaths = 0, scanned = 0;
    for (const a of artifacts) {
      if (!isOwnEvidencePath(a.path)) { badPaths += 1; continue; }
      if (seen.has(a.path)) continue;
      seen.add(a.path);
      console.log(`RED evidence (${g.name}): ${homeTilde(a.path)}`);
      if (typeof a.sha256 !== "string" || !SHA256_RE.test(a.sha256)) {
        console.log("  sha256 not recognised; names not extracted");
        continue;
      }
      console.log(`  sha256 ${a.sha256}`);
      let bytes;
      try {
        const st = lstatSync(a.path);
        if (!st.isFile()) { console.log("  artifact is not a regular file; names not extracted"); continue; }
        if (st.size > RED_ARTIFACT_SCAN_BYTES) { console.log("  artifact too large to scan; open the artifact"); continue; }
        bytes = readFileSync(a.path);
      } catch (e) { console.log(`  artifact unreadable (${errIdent(e)})`); continue; }
      if (createHash("sha256").update(bytes).digest("hex") !== a.sha256) {
        console.log("  artifact digest mismatch; names not extracted");
        continue;
      }
      let doc;
      try { doc = JSON.parse(bytes.toString("utf8")); }
      catch (e) { console.log(`  artifact not parseable (${errIdent(e)})`); continue; }
      // libtest writes its trailer and final list to STDOUT only.
      if (typeof doc?.stdout === "string") extractFailingTests(doc.stdout, names, counts);
      scanned += 1;
    }
    if (badPaths) console.log(`  ${countBucket(badPaths)} evidence path(s) not recognised; not printed`);
    if (!scanned) continue;
    // Atoms print SORTED and deduplicated (order carries nothing), each with a
    // bucketed multiplicity; every count is bucketed (countBucket).
    const atoms = new Map();
    if (names.size) {
      const index = testIndex();
      for (const n of names) {
        const atom = index === null ? null : trustedAtom(n, index);
        if (atom === null) counts.unrecognised += 1; else atoms.set(atom, (atoms.get(atom) || 0) + 1);
      }
    }
    const list = [...atoms.keys()].sort();
    for (const a of list.slice(0, RED_TEST_NAME_LIMIT)) console.log(`  failing test: ${a} ×${countBucket(atoms.get(a))}`);
    if (list.length > RED_TEST_NAME_LIMIT) console.log(`  +${countBucket(list.length - RED_TEST_NAME_LIMIT)} more`);
    if (!list.length) console.log("  no test names recognised; open the artifact");
    if (counts.unrecognised) console.log(`  ${countBucket(counts.unrecognised)} unrecognised test name(s) not printed`);
  }
  if (unknownGates) console.log(`RED evidence: ${countBucket(unknownGates)} gate name(s) not recognised; not printed`);
}

function gate(name, fn) {
  ALL_GATE_NAMES.add(name);
  if (ONLY && !ONLY.split(",").some((selector) => selector.trim() && name.includes(selector.trim()))) return;
  selected += 1;
  registered.push({ name, fn });
}
async function executeGate({ name, fn }) {
  const started = performance.now(), evidenceStart = heavyEvidence.length;
  let r;
  const capture = { outputs: [], failed: false };
  activeGateCapture = capture;
  try { r = await fn(); } catch (e) { r = { state: "UNDETERMINED", detail: `gate threw before a verdict (${ownThrowCause(e)})` }; }
  finally { activeGateCapture = null; }
  if (capture.failed) {
    if (r.state !== "RED") r.state = "UNDETERMINED";
    r.detail = `${r.detail || ""}; could not retain gate command output`;
  }
  r.command_output_evidence = capture.outputs;
  const evidence = heavyEvidence.slice(evidenceStart);
  if (evidence.length) r.heavy_output_evidence = [...(r.heavy_output_evidence || []), ...evidence];
  const measuredLegs = evidence.map((entry) => entry.leg).filter(Boolean);
  if (measuredLegs.length) {
    r.heavy_legs = measuredLegs;
    if (!r.leg) r.detail = `${r.detail || ""}; ${measuredLegs.map((leg) => `wall_ms=${leg.wall_ms} host=${leg.host ?? 'unknown'}`).join('; ')}`;
  }
  if (r.state === "UNDETERMINED" && r.heavy_output_evidence?.length) {
    r.detail = `${r.detail || ""}; output evidence: ${r.heavy_output_evidence.map((e) => `${shownEvidencePath(e?.path)} sha256=${typeof e?.sha256 === "string" && SHA256_RE.test(e.sha256) ? e.sha256 : "not recognised"}`).join("; ")}`;
  }
  r.elapsed_ms = performance.now() - started;
  const row = { name, ...r };
  const line = `  ${name} ... ${r.state}${r.detail ? ` — ${r.detail}` : ""}`;
  try { row.gate_output_evidence = retainOutput({ status: aggregateExit([row]), stdout: line + "\n", stderr: "", elapsed_ms: r.elapsed_ms }, name); }
  catch {
    if (row.state !== "RED") row.state = "UNDETERMINED";
    row.detail = `${row.detail || ""}; could not retain gate verdict output`;
  }
  console.log(`  ${name} ... ${row.state}${row.detail ? ` — ${row.detail}` : ""}`);
  if (ONLY && process.env.DEV_PREFLIGHT_SHOW_GATE_EVIDENCE === "1") console.log("HEAVY_GATE_EVIDENCE " + JSON.stringify({ state: row.state, evidence: row.heavy_output_evidence || [], command_output_evidence: row.command_output_evidence, gate_output_evidence: row.gate_output_evidence }));
  if (treeFingerprint() !== START_FINGERPRINT) treeMovedAfter ||= name;
  return row;
}


console.log("dev-preflight — the only check before a CI-free push\n");

gate("cargo fmt", () => {
  const r = runHeavy("cargo fmt --all -- --check");
  if (r.und) return { state: "UNDETERMINED", detail: r.und };
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

// THE GAP THIS CLOSES (D237 rule 9), measured 2026-10-17: this preflight was
// GREEN on 421077be8 while CI's Edition Seam leak-guard job went RED on step (f)
// "ACL GRANT SURFACE CHANGED" — two new renderer-reachable commands with no
// moved snapshot. Both CI steps are pure python3 and sub-second, so they run
// here as a QUICK gate, locally (no offload: they are not a long job). The
// commands are DERIVED from edition-seam.yml, never restated (an internal ticket's class),
// and the scripts' own exit contract is honoured: 0 clean, 1 finding, anything
// else (2 = could not evaluate, signal, spawn failure) is UNDETERMINED.
const ACL_STEPS = [
  "(f0) ACL manifest freshness (generated __app-acl__ vs permissions/*.toml)",
  "(f) ACL grant-surface ratchet (renderer reachable-command set)",
];
// A finding is exit 1 AND the script's own finding line on stdout. A Python
// crash (traceback) also exits 1, so the exit code alone cannot tell the two
// apart: exit 1 without the marker is UNDETERMINED, never a RED "finding".
const ACL_FINDING_MARKERS = {
  "(f0)": "ACL MANIFEST STALE",
  "(f)": "ACL GRANT SURFACE CHANGED",
};
gate("ACL ratchet (f0)+(f) — derived from edition-seam.yml", () => {
  const ran = [];
  for (const step of ACL_STEPS) {
    const d = deriveStepCommand(step, "community-and-lock-assert", ".github/workflows/edition-seam.yml");
    if (d.err) return { state: "UNDETERMINED", detail: `${d.err} — NOT falling back to a hardcoded invocation` };
    const shown = d.cmd.replace(/\s+/g, " ").slice(0, 100);
    let status = 0;
    let stdout = "";
    try { sh("bash", ["-c", d.cmd], ROOT, d.env); }
    catch (e) { status = e.signal ? -1 : (typeof e.status === "number" ? e.status : -1); stdout = String(e.stdout || ""); }
    if (status === 1 && stdout.includes(ACL_FINDING_MARKERS[step.split(" ")[0]])) return { state: "RED", detail: `${step.split(" ")[0]} reported a finding — ran: ${shown}` };
    if (status !== 0) return { state: "UNDETERMINED", detail: `${step.split(" ")[0]} could not evaluate (status ${status}) — ran: ${shown}` };
    ran.push(shown);
  }
  return { state: "GREEN", detail: `clean; ran: ${ran.join(" ; ")}` };
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
    // A full-line YAML comment is not content at any indent and never ends the
    // block (edition-seam.yml's leak-guard job carries one inside its `env:`);
    // reading it as an entry collapsed the whole derivation to UNDETERMINED.
    if (/^\s*#/.test(l)) continue;
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
  // A YAML-quoted step name (edition-seam.yml quotes every one) is the same
  // name; the quotes must match on both sides.
  const isStep = (l) =>
    new RegExp(`^\\s*-\\s+name:\\s*(["']?)${escaped}\\1\\s*$`).test(l);
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
  const r = runHeavy(d.cmd, d.env, { os: "linux" });
  if (r.und) return { state: "UNDETERMINED", detail: r.und };
  if (r.ok) return { state: "GREEN", detail: `clean; ran: ${shown}` };
  // A toolchain that could not RUN is not a lint finding and must not be
  // reported as one.
  if (!r.out.trim() || /command not found|ENOENT/i.test(r.out)) {
    return { state: "UNDETERMINED", detail: `could not run: ${shown}` };
  }
  // The derived command is echoed on EVERY path, RED included. It is the thing
  // under test here — a reader who cannot see which command produced a finding
  // cannot tell a real lint from a derivation that went wrong.
  const first = firstErrorCodes(r.out);
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
    // `target` is built from `rustc --print sysroot` output: shown only through
    // the local-path allowlist (charset, no `..`, $HOME as `~`).
    missing.push(`x86_64-pc-windows-gnu target (expected ${shownLocalPath(target)})`);
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

  // Offloaded, the cross toolchain this host has or lacks is irrelevant: the
  // step runs on a Linux fleet host. The local probe only applies to the
  // CSQ_PREFLIGHT_LOCAL escape hatch.
  const probe = HEAVY_LOCAL ? probeWindowsCrossToolchain() : { ok: true };
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
  const r = runHeavy(d.cmd, d.env, { os: "linux" });
  if (r.und) return { state: "UNDETERMINED", detail: r.und };
  if (r.ok) return { state: "GREEN", detail: `clean; ran: ${shown}` };
  // A fleet host without the mingw toolchain is "could not check" (and must
  // not read as a lint finding); offloaded, that is UNDETERMINED, not a skip.
  if (
    !HEAVY_LOCAL &&
    /can't find crate for `(core|std)`|x86_64-w64-mingw32-gcc.*(not found|No such file)|linker `?x86_64-w64-mingw32/i.test(
      r.out,
    )
  ) {
    return {
      state: "UNDETERMINED",
      detail: `the --os linux host lacks the windows-gnu cross toolchain — could not lint: ${shown}`,
    };
  }
  if (!r.out.trim() || /command not found|ENOENT/i.test(r.out)) {
    return { state: "UNDETERMINED", detail: `could not run: ${shown}` };
  }
  const first = firstErrorCodes(r.out);
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

for (const t of targets) {
  gate(`docs-${t.label} — derived from workflows`, () => {
  const rel = touchesRustSurface();
  if (rel.err) return { state: "UNDETERMINED", detail: rel.err };
  if (!rel.hit) {
    return {
      state: "NOT_APPLICABLE",
      detail: `not relevant — no .rs/Cargo.{toml,lock}/rust-toolchain.toml in the ${rel.files.length}-file diff vs origin/main`,
    };
  }


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
    const r = runHeavy(d.cmd, d.env, { os: "linux" });
    if (r.und) return { state: "UNDETERMINED", detail: `${t.label}: ${r.und}` };
    if (r.ok) {
      return { state: "GREEN", detail: `clean; ran: ${shown}` };
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
    const first = firstErrorCodes(r.out);
    return { state: "RED", detail: `${first} — ran: ${shown}` };

  });
}

// ALLOWLIST-ONLY detail values for this gate. A ScopeError carries one of this
// gate's own fixed messages; any other error (a git exit, a realpath ENOENT
// whose message names a path) is reduced to its exit status or identifier.
class ScopeError extends Error {}
function scopeCause(error) {
  if (error instanceof ScopeError) return error.message;
  if (Number.isInteger(error?.status)) return `git exited ${error.status}`;
  return `error (${errIdent(error)})`;
}
// A git-reported worktree path / branch name: conservative charset, no `..`
// segment, $HOME shown as `~`; anything else is replaced by a fixed phrase.
function shownLocalPath(p) {
  return typeof p === "string" && /^\/[A-Za-z0-9._\/@+-]{1,1024}$/.test(p) && !p.split("/").includes("..")
    ? homeTilde(p) : "path not recognised";
}
function shownBranch(b) {
  return typeof b === "string" && /^[A-Za-z0-9._\/@+-]{1,200}$/.test(b) ? b : "branch not recognised";
}
// The operator's own DEV_PREFLIGHT_ONLY selector, echoed only if it is a plain
// gate-name selector.
function shownSelector(v) {
  return /^[A-Za-z0-9 ,._:()\/{}'—-]{1,200}$/.test(v) ? v : "selector not shown";
}

// This dev-push gate owns this checkout and the source lanes named by native
// landing trailers in origin/dev..HEAD. Other live sessions are informational.
gate("tree clean (push carries everything)", () => {
  const st = tryRun("git", ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]);
  if (!st.ok) return { state: "UNDETERMINED", detail: "git status failed" };
  if (st.out) return { state: "RED", detail: "uncommitted/untracked paths in this checkout would remain behind" };
  try {
    const here = realpathSync(ROOT);
    const head = sh("git", ["rev-parse", "--verify", "HEAD^{commit}"], ROOT).trim();
    const branchRef = sh("git", ["symbolic-ref", "--quiet", "HEAD"], ROOT).trim();
    if (!branchRef.startsWith("refs/heads/") || !/^[0-9a-f]{40}$/.test(head))
      throw new ScopeError("current landing checkout identity is undetermined");
    const scope = new Set([branchRef.slice("refs/heads/".length)]);
    const baseline = sh("git", ["rev-parse", "--verify", "refs/remotes/origin/dev^{commit}"], ROOT).trim();
    if (!/^[0-9a-f]{40}$/.test(baseline))
      throw new ScopeError("native origin/dev baseline is undetermined");
    sh("git", ["merge-base", "--is-ancestor", baseline, head], ROOT);
    const format = "%H%x00%P%x00%(trailers:key=Landed-From,only,unfold)%x00%(trailers:key=Landed-Partial,only,unfold)%x00%x1e";
    const log = sh("git", ["log", "--format=" + format, baseline + ".." + head], ROOT);
    for (const record of log.split("\x1e").filter((r) => r.trim())) {
      const fields = record.trim().split("\0");
      if (fields.length !== 5 || fields[4] !== "" || !/^[0-9a-f]{40}$/.test(fields[0]))
        throw new ScopeError("native landing scope record is malformed");
      const parents = fields[1].split(" ").filter(Boolean);
      if (parents.some((p) => !/^[0-9a-f]{40}$/.test(p)))
        throw new ScopeError("native payload parent identity is malformed");
      const trailers = fields.slice(2, 4).flatMap((v) => v.split("\n").filter(Boolean));
      if (parents.length <= 1 && trailers.length === 0)
        throw new ScopeError("nonmerge payload lacks native landing scope trailer");
      for (const trailer of trailers) {
        const field = /^Landed-(?:From|Partial):[ \t]*(.*)$/i.exec(trailer);
        if (!field) throw new ScopeError("native landing scope trailer is malformed");
        const value = field[1].trim();
        if (value === "direct") continue;
        const source = /^(\S+)@([0-9a-f]{40})$/.exec(value);
        if (!source) throw new ScopeError("native landing source identity is malformed");
        sh("git", ["check-ref-format", "refs/heads/" + source[1]], ROOT);
        scope.add(source[1]);
      }
    }
    const wt = sh("git", ["worktree", "list", "--porcelain", "-z"], ROOT);
    if (!wt.endsWith("\0\0")) throw new ScopeError("native worktree inventory is incomplete");
    const entries = [];
    for (const record of wt.split("\0\0").filter(Boolean)) {
      const fields = record.split("\0");
      if (!fields[0].startsWith("worktree ") || !fields[0].slice(9))
        throw new ScopeError("native worktree path is missing");
      const heads = fields.filter((f) => f.startsWith("HEAD "));
      const branches = fields.filter((f) => f.startsWith("branch "));
      const detached = fields.filter((f) => f === "detached").length;
      if (heads.length !== 1 || !/^[0-9a-f]{40}$/.test(heads[0].slice(5)) ||
          branches.length + detached !== 1 || branches.length > 1 ||
          (branches.length && !branches[0].startsWith("branch refs/heads/")))
        throw new ScopeError("native worktree identity is missing or ambiguous");
      entries.push({ path: fields[0].slice(9), head: heads[0].slice(5),
        branchRef: branches.length ? branches[0].slice(7) : "HEAD" });
    }
    let own = 0;
    const stranded = [], informational = [];
    for (const entry of entries) {
      const path = realpathSync(entry.path);
      const actualRoot = sh("git", ["-C", path, "rev-parse", "--show-toplevel"], ROOT).replace(/\n$/, "");
      const actualHead = sh("git", ["-C", path, "rev-parse", "--verify", "HEAD^{commit}"], ROOT).trim();
      const actualRef = sh("git", ["-C", path, "rev-parse", "--symbolic-full-name", "HEAD"], ROOT).trim();
      if (realpathSync(actualRoot) !== path || actualHead !== entry.head || actualRef !== entry.branchRef)
        throw new ScopeError("native worktree identity changed or is unreadable");
      if (path === here) {
        own++;
        if (actualHead !== head || actualRef !== branchRef)
          throw new ScopeError("current landing checkout changed during scope read");
        continue;
      }
      const dirty = sh("git", ["-C", path, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], ROOT);
      if (!dirty) continue;
      const branch = entry.branchRef === "HEAD" ? null : entry.branchRef.slice("refs/heads/".length);
      const label = shownLocalPath(entry.path) + " (" + (branch === null ? "detached HEAD" : shownBranch(branch)) + ")";
      if (branch && scope.has(branch)) stranded.push(label);
      else informational.push(label);
    }
    if (own !== 1) throw new ScopeError("current landing checkout absent or ambiguous in native inventory");
    if (stranded.length) return { state: "RED", detail: "dirty source/current-branch lane(s): " + stranded.join(", ") };
    return { state: "GREEN", detail: "current checkout and declared source lanes clean; unrelated dirty peer(s) informational: " + (informational.join(", ") || "none") };
  } catch (error) {
    return { state: "UNDETERMINED", detail: "native push/worktree scope could not be measured: " + scopeCause(error) };
  }
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
// L6 hook point: register scripts/verify/test-orphan-check.sh here when its
// verifier lands. An absent verifier is never represented as a passing gate.
const SIGNOFF_TEST_FEATURES = 'csq/test-utils,csq-core/test-utils';
for (const os of ['linux', 'darwin']) {
  const legs = [
    ['lib-bins', `cargo test --workspace --lib --bins --no-fail-fast --features ${SIGNOFF_TEST_FEATURES}`, true],
    ['integration', `cargo test --workspace --test '*' --no-fail-fast --features ${SIGNOFF_TEST_FEATURES} -- --test-threads=2`, true],
    ['doc', `cargo test --workspace --doc --features ${SIGNOFF_TEST_FEATURES}`, true],
    ['edition-leak', 'bash scripts/check-edition-leak.sh', false],
    // edition-seam.yml job (e): THIRD-PARTY-LICENSES freshness (D237 rule 9).
    ['licenses-fresh', 'bash scripts/check-third-party-licenses-fresh.sh', false],
    // Canonical extraction includes metadata, rustfmt and every leak check.
    // Linux covers the public-tree materialization without a second build.
    ...(os === 'linux' ? [['community-extraction', COMMUNITY_EXTRACTION_COMMAND, false]] : []),
  ];
  for (const [kind, command, buildStub] of legs) {
    gate(`sign-off ${os} ${kind}`, () => {
      const r = runHeavy(command, {}, { os, leg: { token: randomUUID(), buildStub } });
      const leg = { platform: os, host: r.host ?? null, host_provenance: r.host_provenance ?? [], wall_ms: r.wall_ms ?? null, rc: r.leg_rc ?? null, tree: r.tree ?? null, porcelain: r.porcelain ?? null };
      return { state: r.und ? 'UNDETERMINED' : r.ok ? 'GREEN' : 'RED', leg,
        detail: `${r.und || `LEG_RC=${r.leg_rc}`} (wall_ms=${leg.wall_ms ?? 'unknown'} host=${leg.host ?? 'unknown'})` };
    });
  }
}

const SELFTEST_CEILING_MS = 900_000;

// The PER-TEST bound, distinct from the whole-set ceiling above. Same two named
// outcomes, same measured sample (2026-09-20): the worst HEALTHY wrapper is
// `citation-resolution.test.sh` at 322s; a WEDGED wrapper is unbounded. Before
// the split ONE number served both roles, so a single hang could consume the
// whole 900s set budget and the verdict could not say which bound had fired.
// 600s sits 278s (1.86x) above the worst healthy observation — the margin that
// matters is this one, because too LOW kills a passing test and reports a false
// "could not measure" that blocks a push the operator cannot clear by fixing
// anything. The 900s `SELFTEST_CEILING_MS` above is a CAP on this value and a
// refusal bound, NOT a wall-clock bound on the set: `runShellGate` says it in as
// many words ("It is NOT enforced as a wall-clock bound on the set"), the set is
// time-boxed by what its members cost, and the only bound that kills anything is
// this per-test one — so two wedges can run 1200s and nothing here stops them.
// This number therefore claims exactly one thing: a 1.86x margin over the worst
// measured healthy wrapper. A wrapper hitting it is UNDETERMINED, never RED (the
// header above).
const SELFTEST_PER_TEST_MS = 600_000;

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
      detail: `cannot read ${wf} (${errIdent(e)}) — the file list and version pin are derived from it, so this is a cannot-measure, never a pass`,
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

  const script = `set -uo pipefail\nshopt -s nullglob\n${arrayText}\nif [ "\${#files[@]}" -lt 2 ]; then echo "FATAL: the derived glob matched \${#files[@]} file(s)" >&2; exit 64; fi\nprintf 'shellchecking %d file(s)\\n' "\${#files[@]}"\nshellcheck -f gcc "\${files[@]}"\n`;
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
  // ALLOWLIST-ONLY: `-f gcc` emits `<path>:<line>:<col>: <level>: <message> [SC####]`
  // per finding. Only `<path>:<line>:<col> SC####` is printed — the path a
  // repo-relative allowlisted path, the numbers digits only. The message and
  // any other line (tool errors, unexpected shapes) are COUNTED, never shown.
  const findings = [];
  let unrecognised = 0;
  for (const l of res.out.split("\n")) {
    if (!l.trim() || /^shellchecking \d+ file\(s\)$/.test(l)) continue;
    const m = /^([^:\n]{1,200}):(\d{1,7}):(\d{1,7}): [a-z]{1,16}: .* \[SC(\d{1,5})\]$/.exec(l);
    if (m && isRelPath(m[1])) findings.push(`${m[1]}:${m[2]}:${m[3]} SC${m[4]}`);
    else unrecognised += 1;
  }
  const shown = findings.slice(0, 12);
  return {
    state: "RED",
    detail: `shellcheck reported findings (CI's job exits non-zero on ANY level, info included):${shown.length ? `\n    ${shown.join("\n    ")}` : " none recognised"}${findings.length > 12 ? `\n    +${findings.length - 12} more` : ""}${unrecognised ? `\n    ${unrecognised} output line(s) not recognised; not printed` : ""}`,
  };
});

gate("shell-gate self-tests (globbed from scripts/tests/)", async () => {
  if (process.env.DEV_PREFLIGHT_IN_SELFTEST) return { state: "UNDETERMINED", detail: "refusing to re-enter: a self-test invoked this preflight without DEV_PREFLIGHT_ONLY" };
  if (process.env.DEV_PREFLIGHT_FORCE_NO_BASH) return { state: "SKIPPED", detail: "no `bash` on PATH — the self-test set could not run on this host" };
  const local = !!ONLY && process.env.DEV_PREFLIGHT_SELFTEST_LOCAL === "1" && process.env.CSQ_PREFLIGHT_CANONICAL_WORKER !== "1";
  const ceilingMs = local && process.env.DEV_PREFLIGHT_SELFTEST_CEILING_MS ? Number(process.env.DEV_PREFLIGHT_SELFTEST_CEILING_MS) : SELFTEST_CEILING_MS;
  // AN OPERATOR-SUPPLIED per-test bound is passed through RAW, never clamped:
  // runShellGate REFUSES one that is not finite, not positive, or above the
  // ceiling, and clamping here would make that refusal unreachable while quietly
  // running every wrapper under a bound nobody asked for — the policy
  // runShellGate's own comment names ("silently clamping it would kill wrappers
  // under a bound nobody asked for"). A non-numeric override yields NaN, which
  // is not nullish, so `??` keeps it and runShellGate refuses it.
  // The DEFAULT is DERIVED, not clamped: with no per-test override the ceiling IS
  // the bound the operator named, so the fixture harnesses' one-number seam
  // (they lower DEV_PREFLIGHT_SELFTEST_CEILING_MS to make a wedge cost seconds)
  // still bounds each wrapper. Production names neither, so the default resolves
  // to SELFTEST_PER_TEST_MS.
  const perTestOverride = local && process.env.DEV_PREFLIGHT_SELFTEST_PER_TEST_MS ? Number(process.env.DEV_PREFLIGHT_SELFTEST_PER_TEST_MS) : null;
  const perTestMs = perTestOverride ?? Math.min(SELFTEST_PER_TEST_MS, ceilingMs);
  return runShellGate(ROOT, { local, ceilingMs, perTestMs });
});

if (worker) {
  if (registered.length !== 1) process.exit(2);
  const row = await executeGate(registered[0]);
  if (treeMovedAfter || treeFingerprint() !== START_FINGERPRINT || START_FINGERPRINT !== process.env.CSQ_PREFLIGHT_PARENT_FINGERPRINT) {
    row.state = "UNDETERMINED"; row.detail = "source changed during gate worker execution";
  }
  await new Promise((resolve) => process.send({ token: process.env.CSQ_PREFLIGHT_WORKER_TOKEN, gate: row,
    fingerprint: START_FINGERPRINT, no_receipt: true }, resolve));
  process.exit(aggregateExit([row]));
}
const PREFLIGHT_STARTED = performance.now();
const quickNames = new Set(["cargo fmt", "run-ci-gates", "ACL ratchet (f0)+(f) — derived from edition-seam.yml", "shellcheck — derived from test.yml", "workflow job-set vs origin/main", "tree clean (push carries everything)"]);
const quick = registered.filter((r) => quickNames.has(r.name));
for (const item of quick) gates.push(await executeGate(item));
const deferred = registered.filter((r) => !quickNames.has(r.name));
if (gates.every((r) => r.state === "GREEN") && !treeMovedAfter) {
  gates.push(...await runGateWorkers(deferred.map((r) => r.name), { script: fileURLToPath(import.meta.url), cwd: ROOT,
    env: FLEET_ENV, fingerprint: START_FINGERPRINT, onComplete: (row) => {
      console.log(`  ${row.name} ... ${row.state}${row.detail ? ` — ${row.detail}` : ""}`);
      if (ONLY && process.env.DEV_PREFLIGHT_SHOW_GATE_EVIDENCE === "1") console.log("HEAVY_GATE_EVIDENCE " + JSON.stringify({ name: row.name, state: row.state, elapsed_ms: row.elapsed_ms, evidence: row.heavy_output_evidence || [], leg: row.leg, worker_evidence: row.worker_output_evidence }));
      if (treeFingerprint() !== START_FINGERPRINT) treeMovedAfter ||= row.name;
    } }));
} else {
  for (const item of deferred) { const row = { name: item.name, state: "UNDETERMINED", elapsed_ms: 0, detail: "not launched: prerequisite quick checks did not all pass" }; gates.push(row); console.log(`  ${row.name} ... ${row.state} — ${row.detail}`); }
}
const PREFLIGHT_ELAPSED_MS = performance.now() - PREFLIGHT_STARTED;

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
    `dev-preflight: UNDETERMINED — DEV_PREFLIGHT_ONLY='${shownSelector(ONLY)}' matched no gate.`,
  );
  process.exit(2);
}
if (red.length) {
  console.log(
    `dev-preflight: RED — ${red.length} gate(s) failed. No receipt written; the push guard will refuse.`,
  );
  red.forEach((g) => console.log(`    ${g.name}: ${g.detail}`));
  // Runs only after the RED verdict is decided and can change neither it, the
  // exit code nor the (absent) receipt: every failure inside is caught here and
  // reported by an identifier-only cause.
  try { printRedEvidence(red); }
  catch (e) {
    const line = `RED evidence: printer failed (${errIdent(e)})`;
    try { console.log(line); }
    // stdout itself failed: say so on fd 2; if even that fails, exit RED now.
    catch { try { writeSync(2, line + "\n"); } catch { process.exit(1); } }
  }
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
    `dev-preflight: the '${shownSelector(ONLY)}' subset passed (${selected} gate(s)). NO receipt written — a partial run is not evidence.`,
  );
  process.exit(0);
}

writeFileSync(
  RECEIPT,
  JSON.stringify(
    { sha, at: new Date().toISOString(), heavy_steps_ran: HEAVY_RAN, elapsed_ms: PREFLIGHT_ELAPSED_MS, gates },
    null,
    2,
  ) + "\n",
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
  "  job-set, Linux and Darwin lib/bins, integration and doc tests, edition-leak,",
);
console.log(
  "  THIRD-PARTY-LICENSES freshness,",
);
console.log(
  "  and the scripts/tests/*.test.sh shell-gate self-test set (the same",
);
console.log(
  "  glob CI's 'Shell gate self-tests' job runs on main, which `dev` never reaches).",
);
console.log(
  "  NOT covered: the six sink feature combinations, the native-harness",
);
console.log(
  "  lint target and the windows-cfg lint when SKIPPED above",
);
console.log(
  "  (incl. Windows RUNTIME behaviour — the windows-cfg gate is lint-only, per",
);
console.log(
  "  test-windows.yml's own an internal ticket note). Those first run at the dev -> main",
);
console.log("  promotion gate.");
process.exit(0);
