#!/usr/bin/env bash
# ci-gate: tree-scan
# Answer ONE question correctly: "does any fixture CONSTRUCT a `resets_at` that
# will be in the past before this code is retired?"
#
# WHY THIS EXISTS
# ---------------
# On 2026-08-07T11:12:35Z seven quota fixtures expired mid-session and reddened
# every PR in flight. They pinned `resets_at: 1_786_101_155` — that exact instant.
# The quota read path's `clear_expired` NULLS a past window, so the affected rows
# fell back to their `$0.00` balance and the assertions inverted:
#
#   left: "balance"       right: "utilization"
#   left: Some("$0.00")   right: None
#
# Two PRs merged green at 11:03Z; the next job started at 11:15Z and failed on the
# same commits. Nothing changed but the wall clock. `testing.md` Rule 1 already
# documented this exact class from a 2026-04 incident; what was missing was a
# mechanical check, so the second occurrence cost a live queue instead of a diff.
#
# SCOPE IS DELIBERATELY NARROW, AND THAT IS THE POINT
# ---------------------------------------------------
# This gate checks `resets_at` ONLY, and only where a literal is ASSIGNED in
# struct-literal position. Three exclusions, each from a real false positive in the
# hand audit that preceded this script:
#
#   1. `assert*!` lines are SKIPPED. `usage_poller/grok.rs` asserts that
#      "2026-08-07T11:12:35.900538+00:00" parses to 1786101155 — a conversion
#      assertion with NO liveness dependency. It is correct, and it is also where
#      the magic number came from before being copy-pasted into fixtures where
#      liveness does matter. A gate that reds it would be deleted by the first
#      person it blocked.
#   2. `expires_at` / `nextResetTime` are OUT OF SCOPE. Those are milliseconds in
#      this tree, not seconds, and a deliberately-PAST credential expiry is the
#      normal shape for a refresh-path fixture. Flagging them produced more noise
#      than signal (`tooling-self-verification.md` Rule 5 — an audit primitive
#      that cries wolf is one nobody runs).
#   3. Computed values (`now()`, `+`, `SystemTime`) are SKIPPED: those are the
#      CORRECT pattern Rule 1 prescribes as the alternative to a far-future literal.
#   4. Values FAR in the past are SKIPPED — see the band below.
#
# THE BAND, AND WHY IT IS NOT JUST AN UPPER BOUND
# -----------------------------------------------
# The first draft flagged everything below the horizon and produced SIX false
# positives on the very tree it was written to clean: `resets_at: 1000` / `2000` /
# `5000` in `quota/mod.rs::clear_expired_removes_old_windows` and `quota/state.rs`.
# Those are DELIBERATELY expired — they exist to prove `clear_expired` nulls a past
# window, and one carries the comment "resets_at in the past will be cleared on
# load". Flagging a correct test is how a gate earns deletion.
#
# The discriminator is that a deliberate sentinel is OBVIOUSLY SYNTHETIC — 1970-era,
# never plausible as a real reset time — whereas a bomb is a PLAUSIBLE CURRENT-ERA
# timestamp that was the future when it was written and quietly stopped being so.
# So the check is a BAND, not a ceiling: [now - 2y, now + 5y].
#
# Residual, stated rather than hidden: a fixture intentionally pinned to a
# plausible timestamp inside the last two years WILL flag. That is the honest
# trade — such a value is indistinguishable from an expired bomb by inspection, and
# the report tells you the remedy either way.
#
# `resets_at` is seconds in csq (`quota::UsageWindow`), so the decode is unambiguous
# — which is exactly why this field is checkable and `expires_at` is not.
#
# EXIT CODES (fail-closed; never a silent 0)
#   0  clean        — no constructed `resets_at` literal lands inside the band
#   1  time-bomb    — >=1 literal lands inside the band
#   2  undetermined — bad root, or no python3 to decode with
set -uo pipefail

die() { printf 'fixture-timebombs: %s\n' "$1" >&2; exit 2; }

ROOT=""
QUIET=""
for arg in "$@"; do
    case "$arg" in
        --quiet) QUIET=1 ;;
        -*) die "unknown flag '$arg'" ;;
        *)
            if [ -z "$ROOT" ]; then ROOT="$arg"; else die "unexpected argument '$arg'"; fi
            ;;
    esac
done
if [ -z "$ROOT" ]; then
    ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not in a git repo and no REPO_ROOT given"
fi
[ -d "$ROOT" ] || die "REPO_ROOT '$ROOT' is not a directory"
command -v python3 >/dev/null 2>&1 || die "python3 not on PATH (needed to decode epochs)"

# Horizon: `testing.md` Rule 1's own bar — "reject any value that decodes to a
# date within 5 years of when the test was written". Anything nearer is a bomb
# with a longer fuse, not a safe value.
HORIZON_YEARS=5
# Lower edge of the band: below this, a value is an obviously-synthetic
# deliberately-expired sentinel, not a bomb (see § THE BAND).
LOOKBACK_YEARS=2

# Output is captured so --quiet can suppress the REPORT while preserving the
# VERDICT. Piping python straight into a conditional would lose its exit code
# (`durable-instruments.md` MUST NOT — a piped verdict is the last stage's).
#
# KEEP APOSTROPHES BALANCED INSIDE THIS HEREDOC. It is a quoted heredoc, which
# should make quoting irrelevant, but it sits inside a `$( )` and bash 3.2 (the
# macOS system bash) parses that combination by scanning for the closing paren
# with quoting still active. One unpaired `'` — an English possessive is enough
# — makes the whole script die with "unexpected EOF while looking for matching".
# Cost when hit on 2026-08-08: the gate exited 2 on every run until spotted.
OUT="$(python3 - "$ROOT" "$HORIZON_YEARS" "$LOOKBACK_YEARS" <<'PY'
import datetime, os, re, sys

root, horizon_years, lookback_years = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
now = datetime.datetime.now(datetime.timezone.utc).timestamp()
horizon = now + horizon_years * 365 * 86400
floor = now - lookback_years * 365 * 86400

# Struct-literal assignment of a bare integer literal. `_` separators allowed.
# Requires `:` (struct field / type-ascribed let), which is what excludes the
# `assert_eq!(w.resets_at, 178...)` comparison form — that uses a comma.
ASSIGN = re.compile(r'\bresets_at\s*:\s*([0-9][0-9_]*)\b')
SKIP_LINE = re.compile(r'assert|now\(\)|SystemTime|UNIX_EPOCH|^\s*(//|\*|/\*)')

findings, scanned = [], 0
for dirpath, dirnames, filenames in os.walk(root):
    # Prune build output AND any NESTED CHECKOUT. A nested git worktree or
    # submodule holds source from a different branch, so a finding there is a
    # finding about code that is not in this tree — reported against a commit
    # that does not contain it. Detected structurally by the `.git` entry every
    # checkout root carries (a FILE in a worktree, a directory in a clone)
    # rather than by name, so `.claude/worktrees/`, `.csq-wt/`, a vendored
    # clone and a submodule are all covered without a name list to maintain.
    #
    # Measured 2026-08-08: with two agent worktrees nested under
    # `.claude/worktrees/`, this scan went from 455 to 1365 .rs files and
    # reported the pre-fix copy of a line that was already fixed on this tree.
    # CI never reproduces it (no worktrees there), so only a local run exposes it.
    dirnames[:] = [d for d in dirnames
                   if d not in {"target", "node_modules", ".git", "dist", "__pycache__"}
                   and not os.path.exists(os.path.join(dirpath, d, ".git"))]
    for fn in filenames:
        if not fn.endswith(".rs"):
            continue
        path = os.path.join(dirpath, fn)
        scanned += 1
        try:
            lines = open(path, errors="replace").read().split("\n")
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if SKIP_LINE.search(line):
                continue
            for m in ASSIGN.finditer(line):
                secs = int(m.group(1).replace("_", ""))
                if floor <= secs < horizon:
                    when = datetime.datetime.fromtimestamp(secs, datetime.timezone.utc)
                    state = "EXPIRED" if secs < now else "expires soon"
                    rel = os.path.relpath(path, root)
                    findings.append((rel, i, secs, when.date().isoformat(), state))

if findings:
    print(f"fixture-timebombs: {len(findings)} TIME-BOMB(S) — a constructed `resets_at` "
          f"in the band [now-{lookback_years}y, now+{horizon_years}y]:")
    print("")
    for rel, ln, secs, when, state in sorted(findings, key=lambda f: f[3]):
        print(f"    {state:12} {when}  {rel}:{ln}  resets_at={secs}")
    print("")
    print("A past `resets_at` is NULLED by the quota read path's `clear_expired`, so the")
    print("row falls back to its balance and any 'window wins' assertion inverts. Use the")
    print("`testing.md` Rule 1 sentinel 4_102_444_800 (2100-01-01), or compute from")
    print("SystemTime::now() — and record WHY, so it is not 'tidied' back.")
    sys.exit(1)

print(f"fixture-timebombs: CLEAN — scanned {scanned} .rs file(s); no constructed "
      f"`resets_at` literal in the band [now-{lookback_years}y, now+{horizon_years}y].")
sys.exit(0)
PY
)"
rc=$?
[ -n "$QUIET" ] || printf '%s\n' "$OUT"
# python3's exit code IS the verdict; surface it unchanged.
exit "$rc"
