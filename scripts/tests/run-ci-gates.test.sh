#!/usr/bin/env bash
# Self-test for scripts/run-ci-gates.sh.
#
# The point of this file is NOT that the runner runs. It is that the runner
# FAILS on the exact shape it was written to catch: a gate script that nothing
# invokes. That case (`unmarked_script_fails`) is the load-bearing one — if it
# ever goes green the runner has become decoration, which is precisely what
# happened to the two gates whose being unwired motivated the runner.
#
# Every case pins one fixture state to one exit code, and the fixtures are
# hermetic: each builds its own `scripts/verify/` from scratch, so nothing here
# depends on this repo's real gates. That matters because the real gate set is
# expected to change; a self-test coupled to it would decay into a change
# detector.
#
# Deliberately no `set -e` — non-zero is the EXPECTED result in most cases.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/run-ci-gates.sh"
[ -f "$SCRIPT" ] || { echo "FATAL: $SCRIPT not found"; exit 2; }

TMPROOT="$(mktemp -d -t run-ci-gates-selftest-XXXXXX)"
# Explicit `if`, NOT `A && B || C` (SC2015): that idiom fires the FATAL branch
# whenever the SECOND test is falsy on a perfectly good tmpdir. The trap
# rm -rf's this path, so a wrong value must abort before the trap is armed.
if [ -z "$TMPROOT" ] || [ ! -d "$TMPROOT" ]; then
  echo "FATAL: mktemp failed"; exit 2
fi
trap 'rm -rf "$TMPROOT"' EXIT

PASS=0; FAIL=0
check() { # check <desc> <expected-rc> <actual-rc>
  if [ "$2" -eq "$3" ]; then printf '  PASS  %s (exit %s)\n' "$1" "$3"; PASS=$((PASS+1))
  else printf '  FAIL  %s — expected exit %s, got %s\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}

check_out() { # check_out <desc> <needle> <haystack>
  case "$3" in
    *"$2"*) printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)) ;;
    *) printf '  FAIL  %s — output did not contain %s\n' "$1" "$2"; FAIL=$((FAIL+1)) ;;
  esac
}

# Creates a fixture repo root carrying a SATISFIED minimum floor: one passing
# tree-scan gate (`floorbase.sh`) and a registry naming it.
#
# It is not decoration. Both a missing registry AND an empty one are
# UNDETERMINED by design (cases 19 and 21) — a floor of zero cannot detect a
# shrink, so the runner refuses rather than reporting that it checked. Every
# case below is about something else, so each needs a floor that is present,
# non-empty, and met; `floorbase.sh` is the smallest thing that is all three.
new_root() { # new_root <case-name>
  local root="$TMPROOT/$1"
  mkdir -p "$root/scripts/verify"
  plant "$root" floorbase.sh '# ci-gate: tree-scan' 0
  registry "$root"
  printf '%s' "$root"
}

# Sets the floor for a fixture root. $1 = root, remaining args = EXTRA gate
# basenames beyond floorbase.sh, which is always required so the baseline stays
# satisfied and the advisory list stays about the case's own gates.
registry() { # registry <root> [extra-name...]
  local root="$1"; shift
  { printf '# fixture floor\nfloorbase.sh\n'; [ "$#" -gt 0 ] && printf '%s\n' "$@"; } \
    > "$root/scripts/ci-gate-registry.txt"
}

# Plants a gate script. $1 = root, $2 = filename, $3 = the header lines to place
# under the shebang, $4 = the exit code the gate should produce.
plant() { # plant <root> <name> <header> <exit-code>
  local root="$1" name="$2" header="$3" code="$4"
  {
    printf '#!/usr/bin/env bash\n'
    [ -n "$header" ] && printf '%s\n' "$header"
    # Echo the received argument so a case can assert the REPO_ROOT contract,
    # not merely the exit code. A runner that passed no root would still get
    # the right exit code from every gate here, so without this the contract
    # would be untested.
    # shellcheck disable=SC2016  # emitting shell source, not expanding it here
    printf 'printf "GOT_ROOT=[%%s]\\n" "${1-}"\n'
    printf 'exit %s\n' "$code"
  } > "$root/scripts/verify/$name"
  chmod +x "$root/scripts/verify/$name"
}

echo "run-ci-gates self-test"

# ── 1. CLEAN — one enrolled gate, exits 0 ──────────────────────────────
# The negative pole. Without a case that goes green, every other case below is
# consistent with "the runner always fails".
root="$(new_root clean)"
plant "$root" ok.sh '# ci-gate: tree-scan' 0
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "clean tree passes" 0 "$rc"
check_out "clean tree reports CLEAN" "CLEAN" "$out"

# ── 2. The REPO_ROOT contract is actually honoured ─────────────────────
# `tree-scan` promises the gate receives the root as $1. Asserting the exit code
# alone would pass even if the runner invoked the gate with no arguments, in
# which case every real gate would silently scan the CI checkout instead of the
# tree it was handed — invisible in this repo, wrong in the self-test trees.
check_out "gate receives REPO_ROOT as \$1" "GOT_ROOT=[$root]" "$out"

# ── 3. FINDING — a gate exits 1 ────────────────────────────────────────
root="$(new_root finding)"
plant "$root" bad.sh '# ci-gate: tree-scan' 1
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "a gate finding fails the runner" 1 "$rc"
check_out "finding is named in the output" "bad.sh" "$out"

# ── 4. UNDETERMINED stays distinct from both pass and finding ──────────
# The whole reason for a third state: an unreachable oracle must not read as a
# pass, and must not be reported as a finding the operator can go fix.
root="$(new_root undetermined)"
plant "$root" murky.sh '# ci-gate: tree-scan' 2
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "an undetermined gate exits 2, not 0 and not 1" 2 "$rc"
check_out "undetermined says it is not a pass" "NOT a pass" "$out"

# ── 5. A finding OUTRANKS an undetermined ──────────────────────────────
root="$(new_root precedence)"
plant "$root" bad.sh   '# ci-gate: tree-scan' 1
plant "$root" murky.sh '# ci-gate: tree-scan' 2
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "finding + undetermined reports the finding" 1 "$rc"

# ── 6. THE LOAD-BEARING CASE — an undeclared script fails ──────────────
# This is the defect that motivated the whole runner: a gate sitting in
# scripts/verify/ that no workflow ever invokes. Here it cannot hide, because
# absence of a marker is a failure rather than a skip.
root="$(new_root unmarked)"
plant "$root" orphan.sh '' 0
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "an unmarked script FAILS (does not silently skip)" 1 "$rc"
check_out "unmarked script is named" "orphan.sh" "$out"

# ── 7. An unknown marker is not treated as an exemption ────────────────
# Fail-closed on typos. `# ci-gate: treescan` must not read as "not a gate".
root="$(new_root typo)"
plant "$root" typo.sh '# ci-gate: treescan' 0
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "an unknown marker fails" 1 "$rc"

# ── 8. `none` REQUIRES a reason ────────────────────────────────────────
# Otherwise `# ci-gate: none` is a one-line way to opt out forever, which is the
# original defect wearing a marker.
root="$(new_root none_bare)"
plant "$root" skipme.sh '# ci-gate: none' 0
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "bare 'none' with no reason fails" 1 "$rc"

# ── 9. `none` WITH a reason is exempt, and is not executed ─────────────
# The gate below would exit 1 if run; a green result proves it was skipped
# rather than merely tolerated.
root="$(new_root none_reason)"
plant "$root" skipme.sh '# ci-gate: none
# ci-gate-reason: needs a PR number no workflow can supply.' 1
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "'none' + reason is exempt and not executed" 0 "$rc"
check_out "exempt script is counted" "1 exempt" "$out"

# ── 10. The marker must be a DECLARATION, not a mention ────────────────
# This file and the runner both discuss `ci-gate:` in prose. An unanchored grep
# would match those and silently enrol (or exempt) the wrong script, so the
# marker is anchored at start-of-line. A mid-line mention must not count.
root="$(new_root prose)"
plant "$root" prose.sh '# see the ci-gate: tree-scan convention in run-ci-gates.sh' 0
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "a mid-line 'ci-gate:' mention does not declare" 1 "$rc"

# ── 11. Fails CLOSED when the glob matches nothing ─────────────────────
# A runner that silently runs zero gates and exits 0 is the same defect class it
# exists to catch, so it must not be able to pass that way.
root="$(new_root empty)"
rm -f "$root/scripts/verify/"*.sh   # including the floorbase new_root plants
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "an empty scripts/verify/ fails closed" 2 "$rc"

# ── 12. A missing scripts/verify/ is UNDETERMINED, not clean ───────────
root="$TMPROOT/no_verify_dir"; mkdir -p "$root"
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "a missing scripts/verify/ exits 2" 2 "$rc"

# ── 13. A non-directory root is rejected ───────────────────────────────
out="$(bash "$SCRIPT" "$TMPROOT/does-not-exist" 2>&1)"; rc=$?
check "a bad REPO_ROOT exits 2" 2 "$rc"

# ── 14. An unknown flag is rejected rather than silently ignored ───────
out="$(bash "$SCRIPT" --nonsense 2>&1)"; rc=$?
check "an unknown flag exits 2" 2 "$rc"

# ── 15. --quiet suppresses the report but NOT the failure ──────────────
# A quiet mode that also quietened the exit code would be a fail-open switch.
root="$(new_root quiet)"
plant "$root" bad.sh '# ci-gate: tree-scan' 1
out="$(bash "$SCRIPT" "$root" --quiet 2>/dev/null)"; rc=$?
check "--quiet still fails on a finding" 1 "$rc"

# ── 16. THE FLOOR HOLDS — a registered gate that ran is clean ──────────
# The negative pole for the floor cases below. Without it, 17-19 are all
# consistent with "any non-empty registry fails".
root="$(new_root floor_met)"
plant "$root" ok.sh '# ci-gate: tree-scan' 0
registry "$root" ok.sh
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "a met floor passes" 0 "$rc"
check_out "the floor size is reported" "floor expects 2 gate(s)" "$out"

# ── 17. THE LOAD-BEARING FLOOR CASE — a required gate is GONE ──────────
# This is the silent shrink: the tree still has a gate, the runner still reports
# a clean count, and the only thing wrong is that a gate which used to be here
# is not. Without the floor this exits 0 — which is how the community extraction
# went from 5 tree-scan gates to 4 with nothing announcing it.
root="$(new_root floor_shrink)"
plant "$root" ok.sh '# ci-gate: tree-scan' 0
registry "$root" ok.sh vanished.sh
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "a missing required gate FAILS (silent shrink caught)" 1 "$rc"
check_out "the missing gate is named, not just counted" "vanished.sh" "$out"

# ── 18. Declaring a required gate away is the same shrink ──────────────
# `# ci-gate: none` + a reason is a legitimate exemption in general, but it must
# not be a one-line way to retire a gate the floor still requires.
root="$(new_root floor_declared_away)"
plant "$root" ok.sh '# ci-gate: none
# ci-gate-reason: not a tree gate any more.' 0
registry "$root" ok.sh
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "re-declaring a required gate 'none' FAILS" 1 "$rc"
check_out "the declared-away gate is named" "ok.sh" "$out"

# ── 19. A MISSING registry is UNDETERMINED, never a pass ───────────────
# "There is no floor" and "the floor is met" are different answers. Collapsing
# them would make the floor vanish silently on any tree that drops the file —
# the precise failure this whole change exists to prevent, one level up.
root="$(new_root floor_absent)"
plant "$root" ok.sh '# ci-gate: tree-scan' 0
rm -f "$root/scripts/ci-gate-registry.txt"
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "a missing gate floor exits 2 (not 0)" 2 "$rc"

# ── 20. An unregistered gate is enrolled, not rejected ─────────────────
# Glob enrolment must keep working: a gate added on another branch runs here
# without also editing the shared floor file, so concurrent gate PRs do not
# conflict. It is surfaced as an advisory, never a failure.
root="$(new_root floor_advisory)"
plant "$root" ok.sh  '# ci-gate: tree-scan' 0
plant "$root" new.sh '# ci-gate: tree-scan' 0
registry "$root" ok.sh
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "an unregistered gate still runs and passes" 0 "$rc"
check_out "the unregistered gate is surfaced as advisory" "not on the floor: new.sh" "$out"

# ── 21. An EMPTY registry is UNDETERMINED, not "nothing is required" ───
# The likelier accident than a missing file: a failed write, a truncating
# redirect, a bad sed, a partial checkout, a regeneration that produced nothing.
# Read as "no gates are required" it is a fail-OPEN inside the mechanism built
# to catch fail-open gate sets, and it is indistinguishable from a deliberate
# empty floor — so the runner must refuse rather than report that it checked.
root="$(new_root floor_empty)"
plant "$root" ok.sh '# ci-gate: tree-scan' 0
printf '# every line a comment; zero entries\n' > "$root/scripts/ci-gate-registry.txt"
out="$(bash "$SCRIPT" "$root" 2>&1)"; rc=$?
check "an EMPTY gate floor exits 2 (not 0)" 2 "$rc"
check_out "the empty floor says a shrink cannot be detected" "cannot detect a shrink" "$out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
