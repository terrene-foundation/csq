#!/usr/bin/env bash
# Answer ONE question correctly: "does every tree-scanning gate under
# scripts/verify/ actually RUN against this tree, and does it pass?"
#
# WHY THIS EXISTS
# ---------------
# On 2026-08-08 both gates written the previous session to prevent recurrence
# were found to be UNWIRED. `scripts/verify/fixture-timebombs.sh` and
# `scripts/verify/milestone-refs.sh` each had a passing self-test, and neither
# had ever run against the repository it was written to protect:
#
#   $ grep -rn 'fixture-timebombs\.sh\|milestone-refs\.sh' .github/workflows/
#   (no output)
#
# The self-tests pass because they construct a synthetic fixture tree and point
# the gate at that. They prove the gate DISCRIMINATES. They say nothing about
# whether it is ever ASKED. `milestone-refs.sh` was, at that moment, exiting 1
# on real `main` — a live finding nothing could see.
#
# This is the fourth instance of one class in two sessions. The other three were
# a quota salvage loader with zero production callers, an exported `http_post_pipe`
# that was never called, and `worktree-cargo-slot.sh gc` which exited 0 and swept
# nothing. Each shipped, each passed its own tests, each was inert. The pattern is
# not carelessness — it is that "the code is correct" and "the code is reached"
# are separate properties and only the first one has a test by default.
#
# THE FIX IS ENROLMENT BY DEFAULT, NOT A LONGER CHECKLIST
# -------------------------------------------------------
# A second thing to remember is not a fix; the previous session already knew
# gates must be wired and still shipped two that were not. So enrolment here is
# mechanical and FAILS CLOSED:
#
#   * every `scripts/verify/*.sh` is globbed, never enumerated. A gate added on
#     another branch enrols itself rather than needing a second edit to a shared
#     file — which is also why two concurrent gate PRs no longer conflict.
#   * every script MUST declare its role with a `# ci-gate:` marker. A script
#     with NO marker is a FAILURE, not a skip. That is the whole defense: the
#     only way to add a gate that does not run is to explicitly say so in the
#     gate's own header, where a reviewer reads it.
#
# THE MARKER
# ----------
#   # ci-gate: tree-scan   -> run it here; it must exit 0 against this tree.
#   # ci-gate: none        -> deliberately not a tree gate. MUST be followed by
#                             `# ci-gate-reason: <why>` so the exemption is
#                             justified in place rather than by assertion.
#
# `tree-scan` is a CONTRACT, not just a label. A gate declaring it MUST:
#   (a) accept the repo root as its first positional argument — so this runner
#       and the gate's own self-test can both point it at a tree, and
#   (b) use the three-state exit contract: 0 clean, 1 finding(s), 2 UNDETERMINED.
#
# Both existing tree-scan gates already share exactly this `[REPO_ROOT] [--quiet]`
# shape, so the contract was read off the code rather than invented for it.
#
# EXIT CONTRACT (this runner)
# ---------------------------
#   0  every tree-scan gate ran and exited 0.
#   1  a gate reported a finding, or a script carries no marker.
#   2  a gate could not measure (its own exit 2), or this runner could not run.
#
# 2 is deliberately NOT 0 and NOT merged into 1. "A gate could not measure this"
# and "a gate found a problem" demand different operator responses, and a gate
# whose oracle was unreachable must never read as a pass — that is precisely how
# `milestone-refs.sh` would have gone quiet if `gh` were missing. Both are
# non-zero, so CI fails either way; the distinction is for the human reading it.
#
# USAGE
#   scripts/run-ci-gates.sh [REPO_ROOT] [--quiet]
#
# REPO_ROOT defaults to the git toplevel. It is a parameter for the same reason
# the gates take one: a checker that can only run against the real repo cannot
# be shown to go red, so its self-test points it at a fixture tree instead.
#
# This runner lives at scripts/, NOT scripts/verify/, so that it cannot glob and
# invoke itself.
set -uo pipefail

die() { printf 'run-ci-gates: %s\n' "$1" >&2; exit 2; }

ROOT=""
QUIET=""
for arg in "$@"; do
    case "$arg" in
        --quiet) QUIET=1 ;;
        # Explicit if, NOT `A && B || C` (SC2015): with that idiom the die fires
        # whenever the assignment is falsy, not only on a second positional.
        -*) die "unknown flag '$arg'" ;;
        *)
            if [ -z "$ROOT" ]; then ROOT="$arg"; else die "unexpected argument '$arg'"; fi
            ;;
    esac
done

if [ -z "$ROOT" ]; then
    ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" \
        || die "not in a git repo and no REPO_ROOT given"
fi
[ -d "$ROOT" ] || die "REPO_ROOT '$ROOT' is not a directory"

say() { [ -n "$QUIET" ] || printf '%s\n' "$1"; }

GATE_DIR="$ROOT/scripts/verify"
[ -d "$GATE_DIR" ] || die "no scripts/verify/ under '$ROOT'"

# ── THE FLOOR ─────────────────────────────────────────────────────────────────
# Globbing enrols new gates for free, and that is the right default — but it also
# means a tree with FEWER gates reports a smaller number and exits 0. A shrink is
# then invisible: nothing states what SHOULD be here, so "ran 4" and "ran 5" are
# both clean and only a cross-tree comparison tells them apart. That is exactly
# how the community extraction shipped a reduced gate set unnoticed.
#
# The registry is a FLOOR, not a manifest. It is one-directional on purpose:
#   * a gate named here that did NOT run as tree-scan is a FINDING — deleted,
#     renamed, or quietly re-declared `# ci-gate: none`.
#   * a gate that ran but is NOT named here is fine (glob enrolment keeps
#     working, and two concurrent gate PRs still do not conflict on this file).
#     It is reported as an advisory so the floor can be raised deliberately.
# A missing registry is UNDETERMINED, never a pass: "there is no floor" and
# "the floor is met" are different answers and must not share an exit code.
#
# An EMPTY registry is UNDETERMINED for the same reason, and it is the more
# likely accident: a failed write, a truncating redirect, a bad sed, a partial
# checkout, or a regeneration step that produced nothing all leave a file with
# no entries. Read as "no gates are required" that is a fail-OPEN inside the
# mechanism built to catch fail-open gate sets — a floor of zero cannot detect
# a shrink, so it must not report that it checked one.
REGISTRY="$ROOT/scripts/ci-gate-registry.txt"
[ -f "$REGISTRY" ] || die "no scripts/ci-gate-registry.txt under '$ROOT' — the gate floor is unreadable, so a shrink cannot be detected"
expected=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && expected+=("$line")
done < "$REGISTRY"
[ "${#expected[@]}" -gt 0 ] \
    || die "scripts/ci-gate-registry.txt names ZERO gates — a floor of zero cannot detect a shrink. Populate it, or the gate set is unverified"

# Globbed, not enumerated — see the header. `nullglob` so an empty directory
# yields an empty array rather than the literal pattern, which would then be
# reported as a missing-marker failure and bury the real cause.
shopt -s nullglob
gates=("$GATE_DIR"/*.sh)
shopt -u nullglob

# Fails closed if the directory is ever empty or the glob stops matching (a
# rename to `*.bash`). A runner that silently runs nothing is the same defect
# class this script exists to catch, so it must not be able to pass that way.
if [ "${#gates[@]}" -eq 0 ]; then
    printf 'run-ci-gates: FATAL — no gates matched %s/*.sh\n' "$GATE_DIR" >&2
    exit 2
fi

# Read the marker from the header. Bounded to the first 80 lines so a `ci-gate:`
# mentioned in prose far down a long file cannot be mistaken for a declaration,
# and anchored at start-of-line so a reference INSIDE another comment sentence
# (this file is full of them) does not match.
marker_of() {
    sed -n '1,80p' "$1" \
        | grep -Eo '^# ci-gate:[[:space:]]*[a-z-]+' \
        | head -1 \
        | sed -E 's/^# ci-gate:[[:space:]]*//'
}

reason_of() {
    sed -n '1,80p' "$1" \
        | grep -Eo '^# ci-gate-reason:[[:space:]]*.+' \
        | head -1 \
        | sed -E 's/^# ci-gate-reason:[[:space:]]*//'
}

unmarked=()
findings=()
undetermined=()
ran_names=()
ran=0
skipped=0

for gate in "${gates[@]}"; do
    name="${gate##*/}"
    marker="$(marker_of "$gate")"

    case "$marker" in
        tree-scan)
            say "── $name"
            # Not `bash "$gate" "$ROOT" || rc=$?` on one line: under `set -e`-less
            # bash that is fine, but capturing rc explicitly keeps the three-state
            # distinction, which a boolean `||` would collapse to "non-zero".
            bash "$gate" "$ROOT"
            rc=$?
            ran=$((ran + 1))
            ran_names+=("$name")
            case "$rc" in
                0) ;;
                1) findings+=("$name") ;;
                *) undetermined+=("$name (exit $rc)") ;;
            esac
            ;;
        none)
            # An exemption must justify itself in place. A bare `none` is how a
            # gate quietly opts out of ever running, which is the thing being
            # prevented — so the reason line is required, not advisory.
            if [ -z "$(reason_of "$gate")" ]; then
                unmarked+=("$name (declared 'none' with no '# ci-gate-reason:' line)")
            else
                skipped=$((skipped + 1))
            fi
            ;;
        "")
            unmarked+=("$name (no '# ci-gate:' marker)")
            ;;
        *)
            unmarked+=("$name (unknown marker '$marker')")
            ;;
    esac
done

say ""
say "run-ci-gates: ran $ran tree-scan gate(s), $skipped exempt, ${#gates[@]} script(s) total."
say "run-ci-gates: floor expects ${#expected[@]} gate(s) from ${REGISTRY#"$ROOT"/}."

# Floor evaluation. A registry entry that did not run is a shrink; report every
# one by name rather than a count, because "ran 4, expected 5" does not say WHICH.
#
# Every array expansion below is guarded on its own length. bash 3.2 — still the
# /bin/bash on macOS, where this runs locally — treats `"${a[@]}"` on an EMPTY
# array as an unbound variable under `set -u`, which aborts mid-run with rc=1:
# a FINDING exit code for a tree that has none.
missing_floor=()
if [ "${#expected[@]}" -gt 0 ]; then
    for want in "${expected[@]}"; do
        seen=0
        if [ "${#ran_names[@]}" -gt 0 ]; then
            for got in "${ran_names[@]}"; do
                [ "$got" = "$want" ] && seen=1
            done
        fi
        [ "$seen" -eq 1 ] || missing_floor+=("$want")
    done
fi
# Advisory only — an unregistered gate is glob-enrolment working as designed.
unregistered=()
if [ "${#ran_names[@]}" -gt 0 ]; then
    for got in "${ran_names[@]}"; do
        listed=0
        if [ "${#expected[@]}" -gt 0 ]; then
            for want in "${expected[@]}"; do
                [ "$got" = "$want" ] && listed=1
            done
        fi
        [ "$listed" -eq 1 ] || unregistered+=("$got")
    done
fi
if [ "${#unregistered[@]}" -gt 0 ]; then
    say "run-ci-gates: note — ran but not on the floor: ${unregistered[*]}"
    say "             (glob enrolment; add to ${REGISTRY##*/} to make them required)"
fi
if [ "${#expected[@]}" -eq 0 ] && [ "$ran" -gt 0 ]; then
    say "run-ci-gates: note — the floor is EMPTY while $ran gate(s) ran; a shrink to"
    say "             zero would not be detected. Populate ${REGISTRY##*/}."
fi

rc=0

if [ "${#missing_floor[@]}" -gt 0 ]; then
    printf 'run-ci-gates: GATE FLOOR NOT MET\n\n' >&2
    printf 'These gates are required by %s but did not run as tree-scan\n' "${REGISTRY#"$ROOT"/}" >&2
    printf 'against this tree — deleted, renamed, or re-declared "# ci-gate: none":\n\n' >&2
    printf '    %s\n' "${missing_floor[@]}" >&2
    printf '\nIf the removal is intended, remove the name from the floor in the SAME\n' >&2
    printf 'change, so the shrink is reviewed rather than discovered.\n' >&2
    rc=1
fi

if [ "${#unmarked[@]}" -gt 0 ]; then
    printf 'run-ci-gates: UNDECLARED GATE(S)\n\n' >&2
    printf 'Every script under scripts/verify/ must declare its CI role in its\n' >&2
    printf 'header, because a gate that nothing runs is the defect this checks for:\n\n' >&2
    printf '    # ci-gate: tree-scan   (runs here; takes REPO_ROOT; 0/1/2 exits)\n' >&2
    printf '    # ci-gate: none        (plus a "# ci-gate-reason:" line saying why)\n\n' >&2
    printf '    %s\n' "${unmarked[@]}" >&2
    rc=1
fi

if [ "${#findings[@]}" -gt 0 ]; then
    printf '\nrun-ci-gates: GATE(S) REPORTED FINDINGS\n\n' >&2
    printf '    %s\n' "${findings[@]}" >&2
    printf '\nRead each gate output above; it names the offending line.\n' >&2
    rc=1
fi

if [ "${#undetermined[@]}" -gt 0 ]; then
    printf '\nrun-ci-gates: GATE(S) COULD NOT MEASURE\n\n' >&2
    printf '    %s\n' "${undetermined[@]}" >&2
    printf '\nThis is NOT a pass. The gate ran but its oracle was unreachable\n' >&2
    printf '(missing tool, unauthenticated gh, failed scan). Resolve the\n' >&2
    printf 'oracle and re-run; do not merge on an unmeasured gate.\n' >&2
    # A finding is more actionable than an undetermined, so 1 wins when both
    # are present: the operator has something concrete to fix either way.
    [ "$rc" -eq 0 ] && rc=2
fi

if [ "$rc" -eq 0 ]; then
    say "run-ci-gates: CLEAN — every enrolled gate ran and passed."
fi

exit "$rc"
