#!/usr/bin/env bash
# ci-gate: none
# ci-gate-reason: a lookup, not a gate — it answers "has branch X landed?" for
#   other tools (retire.sh, orphan-branch-drift.sh). Its correctness is covered
#   by scripts/tests/landing.test.sh, which the self-test glob collects.
#
# Answer ONE question by LOOKUP, never by comparison: "which commits on the
# integration branch record that they landed FROM branch X?"
#
# Every commit that lands on the integration branch carries one git trailer per
# source commit (see scripts/landing/land.sh):
#     Landed-From:    <source-branch>@<40-hex source commit>
#     Landed-Partial: <source-branch>@<40-hex source commit>
#     Landed-From:    direct            (made directly on the integration branch)
# This script reads those trailers straight out of `git log`. Commit ids and
# patch-ids change when landing rebases, squashes or conflict-fixes a commit;
# the trailer does not, which is why nothing here compares content.
#
# USAGE
#   landed-map.sh [--ref <integration-ref>]            print the whole map
#   landed-map.sh [--ref <ref>] --branch <name>        answer for one branch
#
# OUTPUT (TSV, one row per trailer; `direct` rows are omitted):
#   <source-branch> <TAB> <source-sha> <TAB> <landed-commit> <TAB> full|partial
#
# EXIT (durable-instruments.md MUST-2 — three outcomes, never folded)
#   0  map printed / branch has at least one Landed-From row
#   1  --branch: the branch has NO row (not recorded as landed)
#   3  --branch: only Landed-Partial rows (partly landed)
#   2  UNDETERMINED — the integration ref does not resolve or git failed
#
# A branch that predates the trailer rule has no rows: callers fall back to
# content comparison ONLY for such branches (scripts/landing/content-audit.sh).
set -uo pipefail

REF="dev"
BRANCH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:-}"; shift 2 ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "landed-map: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

if ! git rev-parse --verify --quiet "${REF}^{commit}" >/dev/null; then
  echo "landed-map: UNDETERMINED — integration ref '$REF' does not resolve" >&2
  exit 2
fi

# %x1e ends each commit record; within a record %x1f separates the fields and
# newlines separate multiple values of one trailer key. (Not NUL: BSD awk on
# macOS cannot split on NUL.)
LOG="$(git log "$REF" --format='%H%x1f%(trailers:key=Landed-From,valueonly)%x1f%(trailers:key=Landed-Partial,valueonly)%x1e')" || {
  echo "landed-map: UNDETERMINED — git log $REF failed" >&2
  exit 2
}

MAP="$(printf '%s' "$LOG" | awk -v RS='\036' -v FS='\037' '
  function emit(values, kind,   n, i, j, v, at, br, sha, vs) {
    n = split(values, vs, "\n")
    for (i = 1; i <= n; i++) {
      v = vs[i]; gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", v)
      if (v == "" || v == "direct") continue
      at = 0
      for (j = length(v); j > 0; j--) if (substr(v, j, 1) == "@") { at = j; break }
      if (at == 0) { printf "landed-map: malformed trailer on %s: %s\n", commit, v > "/dev/stderr"; continue }
      br = substr(v, 1, at - 1); sha = substr(v, at + 1)
      if (br == "" || sha !~ /^[0-9a-f]{40}$/) { printf "landed-map: malformed trailer on %s: %s\n", commit, v > "/dev/stderr"; continue }
      printf "%s\t%s\t%s\t%s\n", br, sha, commit, kind
    }
  }
  {
    commit = $1; gsub(/^[\n]+/, "", commit)
    if (commit == "") next
    emit($2, "full"); emit($3, "partial")
  }')"

if [ -z "$BRANCH" ]; then
  [ -n "$MAP" ] && printf '%s\n' "$MAP"
  exit 0
fi

ROWS="$(printf '%s\n' "$MAP" | awk -F'\t' -v b="$BRANCH" '$1 == b')"
if [ -z "$ROWS" ]; then
  exit 1
fi
printf '%s\n' "$ROWS"
if printf '%s\n' "$ROWS" | awk -F'\t' '$4 == "full" { found = 1 } END { exit !found }'; then
  exit 0
fi
exit 3
