#!/usr/bin/env bash
# ci-gate: none
# ci-gate-reason: range-scoped — it needs the range being pushed or promoted.
#   Invoked by .githooks/pre-push for refs/heads/dev and refs/heads/main, and as
#   its own step for pull requests into main (.github/workflows/test.yml). Its
#   correctness is covered by scripts/tests/landing.test.sh.
#
# Answer ONE question: "does every non-merge commit this push lands on the
# integration branch record where it came from?"
#
# A commit passes when it carries at least one well-formed trailer:
#     Landed-From:    <source-branch>@<40-hex commit id>
#     Landed-Partial: <source-branch>@<40-hex commit id>
#     Landed-From:    direct
# Merge commits are exempt (they record their parents structurally). Commits
# that are ancestors of the cutoff in scripts/landing/trailer-cutoff predate the
# rule and are exempt — that file is the ONE grandfather line, never widened.
#
# USAGE
#   check-trailers.sh <rev-list args>...    e.g. origin/dev..HEAD
#                                           or  <sha> --not --remotes (first push)
#
# EXIT (durable-instruments.md MUST-2)
#   0  every checked commit carries a trailer
#   1  REFUSED — at least one commit lacks one (listed); a hard stop
#   2  UNDETERMINED — the range or the cutoff could not be resolved
set -uo pipefail

if [ $# -eq 0 ]; then
  echo "check-trailers: UNDETERMINED — no revision range given (usage: check-trailers.sh <range>)" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "check-trailers: UNDETERMINED — not inside a git repository" >&2
  exit 2
}
CUTOFF_FILE="${LANDING_TRAILER_CUTOFF_FILE:-$ROOT/scripts/landing/trailer-cutoff}"
CUTOFF=""
if [ -f "$CUTOFF_FILE" ]; then
  CUTOFF="$(grep -Eo '^[0-9a-f]{40}' "$CUTOFF_FILE" | head -1)"
  if [ -z "$CUTOFF" ] || ! git cat-file -e "${CUTOFF}^{commit}" 2>/dev/null; then
    echo "check-trailers: UNDETERMINED — cutoff in $CUTOFF_FILE is not a commit in this repository" >&2
    exit 2
  fi
fi

COMMITS="$(git rev-list --no-merges "$@" 2>/dev/null)" || {
  echo "check-trailers: UNDETERMINED — cannot list commits in '$*'" >&2
  exit 2
}

VALID='^(direct|[^[:space:]]+@[0-9a-f]{40})$'
MISSING=""
CHECKED=0
while IFS= read -r c; do
  [ -z "$c" ] && continue
  if [ -n "$CUTOFF" ]; then
    git merge-base --is-ancestor "$c" "$CUTOFF" 2>/dev/null
    case $? in
      0) continue ;;                      # predates the rule
      1) ;;                               # after the cutoff: must carry a trailer
      *) echo "check-trailers: UNDETERMINED — ancestry of $c against the cutoff failed" >&2; exit 2 ;;
    esac
  fi
  CHECKED=$((CHECKED + 1))
  VALUES="$(git log -1 --format='%(trailers:key=Landed-From,valueonly)%(trailers:key=Landed-Partial,valueonly)' "$c")"
  OK=0
  while IFS= read -r v; do
    v="$(printf '%s' "$v" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$v" ] && continue
    if printf '%s' "$v" | grep -Eq "$VALID"; then OK=1; else OK=0; break; fi
  done <<EOF
$VALUES
EOF
  if [ "$OK" -ne 1 ]; then
    MISSING="${MISSING}  $(git log -1 --format='%h %s' "$c")"$'\n'
  fi
done <<EOF
$COMMITS
EOF

if [ -n "$MISSING" ]; then
  echo "check-trailers: REFUSED — commit(s) without a landing trailer:"
  printf '%s' "$MISSING"
  echo
  echo "Every non-merge commit on the integration branch must record its source."
  echo "  Landing a branch:   bash scripts/landing/land.sh <branch>"
  echo "  A direct commit:    git commit --amend --no-edit --trailer 'Landed-From: direct'"
  echo "                      (the .githooks/commit-msg hook adds this automatically on dev/main)"
  exit 1
fi
echo "check-trailers: OK — $CHECKED commit(s) checked, all carry a landing trailer"
exit 0
