#!/usr/bin/env bash
# ci-gate: none
# ci-gate-reason: an operator action on LOCAL branch refs after a confirmed push;
#   a CI checkout has no local source branches. Covered by
#   scripts/tests/landing.test.sh.
#
# Retire source branches whose landing is CONFIRMED ON THE REMOTE.
#
# It fetches the integration ref, reads the Landed-From / Landed-Partial
# trailers back from the REMOTE copy (scripts/landing/landed-map.sh), and for
# every local branch:
#   - every one of its own commits is recorded as landed  -> delete the branch
#   - some are recorded                                    -> keep it; list the
#                                                             commits still outstanding
#   - none are recorded                                    -> leave it alone
# A branch checked out in a worktree cannot be deleted; it is renamed
# landed/<branch> instead (the worktree follows the rename), and reported.
# Remote copies of retired branches are listed; pass --delete-remote to delete
# them (an outward action, so it is opt-in).
#
# USAGE
#   retire.sh [--remote origin] [--ref dev] [--delete-remote] [--dry-run]
#
# EXIT  0 done · 2 UNDETERMINED (fetch failed or the remote ref is unreadable)
set -uo pipefail

REMOTE="origin"; REF="dev"; DELETE_REMOTE=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --remote) REMOTE="${2:-}"; shift 2 ;;
    --ref) REF="${2:-}"; shift 2 ;;
    --delete-remote) DELETE_REMOTE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "retire: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
git fetch --quiet "$REMOTE" "$REF" 2>/dev/null || { echo "retire: UNDETERMINED — could not fetch $REMOTE/$REF" >&2; exit 2; }
TRACK="refs/remotes/$REMOTE/$REF"
git rev-parse --verify --quiet "$TRACK^{commit}" >/dev/null || { echo "retire: UNDETERMINED — $TRACK does not resolve after fetch" >&2; exit 2; }

MAP="$(bash "$HERE/landed-map.sh" --ref "$TRACK")"; rc=$?
[ "$rc" -eq 0 ] || { echo "retire: UNDETERMINED — landed-map failed (exit $rc)" >&2; exit 2; }
LANDED_SHAS="$(printf '%s\n' "$MAP" | awk -F'\t' 'NF >= 2 { print $2 }' | sort -u)"

CURRENT="$(git symbolic-ref --quiet --short HEAD || true)"
retired=0; partial=0
while IFS= read -r b; do
  case "$b" in ""|dev|main|landed/*) continue ;; esac
  own="$(git rev-list --no-merges "$TRACK..refs/heads/$b" 2>/dev/null)" || continue
  [ -z "$own" ] && continue          # nothing of its own beyond the integration ref
  total=0; done_n=0; outstanding=""
  while IFS= read -r c; do
    [ -z "$c" ] && continue
    total=$((total + 1))
    if printf '%s\n' "$LANDED_SHAS" | grep -qx "$c"; then done_n=$((done_n + 1)); else outstanding="$outstanding    $(git log -1 --format='%h %s' "$c")"$'\n'; fi
  done <<EOF
$own
EOF
  [ "$done_n" -eq 0 ] && continue
  if [ "$done_n" -lt "$total" ]; then
    partial=$((partial + 1))
    echo "PARTIAL  $b — $done_n of $total commit(s) landed; kept. Outstanding:"
    printf '%s' "$outstanding"
    continue
  fi
  retired=$((retired + 1))
  in_worktree="$(git worktree list --porcelain | awk -v r="refs/heads/$b" '$1 == "branch" && $2 == r { print "yes" }')"
  if [ "$DRY" -eq 1 ]; then
    echo "LANDED   $b — all $total commit(s) recorded on $REMOTE/$REF (dry run: not retired)"
  elif [ "$b" = "$CURRENT" ] || [ -n "$in_worktree" ]; then
    git branch -m "$b" "landed/$b" && echo "LANDED   $b — checked out, so renamed to landed/$b"
  else
    git branch -D "$b" >/dev/null && echo "LANDED   $b — all $total commit(s) recorded on $REMOTE/$REF; branch deleted"
  fi
  if git rev-parse --verify --quiet "refs/remotes/$REMOTE/$b" >/dev/null; then
    if [ "$DELETE_REMOTE" -eq 1 ] && [ "$DRY" -eq 0 ]; then
      git push --quiet "$REMOTE" --delete "$b" && echo "         remote $REMOTE/$b deleted"
    else
      echo "         remote $REMOTE/$b still exists (re-run with --delete-remote to delete it)"
    fi
  fi
done <<EOF
$(git for-each-ref --format='%(refname:short)' refs/heads)
EOF

echo "retire: $retired branch(es) fully landed, $partial partly landed (kept)."
exit 0
