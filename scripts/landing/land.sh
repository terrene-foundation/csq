#!/usr/bin/env bash
# ci-gate: none
# ci-gate-reason: an operator action that rewrites the local integration branch,
#   not a check. Its correctness is covered by scripts/tests/landing.test.sh.
#
# Land a source branch onto the integration branch AND record where each landed
# commit came from, at landing time.
#
# Landing re-applies the branch's commits (cherry-pick), so they get NEW commit
# ids — after that, nothing can reliably tell by comparison which branch they
# came from. So every landed commit carries a trailer naming its source:
#     Landed-From:    <branch>@<40-hex source commit>   (whole branch landed)
#     Landed-Partial: <branch>@<40-hex source commit>   (--only: part of it)
# Trailers are added with `git interpret-trailers`, never by hand-editing.
#
# USAGE (run on a clean checkout of the integration branch, e.g. dev)
#   land.sh <branch>                     land every commit of <branch> not on HEAD
#   land.sh <branch> --only <sha>...     land just these commits (Landed-Partial)
#   land.sh --continue                   after resolving a conflict, carry on
#   land.sh --abort                      abandon an in-progress landing
#
# After landing: run the pre-push checks, push, then retire the branch:
#   node scripts/ci/dev-preflight.mjs && git push origin dev
#   bash scripts/landing/retire.sh            # reads the pushed ref back
#
# EXIT  0 landed · 1 refused or conflict (state kept for --continue) · 2 usage
set -uo pipefail

die() { echo "land: $*" >&2; exit "${EXIT:-1}"; }

GIT_DIR_ABS="$(git rev-parse --absolute-git-dir 2>/dev/null)" || { EXIT=2 die "not inside a git repository"; }
STATE="$GIT_DIR_ABS/landing-state"

# Apply one source commit onto HEAD with its provenance trailer. On conflict,
# leave the index for the operator and return 1.
apply_one() {
  local branch="$1" sha="$2" key="$3" msgfile
  if ! git cherry-pick --no-commit "$sha" >/dev/null 2>&1; then
    if [ -z "$(git diff --name-only --diff-filter=U)" ] && git diff --cached --quiet; then
      :   # nothing to apply (already present) — recorded as an empty landing below
    else
      echo "land: CONFLICT applying ${sha:0:12} from '$branch'."
      echo "  Resolve the files git lists, 'git add' them, then run:"
      echo "    bash scripts/landing/land.sh --continue"
      return 1
    fi
  fi
  commit_one "$branch" "$sha" "$key"
}

commit_one() {
  local branch="$1" sha="$2" key="$3" msgfile
  msgfile="$(mktemp)"
  git log -1 --format='%B' "$sha" \
    | git interpret-trailers --trailer "$key: $branch@$sha" > "$msgfile"
  GIT_AUTHOR_NAME="$(git log -1 --format='%an' "$sha")" \
  GIT_AUTHOR_EMAIL="$(git log -1 --format='%ae' "$sha")" \
  GIT_AUTHOR_DATE="$(git log -1 --format='%aI' "$sha")" \
    git commit --quiet --allow-empty -F "$msgfile" || { rm -f "$msgfile"; return 1; }
  rm -f "$msgfile"
  echo "  landed ${sha:0:12} -> $(git rev-parse --short HEAD)  ($key: $branch@${sha:0:12}…)"
}

run_queue() {
  # STATE: line1 branch, line2 trailer key, remaining lines = queued shas
  local branch key sha
  branch="$(sed -n 1p "$STATE")"; key="$(sed -n 2p "$STATE")"
  while :; do
    sha="$(sed -n 3p "$STATE")"
    [ -z "$sha" ] && break
    apply_one "$branch" "$sha" "$key" || exit 1
    sed -i.bak 3d "$STATE" && rm -f "$STATE.bak"
  done
  rm -f "$STATE"
  echo "land: done — '$branch' landed onto $(git rev-parse --abbrev-ref HEAD) with $key trailers."
  echo "Next: pre-push checks, push, then: bash scripts/landing/retire.sh"
}

case "${1:-}" in
  "" | -h | --help) sed -n '2,32p' "$0"; exit 2 ;;
  --abort)
    [ -f "$STATE" ] || die "no landing in progress"
    git cherry-pick --abort >/dev/null 2>&1 || git reset --merge >/dev/null 2>&1
    rm -f "$STATE"; echo "land: aborted (commits already landed in this run stay on HEAD)"; exit 0 ;;
  --continue)
    [ -f "$STATE" ] || die "no landing in progress"
    [ -z "$(git diff --name-only --diff-filter=U)" ] || die "unresolved conflicts remain — resolve and 'git add' them first"
    branch="$(sed -n 1p "$STATE")"; key="$(sed -n 2p "$STATE")"; sha="$(sed -n 3p "$STATE")"
    commit_one "$branch" "$sha" "$key" || exit 1
    sed -i.bak 3d "$STATE" && rm -f "$STATE.bak"
    run_queue; exit 0 ;;
esac

[ -f "$STATE" ] && die "a landing is already in progress — run --continue or --abort"
BRANCH="$1"; shift
git rev-parse --verify --quiet "refs/heads/$BRANCH^{commit}" >/dev/null \
  || git rev-parse --verify --quiet "$BRANCH^{commit}" >/dev/null \
  || { EXIT=2 die "source branch '$BRANCH' does not resolve"; }
case "$BRANCH" in dev|main|origin/dev|origin/main) EXIT=2 die "'$BRANCH' is an integration branch, not a source branch" ;; esac
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "working tree has uncommitted changes — commit or stash them first"

KEY="Landed-From"
if [ "${1:-}" = "--only" ]; then
  shift
  [ $# -gt 0 ] || { EXIT=2 die "--only needs at least one commit"; }
  KEY="Landed-Partial"
  SHAS=""
  for s in "$@"; do
    full="$(git rev-parse --verify --quiet "$s^{commit}")" || { EXIT=2 die "commit '$s' does not resolve"; }
    git merge-base --is-ancestor "$full" "$BRANCH" || { EXIT=2 die "${s} is not on '$BRANCH'"; }
    SHAS="$SHAS$full"$'\n'
  done
  # land them in branch order
  SHAS="$(git rev-list --reverse --no-merges HEAD.."$BRANCH" | grep -Fx -f <(printf '%s' "$SHAS"))"
else
  SHAS="$(git rev-list --reverse --no-merges HEAD.."$BRANCH")"
fi
[ -n "$SHAS" ] || die "nothing to land: every commit of '$BRANCH' is already on HEAD by id"

{ printf '%s\n%s\n' "$BRANCH" "$KEY"; printf '%s\n' "$SHAS"; } > "$STATE"
echo "land: landing $(printf '%s\n' "$SHAS" | grep -c .) commit(s) from '$BRANCH' onto $(git rev-parse --abbrev-ref HEAD) ($KEY)"
run_queue
