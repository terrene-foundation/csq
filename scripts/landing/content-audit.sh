#!/usr/bin/env bash
# ci-gate: none
# ci-gate-reason: a ONE-TIME clean-up for branches that predate the landing
#   trailers (scripts/landing/). After the trailer rule is live, "has this
#   branch landed?" is answered by scripts/landing/landed-map.sh, never by this.
#
# For each branch that predates the fix, decide by CONTENT whether it landed on
# the integration branch — never by commit id or patch-id, both of which change
# when landing rebases, squashes or conflict-fixes.
#
# For every file the branch's OWN commits changed (merge-base..branch):
#   - skip the file ONLY if the integration branch DELETED it after the fork
#     (not counted as "added by the branch"); a file it never had counts, and
#     its added lines are simply absent;
#   - take the lines the branch ADDED to it (net diff merge-base..branch);
#   - check each is present in the integration branch's current copy.
# Lines whose trimmed text is shorter than 4 characters, or holds no letter or
# digit ("}", "", "});", "-----"), are not evidence either way and are ignored:
# such lines exist everywhere, and counting them made an unlanded branch read
# "partly landed" (474 of 33,066 lines in a sibling repo's audit).
#
# Verdict per branch:  landed (all added lines present, or every commit is
# already an ancestor of the integration branch) · partly (some) ·
# not-landed (none) · no-content (nothing countable, e.g. only deletions or
# only files the integration branch removed).
#
# USAGE
#   content-audit.sh [--ref origin/dev] [--include-remote]
# OUTPUT  TSV: branch <TAB> verdict <TAB> present/total added lines <TAB> files
# EXIT    0 printed · 2 UNDETERMINED (the integration ref does not resolve)
set -uo pipefail

REF="origin/dev"; INCLUDE_REMOTE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:-}"; shift 2 ;;
    --include-remote) INCLUDE_REMOTE=1; shift ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "content-audit: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
git rev-parse --verify --quiet "$REF^{commit}" >/dev/null || { echo "content-audit: UNDETERMINED — '$REF' does not resolve" >&2; exit 2; }

branches() {
  git for-each-ref --format='%(refname)' refs/heads
  [ "$INCLUDE_REMOTE" -eq 1 ] && git for-each-ref --format='%(refname)' refs/remotes
}

printf 'branch\tverdict\tpresent/total\tfiles\n'
while IFS= read -r ref; do
  short="${ref#refs/heads/}"; short="${short#refs/remotes/}"
  case "$short" in dev|main|*/HEAD|*/dev|*/main|landed/*) continue ;; esac
  mb="$(git merge-base "$REF" "$ref" 2>/dev/null)" || { printf '%s\tundetermined\t-\tno merge-base\n' "$short"; continue; }
  if [ -z "$(git rev-list --no-merges -1 "$mb..$ref")" ]; then
    # every commit already reachable from the integration branch
    printf '%s\tlanded\t(ancestor)\t-\n' "$short"; continue
  fi
  total=0; present=0; nfiles=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if git cat-file -e "$REF:$f" 2>/dev/null; then
      target="$(git show "$REF:$f" 2>/dev/null)"
    elif [ -n "$(git log --format=%H -1 --diff-filter=D "$mb..$REF" -- "$f")" ]; then
      continue      # the integration branch DELETED it after the fork: not evidence either way
    else
      target=""     # never on the integration branch: its added lines are absent
    fi
    nfiles=$((nfiles + 1))
    while IFS= read -r line; do
      t="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      [ "${#t}" -lt 4 ] && continue
      case "$t" in *[[:alnum:]]*) ;; *) continue ;; esac   # punctuation-only: not evidence
      total=$((total + 1))
      if printf '%s\n' "$target" | grep -qxF -- "$line"; then present=$((present + 1)); fi
    done <<EOF
$(git diff --no-color --unified=0 "$mb" "$ref" -- "$f" | sed -n 's/^+\([^+]\)/\1/p; s/^+$//p' | grep -v '^++' )
EOF
  done <<EOF
$(git diff --name-only --diff-filter=AMR "$mb" "$ref")
EOF
  if [ "$total" -eq 0 ]; then v="no-content"
  elif [ "$present" -eq "$total" ]; then v="landed"
  elif [ "$present" -eq 0 ]; then v="not-landed"
  else v="partly"; fi
  printf '%s\t%s\t%s/%s\t%s\n' "$short" "$v" "$present" "$total" "$nfiles"
done <<EOF
$(branches)
EOF
