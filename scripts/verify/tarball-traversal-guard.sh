#!/usr/bin/env bash
# ci-gate: none
# ci-gate-reason: needs a built tarball; driven by its self-test and invoked by
#   release.yml inside the macOS packaging step, where the artifact exists.
#
# tarball-traversal-guard.sh — refuse a tarball containing absolute-path or
# `..` traversal entries BEFORE it is extracted.
#
# WHY THIS IS A SCRIPT, NOT AN INLINE `tar tzf … | grep -q`  # pipefail-ok: prose quoting the refused form
# ---------------------------------------------------------
# The guard used to be
#
#     if tar tzf X | grep -qE '(^|/)\.\.($|/)|^/'; then  refuse  fi  # pipefail-ok: prose quoting the refused form
#
# under `set -euo pipefail`. grep -q exits at its FIRST match; tar takes
# SIGPIPE; the pipeline reports 141; the `if` is FALSE — on exactly the input
# the guard exists to refuse. And a hostile archive controls entry order, so
# the attacker can put `../` first and steer the guard into the fail-open arm
# deterministically (it is not a timing race).
#
# The listing is therefore CAPTURED with tar's own status checked, and the
# traversal count is taken with `grep -c` (a whole-input reader, so no SIGPIPE
# and no tempfile) and validated as an integer before it is compared.
#
# EXIT CODES
#   0  PASS          — the archive lists and has ZERO traversal entries
#   1  FAIL          — traversal entries found (each printed to stderr)
#   2  UNDETERMINED  — tar cannot list the archive, or the count is unreadable
#
# Usage: tarball-traversal-guard.sh <tarball> [max-listed]

set -uo pipefail

TARBALL="${1-}"
MAX_LISTED="${2:-10}"
[ -n "$TARBALL" ] || { echo "tarball-traversal-guard: usage: $0 <tarball> [max-listed]" >&2; exit 2; }
[ -f "$TARBALL" ] || { echo "tarball-traversal-guard: UNDETERMINED — '$TARBALL' is not a file" >&2; exit 2; }
case "$MAX_LISTED" in
    '' | *[!0-9]*) echo "tarball-traversal-guard: UNDETERMINED — max-listed '$MAX_LISTED' is not an integer" >&2; exit 2 ;;
esac

if ! listing="$(tar tzf "$TARBALL" 2>/dev/null)"; then
    echo "tarball-traversal-guard: UNDETERMINED — cannot list $TARBALL (unreadable or truncated); refusing to extract an unmeasured archive" >&2
    exit 2
fi

# grep -c reads its WHOLE input, so the producer cannot be SIGPIPE'd; the count
# is validated as an integer before the comparison (an empty capture is not 0).
count="$(printf '%s\n' "$listing" | grep -cE '(^|/)\.\.($|/)|^/' 2>/dev/null || true)"
case "$count" in
    '' | *[!0-9]*)
        echo "tarball-traversal-guard: UNDETERMINED — could not count traversal entries in $TARBALL" >&2
        exit 2 ;;
    0) exit 0 ;;
esac

echo "tarball-traversal-guard: $count traversal entr(y|ies) in $TARBALL:" >&2
printf '%s\n' "$listing" | grep -E '(^|/)\.\.($|/)|^/' | sed -n "1,${MAX_LISTED}p" >&2
exit 1
