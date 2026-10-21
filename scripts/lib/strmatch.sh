#!/usr/bin/env bash
#
# strmatch.sh — in-memory membership and match testing for shell scripts.
# Source it; do not execute it.
#
# WHY THIS EXISTS
# ---------------
# A "does this captured value contain X" test written as
#
#     printf '%s' "$hay" | grep -qF -- "$needle"  # pipefail-ok: prose quoting the refused form
#
# fails under `set -o pipefail`: grep -q exits at its first match, printf takes
# SIGPIPE, and the PIPELINE reports 141 — so a PRESENT needle reads ABSENT
# wherever the status is read. The window is not limited to large inputs: a
# multi-write producer can be signalled under load at under 1 KiB (measured: a
# flake at 786 B with four suites running; deterministic above the pipe
# buffer). The usual workaround, `grep -qF -- "$needle" <<< "$hay"`, removes
# the SIGPIPE but is a TEMPFILE in bash 3.2 (and above PIPE_BUF in newer bash):
# when the temp file cannot be created, bash does not run grep and the command
# exits 1 — byte-for-byte grep's "no match" — which fails OPEN wherever
# no-match is the PASS verdict. That failure is latent, not reproduced on this
# host (TMPDIR=/dev/null still answers on bash 3.2); the realistic trigger is a
# full disk. Neither shape is safe on a gate.
#
# THE TWO SHAPES
# --------------
# FIXED tests (exact whole line, fixed substring) are bash builtins — one
# pattern match, linear, no child, no disk:
#
#     [[ $'\n'"$hay"$'\n' == *$'\n'"$needle"$'\n'* ]]   exact whole line
#     [[ $hay == *"$needle"* ]]                          fixed substring
#
#   The needle is QUOTED, so `*`, `?` and `[` in it are literal, and the
#   newline anchors stop `/x/foo` matching a line `/x/foo-2`.
#
# REGEX tests go through `grep -c -E`, a WHOLE-INPUT reader:
#
#     n=$(printf '%s\n' "$hay" | grep -c -E -- "$re")
#
#   grep -c consumes every line, so no early exit, no SIGPIPE, no tempfile, and
#   the cost is linear (the previous per-line bash loop copied the remaining
#   haystack once per line: 287 s at 8,000 lines on bash 3.2; the count reader
#   is measured in the self-test). It also keeps grep's ERE DIALECT: `\b`,
#   `\s`, `\w` and back-references behave exactly as they did in the pipelines
#   these helpers replaced, instead of differing between macOS (BSD regex) and
#   Linux (glibc). The COUNT must parse as an integer; grep's rc must be 0 or
#   1 (match / no match). Anything else — grep could not run, an invalid ERE —
#   is rc 2, UNKNOWN, never "no match".
#
# EMPTY NEEDLE OR PATTERN => rc 2 (UNKNOWN) with a line on stderr. It is never
# reported as "no match": an empty needle is a caller bug, and its correct
# answer is "I cannot tell", not "absent".
#
# BASH 3.2 — this file must run on macOS's /bin/bash 3.2.57: no associative
# arrays, no `mapfile`, no `${var,,}`, ERE only. `scripts/tests/strmatch.test.sh`
# runs under /bin/bash on darwin for exactly this reason.
#
# This is the ONE implementation of these tests; do not re-inline them.

# strmatch_line_contains HAYSTACK NEEDLE
#   rc 0 iff NEEDLE is a COMPLETE line of HAYSTACK (exact bytes, no regex).
strmatch_line_contains() {
    [ -n "${2-}" ] || { echo "strmatch_line_contains: empty needle — cannot answer" >&2; return 2; }
    case ${2-} in *$'\n'*) echo "strmatch_line_contains: multi-line needle is not one line" >&2; return 2 ;; esac
    [[ $'\n'"${1-}"$'\n' == *$'\n'"${2-}"$'\n'* ]]
}

# strmatch_contains HAYSTACK NEEDLE
#   rc 0 iff NEEDLE is a substring of HAYSTACK (fixed string, any line).
strmatch_contains() {
    [ -n "${2-}" ] || { echo "strmatch_contains: empty needle — cannot answer" >&2; return 2; }
    [[ ${1-} == *"${2-}"* ]]
}

# _strmatch_grep_count FLAGS HAYSTACK ERE
#   Prints the line count from a whole-input grep, or returns 2 (UNKNOWN) when
#   grep's status or its output cannot be trusted.
_strmatch_grep_count() {
    local __sm_hay="${2-}" __sm_re="$3" __sm_n __sm_rc
    local -a __sm_flags=()
    if [ -n "${1-}" ]; then read -r -a __sm_flags <<< "$1"; fi
    __sm_n="$(printf '%s\n' "$__sm_hay" | grep -c ${__sm_flags[@]+"${__sm_flags[@]}"} -- "$__sm_re")" && __sm_rc=0 || __sm_rc=$?
    case "$__sm_rc" in 0 | 1) ;; *) return 2 ;; esac
    case "$__sm_n" in '' | *[!0-9]*) return 2 ;; esac
    printf '%s\n' "$__sm_n"
}

# strmatch_regex HAYSTACK ERE
#   rc 0 iff ANY LINE of HAYSTACK matches ERE (grep's ERE dialect).
strmatch_regex() {
    [ -n "${2-}" ] || { echo "strmatch_regex: empty pattern — cannot answer" >&2; return 2; }
    local __sm_n
    __sm_n="$(_strmatch_grep_count "-E" "${1-}" "$2")" || return 2
    [ "$__sm_n" -gt 0 ]
}

# strmatch_regex_i HAYSTACK ERE
#   Case-insensitive strmatch_regex (the `grep -i` form).
strmatch_regex_i() {
    [ -n "${2-}" ] || { echo "strmatch_regex_i: empty pattern — cannot answer" >&2; return 2; }
    local __sm_n
    __sm_n="$(_strmatch_grep_count "-E -i" "${1-}" "$2")" || return 2
    [ "$__sm_n" -gt 0 ]
}

# strmatch_regex_not HAYSTACK ERE
#   rc 0 iff SOME LINE of HAYSTACK does NOT match ERE (the `grep -Ev …` test).
strmatch_regex_not() {
    [ -n "${2-}" ] || { echo "strmatch_regex_not: empty pattern — cannot answer" >&2; return 2; }
    local __sm_n
    __sm_n="$(_strmatch_grep_count "-E -v" "${1-}" "$2")" || return 2
    [ "$__sm_n" -gt 0 ]
}

# strmatch_count_lines HAYSTACK ERE
#   Prints the number of lines matching ERE; rc 2 (no output) when UNKNOWN.
strmatch_count_lines() {
    [ -n "${2-}" ] || { echo "strmatch_count_lines: empty pattern — cannot answer" >&2; return 2; }
    _strmatch_grep_count "-E" "${1-}" "$2"
}

# strmatch_count_nonempty HAYSTACK
#   Prints the number of NON-EMPTY lines (the builtin `grep -c .`). This is the
#   count consumed in arithmetic: it always prints an integer, so an
#   unreadable capture cannot become `[ "" -eq 0 ]` (an integer-expression
#   error that reads as FALSE — how "could not count" became "not zero").
strmatch_count_nonempty() {
    local __sm_hay="${1-}" __sm_n __sm_rc
    __sm_n="$(printf '%s\n' "$__sm_hay" | grep -c .)" && __sm_rc=0 || __sm_rc=$?
    case "$__sm_rc" in 0 | 1) ;; *) return 2 ;; esac
    case "$__sm_n" in '' | *[!0-9]*) return 2 ;; esac
    printf '%s\n' "$__sm_n"
}
