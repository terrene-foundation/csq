#!/usr/bin/env bash
# gh-free-path.sh — build a PATH that PROVABLY lacks `gh`, for self-tests that
# exercise a gate's "oracle unreachable -> UNDETERMINED" branch.
#
# WHY THIS EXISTS (2026-08-13). Three self-tests simulated "gh is absent" with:
#
#     PATH="$TMPROOT/emptybin:/usr/bin:/bin" "$SCRIPT" ... ; rc=$?
#     check "no gh -> undetermined" 2 "$rc"
#
# That is not hermetic, and the failure is PLATFORM-DEPENDENT:
#
#   * macOS dev box  — Homebrew puts gh at /opt/homebrew/bin/gh, which the
#                      constructed PATH excludes, so gh really is absent
#                      and the case measures what it claims to.  PASSES.
#   * Linux CI       — gh is at /usr/bin/gh, which the constructed PATH
#                      INCLUDES. gh is still reachable, the gate queries the
#                      real API, and returns a determinate verdict.  FAILS.
#
# `milestone-refs.test.sh` failed exactly this way on every Linux runner while
# passing for every developer locally. The other two consumers of the same
# pattern did NOT fail — which is worse: they were returning the expected exit
# code while `gh` was still on PATH, i.e. passing for the wrong reason. A test
# that cannot reach the branch it names certifies nothing about it
# (`instrument-discipline.md` MUST-2).
#
# The fix is a symlink farm rather than a subtractive PATH: name the tools the
# script under test needs, link exactly those, and let absence be structural.
# Subtracting a directory cannot work portably, because on Linux the directory
# holding `gh` is the same one holding `grep`.

# Build an isolated bin dir containing ONLY the named tools, and echo it.
#
# $1        — directory to create (caller-owned; typically under a TMPROOT)
# $2..$n    — tool names to link in. `gh` is refused outright: linking it would
#             defeat the entire purpose, and a caller asking for it has
#             misunderstood what this function is for.
#
# Tools not found on the current PATH are skipped silently — the caller asserts
# reachability of what it actually needs via gh_free_path_assert_absent plus its
# own passing cases.
gh_free_path_build() {
    local bindir="$1"
    shift
    mkdir -p "$bindir"

    local tool src
    for tool in "$@"; do
        if [ "$tool" = "gh" ]; then
            printf 'gh_free_path_build: refusing to link gh -- that defeats the isolation\n' >&2
            return 2
        fi
        src="$(command -v "$tool" 2>/dev/null)" || continue
        [ -n "$src" ] || continue
        ln -sf "$src" "$bindir/$tool"
    done

    printf '%s\n' "$bindir"
}

# Assert `gh` is genuinely unreachable under $1, or abort the whole self-test.
#
# This is the load-bearing half. Without it, a future change that reintroduces a
# reachable `gh` turns the "oracle unreachable" case back into a silent
# false-pass — the exact regression this file was written to end. Failing loudly
# is correct: a self-test that cannot construct its own precondition has not run
# that case, and reporting it as passed would be a lie
# (`durable-instruments.md` MUST-2 — "could not measure" is never "pass").
gh_free_path_assert_absent() {
    local isolated="$1"
    if PATH="$isolated" command -v gh >/dev/null 2>&1; then
        printf 'FATAL: gh is still reachable under the isolated PATH (%s).\n' "$isolated" >&2
        printf '       The oracle-unreachable case CANNOT run; refusing to report it as passed.\n' >&2
        return 1
    fi
    return 0
}
