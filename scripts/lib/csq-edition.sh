#!/usr/bin/env bash
#
# csq-edition.sh — answer "which csq edition is installed at this path?", and
# be able to say "I cannot tell".
#
# # Why this exists
#
# `rules/edition-safe-install.md` MUST-1 makes "preserve the installed edition"
# structural: the installer reads what is on disk and rebuilds to match, rather
# than defaulting to whichever edition the operator's shell history last used.
# Every part of that rests on ONE question — which edition is installed? — and
# the original implementation had no way to answer "I don't know".
#
# It returned the empty string for BOTH of these:
#
#   (a) nothing is installed there                  -> a legitimately fresh host
#   (b) something IS installed and cannot be run
#         - SIGKILL 137 from macOS Gatekeeper provenance (the failure mode a
#           `cp` over the installed binary produces),
#         - a truncated or corrupt file, a broken signature,
#         - a wrong-architecture build, a missing dynamic loader,
#         - a symlink whose target is gone,
#         - a `--version` that prints a shape nobody recognises.
#
# Case (b) then took case (a)'s path, and the consequences chained:
#
#   1. edition resolution fell through to EDITION="community";
#   2. the enterprise->community downgrade guard was skipped, because it tests
#      INSTALLED_EDITION = "enterprise" and the string was empty;
#   3. a COMMUNITY build was installed over an ENTERPRISE host;
#   4. the post-install check compared the new binary against the edition the
#      script had just guessed, matched, and printed
#      "Verified: installed edition = community".
#
# The script verified its own wrong choice. That is not hypothetical: it
# downgraded the maintainer's host on 2026-08-02, silently dropping the
# direct-API moat, the licensing gate and the kailash trust plane — none of
# which announce their absence.
#
# So detection here is TRI-state, and the third state is loud:
#
#   determinate   -> prints `enterprise` | `community` | `absent`, returns 0
#   indeterminate -> prints NOTHING, writes a diagnostic to stderr, returns 1
#
# `absent` is a POSITIVELY CONFIRMED nonexistence, not merely a failed stat:
# see `_csq_edition_confirm_absent` for why a failed `-e`/`-L` alone is not
# enough (it also fails on a permission-denied ancestor, a stale mount, or a
# non-directory in the path -- none of which mean "nothing is installed").
#
# `absent` is deliberately a WORD rather than an empty string: the caller has to
# name the fresh-host case to act on it, so the case cannot be re-entered by
# accident the way an empty string was.
#
# # Why stdout is empty when indeterminate
#
# The same reason `cargo-target-dir.sh` prints nothing when cargo fails: a
# caller that forgets to check the status must not be able to consume something
# that looks like an answer. `$(csq_detect_edition …)` with an unchecked status
# yields "", and every consumer's own "is this a known edition" validation then
# rejects it — which is the direction we want to fail in.
#
# # Usage
#
#   . "$REPO_ROOT/scripts/lib/csq-edition.sh"
#   if edition="$(csq_detect_edition "$bin")"; then …; else …; fi
#   csq_resolve_edition "$bin" || exit $?     # sets CSQ_RESOLVED_EDITION etc.
#
# Origin: 2026-08-02 — a fail-OPEN edition detection downgraded an enterprise
# host to community and reported the downgrade as verified.

# How much of a binary's `--version` output may be echoed back to the operator.
#
# Two outcomes have to stay far away from this number, in opposite directions:
#
#   - a legitimate but UNRECOGNISED version line, which the operator must see
#     in full in order to act on it. The real line is
#     `csq 2.17.1 (enterprise)` = 23 characters; a future form carrying a git
#     SHA, a build date and a target triple still lands under ~120.
#   - RUNAWAY output from a corrupt or wrong-architecture binary, which can be
#     megabytes of noise and must not reach the terminal at all.
#
# 200 sits ~80 characters above the plausible-legitimate ceiling (so no real
# version line is ever cut) and roughly four orders of magnitude below the
# runaway case (so no runaway output is ever printed whole). Only the FIRST
# line is echoed, for the same reason: a legitimate `--version` is one line.
CSQ_EDITION_ECHO_MAX_CHARS=200

# How long a `--version` call is given to answer before it is killed.
#
# Two outcomes this has to separate, and there is no plausible middle ground:
#
#   - a HEALTHY call, WARM. Measured against the real installed enterprise
#     binary on this machine (csq 2.18.0), ten consecutive runs via a
#     monotonic Python timer: 3.7-4.8ms. A version-string print and exit --
#     no network, no disk beyond pages the binary already has resident.
#   - a HEALTHY call, COLD -- the case this bound is ACTUALLY sized against,
#     and the one the pre-2026-08-09 derivation missed. `dev-install.sh`
#     read-back always runs on a binary that was JUST codesigned and has
#     NEVER been executed, so macOS performs a full signature verification of
#     the ~21MB Mach-O on that first exec. Measured 2026-08-09 by re-signing
#     a copy (which invalidates the verification cache) and timing the first
#     run on an IDLE machine: **498ms**, with the next three runs at
#     5.0/6.3/6.4ms. That is ~100x the warm figure, and it is the NORMAL
#     path for this function's primary caller, not a pathological one.
#   - a HUNG call. `csq/src/mode.rs::check_bundle_sentinel` runs BEFORE the
#     tty guard and canonicalizes `current_exe()` -- so a CLI-path symlink
#     into the .app resolves back into Desktop mode and enters the Tauri
#     event loop. There is no code path back out of that loop for a
#     `--version` invocation: it does not return SLOWLY, it does not return
#     AT ALL until something outside the process kills it.
#
# Why 30000 and not the previous 5000. The old value was derived as "~1000x
# the measured healthy figure" against the WARM number (4ms). Against the
# COLD number (498ms) -- the one that actually applies here -- 5000ms is only
# ~10x. That margin does not survive contention: this workstation also hosts
# the self-hosted macOS CI runner and routinely sits above load average 200
# while a build or test matrix runs, which is EXACTLY when `dev-install.sh`
# is invoked. A 498ms CPU-bound verification at heavy oversubscription can
# cross 5s, and when it does the failure is maximally alarming and WRONG: the
# script reports "the binary just installed cannot be read back ... Do NOT
# trust this install" about a perfectly good binary. That was observed on
# 2026-08-09.
#
# This is not the first time 5000ms proved too tight on this host. The
# self-test records an INDEPENDENT measurement (2026-08-03, same self-hosted
# runner, load average 62 on 16 cores): cases 2, 3, 10 and 11 all failed with
# `The --version call did not answer within 5000ms` -- and those fixtures are
# a `/bin/sh` printing a line, not a 21MB signed Mach-O. Two independent
# observations, six days apart, of the same bound false-alarming under the
# load this machine normally carries.
#
# Raising the ceiling costs nothing in discriminating power, because the
# opposing outcome is UNBOUNDED, not merely slow -- there is no hang duration
# this could collide with. 30000ms is ~60x the measured cold figure, still
# bounds the hung case to something an operator at a terminal tolerates, and
# matches what `scripts/tests/dev-install-edition.test.sh` already picked for
# its own detection calls (`DETECT_TIMEOUT_MS=30000`) on the same reasoning:
# "a ceiling against a regressed fixture, not a discriminator". Overridable
# so the self-test can still drive hang-detection in milliseconds rather than
# thirty real seconds per case.
CSQ_EDITION_VERSION_TIMEOUT_MS="${CSQ_EDITION_VERSION_TIMEOUT_MS:-30000}"
# Validated, because this value is the ONLY bound on the hang path. A
# non-numeric override makes `[ "$elapsed_ms" -ge "$timeout" ]` error (status
# 2, i.e. false) on EVERY iteration, so the deadline branch never fires: the
# poll loop then spins against a hung binary indefinitely at 10 iterations a
# second. Silently falling back to the default is right here — the operator
# supplied something meaningless, and the alternative to a working default is
# no deadline at all. Accepts the self-test's own overrides unchanged.
case "$CSQ_EDITION_VERSION_TIMEOUT_MS" in
    '' | *[!0-9]*)
        printf 'csq: ignoring non-numeric CSQ_EDITION_VERSION_TIMEOUT_MS=%s; using 30000ms.\n' \
            "$CSQ_EDITION_VERSION_TIMEOUT_MS" >&2
        CSQ_EDITION_VERSION_TIMEOUT_MS=30000
        ;;
esac

# How many bytes of a binary's `--version` stdout are read into memory before
# the reader stops listening -- independent of CSQ_EDITION_ECHO_MAX_CHARS
# above, which only bounds what is ECHOED *after* capture. Without this bound
# the capture itself is exactly the "can be megabytes of noise" case that
# comment already names, sitting upstream of the echo cap and unbounded by it.
#
# 4096 is ~20x the plausible-legitimate ceiling used for the echo cap (a
# version line plus a handful of extra banner lines still lands under a few
# hundred bytes) and 3-4 orders of magnitude below "megabytes of noise".
CSQ_EDITION_CAPTURE_MAX_BYTES=4096

# Writes the "I cannot tell, and here is exactly what I saw" block to stderr.
# $1 = binary path, $2 = stable reason token, $3.. = human detail lines.
#
# The reason token is a fixed vocabulary (`not-executable`, `killed-by-signal`,
# `exec-failed`, `nonzero-exit`, `no-output`, `unrecognized-format`,
# `ambiguous-tags`, `no-answer`, `setup-failed`, `parent-unconfirmed`) so an
# operator, a log grep, and the self-test all key on the same string rather
# than on prose that will be reworded. Every token in this list has a case in
# scripts/tests/dev-install-edition.test.sh asserting on it by name -- that
# is the check that this list has not drifted from what the code emits.
# Single-quotes a path for a remedy line the operator is told to paste into a
# shell. Spaces are already covered by the surrounding quotes; a path
# containing a SINGLE QUOTE is not — it closes the quoting mid-command and
# the operator runs something other than what was printed. Each `'` becomes
# `'\''` (close, escaped quote, reopen), the standard POSIX construction.
# The two literals are built in variables rather than escaped inline: the
# inline form is a backslash maze that is easy to get wrong and impossible to
# read, and the first draft of this function DID get it wrong (it emitted
# `\'\\'\'`, which does not round-trip). Verified by round-tripping a path
# containing a quote, a space and a `$` through `eval`.
_csq_shell_quote() {
    local s="$1"
    local q="'"
    local esc="'\\''" # close-quote, escaped quote, reopen-quote
    printf '%s%s%s' "$q" "${s//$q/$esc}" "$q"
}

_csq_edition_diag() {
    local bin="$1" reason="$2"
    shift 2
    local line
    {
        printf 'csq: could not determine the edition of the binary at %s\n' "$bin"
        printf '  reason=%s\n' "$reason"
        # Guarded: `"$@"` with zero positional parameters is an unbound-variable
        # error under `set -u` on bash 3.2, which is what macOS ships and what
        # this library is sourced into.
        if [ "$#" -gt 0 ]; then
            for line in "$@"; do
                printf '  %s\n' "$line"
            done
        fi
    } >&2
}

# Names a signal number for the diagnostic only.
#
# ONLY signals whose NUMBER is identical on Linux and macOS are named. 7, 10,
# 12 and everything from 16 up disagree between the two (7 = SIGBUS on Linux
# but SIGEMT on macOS; 10 = SIGUSR1 on Linux but SIGBUS on macOS), so naming
# those would print a confident lie on one of the two platforms this script
# runs on. Unnamed numbers are reported numerically — an unnamed signal is
# still a signal, and the number is the actionable part.
_csq_signal_name() {
    case "$1" in
        1)  printf 'SIGHUP'  ;;
        2)  printf 'SIGINT'  ;;
        3)  printf 'SIGQUIT' ;;
        4)  printf 'SIGILL'  ;;
        5)  printf 'SIGTRAP' ;;
        6)  printf 'SIGABRT' ;;
        8)  printf 'SIGFPE'  ;;
        9)  printf 'SIGKILL' ;;
        11) printf 'SIGSEGV' ;;
        13) printf 'SIGPIPE' ;;
        14) printf 'SIGALRM' ;;
        15) printf 'SIGTERM' ;;
        *)  printf 'signal %s' "$1" ;;
    esac
}

# Bounded, sanitised echo of a binary's `--version` output: first line only,
# non-printable bytes replaced, length capped.
_csq_edition_echo() {
    local raw="${1:-}"
    # The newline goes through a variable rather than appearing as `$'\n'`
    # inside the expansion: ANSI-C quoting is a word-level construct, and
    # whether it is honoured inside `"${var%%…}"` is exactly the kind of detail
    # that degrades silently to "the pattern never matches, keep everything".
    # Quoting "$nl" in the pattern also keeps it a literal match.
    local nl
    nl=$'\n'
    local line="${raw%%"$nl"*}"
    # Bytes from a binary that is ALREADY misbehaving must not be able to move
    # the operator's cursor, clear their screen, or repaint earlier output: an
    # escape sequence inside a diagnostic is a diagnostic that can lie about
    # itself. Everything outside the printable set becomes '?'.
    line="${line//[^[:print:]]/?}"
    if [ "${#line}" -gt "$CSQ_EDITION_ECHO_MAX_CHARS" ]; then
        line="${line:0:CSQ_EDITION_ECHO_MAX_CHARS} [truncated]"
    fi
    if [ -z "$line" ]; then
        printf '(nothing)'
    else
        printf '%s' "$line"
    fi
}

# Runs `$1 --version` with a hard wall-clock deadline AND a hard capture-size
# bound, in a bash-3.2-compatible way (macOS ships 3.2: no `wait -n`, no
# `timeout(1)` by default). Kills the child if it is still alive at
# CSQ_EDITION_VERSION_TIMEOUT_MS; reads at most CSQ_EDITION_CAPTURE_MAX_BYTES
# of its stdout regardless of how much it tries to write.
#
# Bash 3.2 has no `local -n`/nameref, so multiple return values go out
# through global variables rather than the local scope a caller could shadow
# safely -- callers MUST read them immediately, before calling this again.
#
# Sets on return:
#   _CSQ_V_OUT       stdout captured so far, capped at CSQ_EDITION_CAPTURE_MAX_BYTES
#   _CSQ_V_STATUS    the child's exit status. 0 when _CSQ_V_TIMED_OUT == 2
#                    (early return, the child never ran). NOT necessarily 0
#                    when _CSQ_V_TIMED_OUT == 1: the deadline path `wait`s on
#                    a killed child and reports 143/137. Callers MUST check
#                    _CSQ_V_TIMED_OUT BEFORE reading this field.
#   _CSQ_V_TIMED_OUT 0 completed | 1 killed at the deadline | 2 setup failed
#                    (mktemp/mkfifo unavailable -- an environment problem,
#                    not a statement about the binary)
#   _CSQ_V_TRUNCATED 1 when the binary was still writing at the cap, i.e. its
#                    answer could NOT be read whole; 0 otherwise
_csq_edition_capture_version() {
    local bin="$1"
    _CSQ_V_OUT=""
    _CSQ_V_STATUS=0
    _CSQ_V_TIMED_OUT=0
    _CSQ_V_TRUNCATED=0

    local workdir
    workdir="$(mktemp -d "${TMPDIR:-/tmp}/csq-edition.XXXXXX" 2>/dev/null)" || {
        _CSQ_V_TIMED_OUT=2
        return 0
    }
    local fifo="$workdir/out.fifo"
    local outfile="$workdir/out.cap"
    if ! mkfifo "$fifo" 2>/dev/null; then
        rm -rf "$workdir"
        _CSQ_V_TIMED_OUT=2
        return 0
    fi

    # The capture bound: `head -c` reads at most N bytes off the fifo and
    # exits, closing its end of the pipe. A writer that writes again after
    # that is reporting OUR truncation, not its own failure, so its status is
    # reclassified back to a normal completion below -- see the two shapes
    # that report a closed pipe, which depend on the HOST, not the binary.
    # ONE byte past the cap, deliberately. Reading exactly the cap makes
    # "we truncated" and "the binary emitted exactly the cap and then
    # failed on its own" indistinguishable -- both land at captured ==
    # cap -- and the reclassification below would then erase a genuine
    # binary failure. Reading cap+1 makes the test exact: > cap proves WE
    # closed the pipe, <= cap proves the writer reached EOF first.
    head -c "$((CSQ_EDITION_CAPTURE_MAX_BYTES + 1))" <"$fifo" >"$outfile" 2>/dev/null &
    local head_pid=$!

    # stdin from /dev/null: stdout is captured and stderr discarded, but
    # without this the binary under test inherits the operator's TTY on fd 0
    # — and this whole file exists for binaries that are corrupt, hostile, or
    # wedged. One that reads stdin can swallow keystrokes or leave the
    # terminal in a changed mode before the deadline kills it.
    "$bin" --version >"$fifo" 2>/dev/null </dev/null &
    local pid=$!

    # Poll rather than a single blocking `wait`: a `kill -0` check BEFORE the
    # first sleep means a process that is already done by the time we get
    # here (the overwhelmingly common case) adds no sleep at all.
    local elapsed_ms=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$elapsed_ms" -ge "$CSQ_EDITION_VERSION_TIMEOUT_MS" ]; then
            _CSQ_V_TIMED_OUT=1
            # `|| :` on BOTH kills. These sit in an `if` BODY inside a `while`
            # body, where `set -e` is NOT suspended (the exemption covers the
            # loop/if CONDITION only), and the installer runs `set -euo
            # pipefail`. The second kill reliably fails: `kill -TERM` lands,
            # the process dies during the sleep, bash reaps it in its SIGCHLD
            # handler, and `kill -KILL` then returns ESRCH. Measured:
            #   bash -ec 'sleep 0.1 & p=$!; sleep 0.5; kill -KILL $p 2>/dev/null; echo reached'
            # never prints `reached`. `2>/dev/null` hides the message, not the
            # status. Unguarded, the script died HERE — before the `no-answer`
            # diagnostic below, which is written for exactly this binary (a
            # CLI-path symlink into the .app that hangs in the Tauri loop).
            kill -TERM "$pid" 2>/dev/null || :
            sleep 0.2
            kill -KILL "$pid" 2>/dev/null || :
            break
        fi
        sleep 0.1
        elapsed_ms=$((elapsed_ms + 100))
    done

    # `|| assignment` rather than a bare `wait` followed by `$?`: the bare form
    # is not `set -e`-safe, and this function is REACHED under `set -e` (the
    # installer runs `set -euo pipefail` and csq_verify_post_install calls this
    # directly). A child that was killed at the deadline, or that failed on its
    # own, makes `wait` return non-zero — which would abort the caller mid-verify
    # instead of letting the named 66/68 refusals print. The `||` puts it in a
    # condition context, which suspends `set -e`, while still capturing the
    # status the whole function exists to report.
    _CSQ_V_STATUS=0
    wait "$pid" 2>/dev/null || _CSQ_V_STATUS=$?

    # head may STILL be blocked on the fifo even though $pid is confirmed
    # dead: if the binary forked a further process before we killed it (the
    # reachable Desktop-mode shape is exactly this -- a daemon supervisor
    # subprocess), that grandchild inherited its own copy of the fifo's write
    # end and keeps it open independently of $pid's fate. We own head, unlike
    # the binary under test, so give it a brief grace window to drain
    # whatever the writer already flushed to the pipe before $pid died, then
    # force it closed rather than trusting an EOF that may never come.
    local head_waited_ms=0
    while kill -0 "$head_pid" 2>/dev/null; do
        if [ "$head_waited_ms" -ge 500 ]; then
            # Reaching here means head NEVER saw EOF — we are cutting it off
            # mid-read — so the answer could not be read whole. That is the
            # same class the byte cap flags, arriving through the grace window
            # instead, and it MUST set the same flag: `captured` here is just
            # whatever the writer had flushed, routinely at-or-under the cap,
            # so the cap test below would leave TRUNCATED=0 and the partial
            # read would go on to be tag-scanned. A prefix carrying
            # `(community)` with `(enterprise)` in the unread remainder would
            # then resolve DETERMINATELY to community — case 41's fail-open,
            # reached by a different door.
            _CSQ_V_TRUNCATED=1
            # `|| :` for the same `set -e` reason as the deadline kills above.
            # NOTE the coupling: adding these guards WITHOUT the flag above
            # would convert a loud abort into a silent wrong-edition install.
            kill -TERM "$head_pid" 2>/dev/null || :
            sleep 0.1
            kill -KILL "$head_pid" 2>/dev/null || :
            break
        fi
        sleep 0.05
        head_waited_ms=$((head_waited_ms + 50))
    done
    # Same `set -e` reasoning as the child `wait` above; head's status is not
    # consulted, so it is discarded rather than captured.
    wait "$head_pid" 2>/dev/null || true

    # How many bytes we actually took. Read from the FILE, not from the string
    # captured below: `$(cat …)` strips trailing newlines, so the string's
    # length is not the byte count and would under-report a capped read whose
    # last byte is a newline.
    local captured
    captured="$(wc -c <"$outfile" 2>/dev/null | tr -d '[:space:]')"
    case "$captured" in
        '' | *[!0-9]*) captured=0 ;;
    esac

    # A closed pipe is reported in TWO shapes, and which one a writer uses is a
    # property of the HOST, not of the binary under test:
    #
    #   - SIGPIPE at its default disposition -> the writer is KILLED, and the
    #     shell encodes that as 128+13 = 141.
    #   - SIGPIPE IGNORED -> no signal is delivered; the write returns EPIPE and
    #     the writer reports an ordinary write error. Every writer in reach of
    #     this code (dash/bash builtin printf, GNU coreutils) exits 1 for that.
    #
    # SIG_IGN is inherited across fork/exec, so a whole process tree can run
    # with SIGPIPE ignored without any of its members choosing to -- which is
    # exactly the case under the GitHub Actions runner (a .NET host; the .NET
    # runtime ignores SIGPIPE process-wide). Measured on this repo: the
    # infinite-writer stub returns 141 with the default disposition and 1 under
    # `trap '' PIPE`, from the identical binary.
    #
    # Reclassifying only 141 therefore made the verdict depend on the host's
    # signal disposition: the SAME runaway binary read `unrecognized-format`
    # on a developer's machine and `nonzero-exit` in CI.
    #
    # The discriminator for "WE closed the pipe" is the capture cap, tested
    # against the cap+1 read above so it is EXACT rather than merely tuned:
    # more than cap bytes arrived only if the writer was still writing when
    # `head` stopped, and cap-or-fewer proves the writer reached EOF on its
    # own (so a non-zero status there is genuinely the binary's). An earlier
    # revision tested `-ge cap` against a cap-sized read, which also matched
    # a binary that emitted exactly cap bytes and THEN failed for its own
    # reason -- erasing a real failure. Statuses a closed pipe cannot produce
    # -- 126/127 exec failures, and every other signal, including the SIGKILL
    # 137 that names the Gatekeeper provenance shape -- keep their own far
    # more actionable diagnostics.
    if [ "$captured" -gt "$CSQ_EDITION_CAPTURE_MAX_BYTES" ]; then
        _CSQ_V_TRUNCATED=1
    fi
    if [ "$_CSQ_V_TIMED_OUT" -eq 0 ]; then
        if [ "$_CSQ_V_STATUS" -eq 141 ]; then
            # 128+13. Reclassified whether or not the cap was reached: the
            # head-grace kill below can also close the pipe early.
            _CSQ_V_STATUS=0
        elif [ "$_CSQ_V_STATUS" -eq 1 ] && [ "$_CSQ_V_TRUNCATED" -eq 1 ]; then
            _CSQ_V_STATUS=0
        fi
    fi

    # Hand back at most the cap: the extra byte exists to DETECT truncation,
    # never to widen what a caller may read.
    _CSQ_V_OUT="$(head -c "$CSQ_EDITION_CAPTURE_MAX_BYTES" "$outfile" 2>/dev/null)"
    rm -rf "$workdir"
    return 0
}

# Answers "is it PROVEN that nothing exists at $1?" -- status 0 = proven,
# status 1 = unproven. `-e`/`-L` on $1 itself cannot answer this: they return
# false for EVERY stat error on the path, and EACCES on an ancestor
# directory, ESTALE on a disconnected mount, ENOTDIR from a file where a
# directory was expected, and a genuine ENOENT are all indistinguishable at
# that single test. Reproduced empirically: `chmod 0644` on an ancestor
# directory (removing search/execute permission) makes `-e`/`-L` report
# false on a present, executable, enterprise binary three levels below it --
# exactly the fresh-host shape that lets community install over it.
#
# The fix walks UP from $1's parent to the first ancestor that CAN be
# stat'd (every absolute path bottoms out at "/", which always can). If that
# ancestor is a searchable directory, everything below it is a genuine
# ENOENT and the caller's "absent" verdict is correct -- this is also what
# keeps a not-yet-created ~/.local/bin on an actually fresh host resolving
# to "absent" rather than misfiring here: nothing between $HOME (which
# exists) and the missing leaf ever stat'd successfully as a non-searchable
# node, so the walk reaches $HOME and confirms it. If the first stat'able
# ancestor is NOT a searchable directory -- a file where a directory was
# expected, or one this process cannot search into, the exact shape above
# -- the absence of $1 is UNPROVEN.
# Walking up is NOT sufficient on its own, and an earlier revision of this
# function stopped there. Climbing treats "`-e`/`-L` false" as "does not
# exist" -- the SAME conflation this function exists to remove, just one
# level up. On an NFS/autofs home whose mount has gone stale, every
# component under it fails to stat with ESTALE, the walk skips all of them,
# reaches a healthy `/Users`, finds it searchable, and reports absence
# PROVEN -- for a leaf it never managed to look at. The installer then
# defaults to community, skips the downgrade guard (which reads
# INSTALLED_EDITION = "enterprise" and sees ""), the autofs mount comes back
# on the first write, the install succeeds, and the post-install check
# confirms the binary is the community one it just chose. The 2026-08-02
# incident end to end, self-verifying line included.
#
# So the ancestor walk answers only "which directory can I actually look
# in", and the VERDICT comes from a readdir of that directory: the next path
# component below it must be genuinely absent from the listing. readdir
# returns names without stat'ing them, so a name that is PRESENT but
# unstat'able (the stale-mount and EIO cases) is seen and absence is
# correctly reported UNPROVEN. This also closes the same hole at the leaf --
# a binary whose own stat fails under a perfectly healthy parent.
#
# `-r` is required alongside `-d`/`-x` because the readdir is now
# load-bearing: a directory that is searchable but not readable yields an
# unexpanded glob, which is indistinguishable from an empty directory. Fail
# closed there rather than read "cannot list" as "nothing present".
_csq_edition_confirm_absent() {
    local p child
    # `child` trails `p` by one component: the thing whose absence FROM `p`
    # is what "nothing is installed at $1" actually means.
    child="$(basename -- "$1")"
    p="$(dirname -- "$1")"
    while :; do
        if [ -e "$p" ] || [ -L "$p" ]; then
            [ -d "$p" ] && [ -x "$p" ] && [ -r "$p" ] || return 1
            # `-r` is an access(2) test, and access(2) saying "readable" does
            # NOT prove opendir(3) will succeed — macOS TCC (a terminal
            # without Full Disk Access reading ~/Documents), SELinux/AppArmor
            # mediation, and some bind-mount profiles all permit by mode bits
            # while denying enumeration. Where they diverge the globs below
            # match nothing, BOTH stay literal, and the loop would fall
            # straight to `return 0` — absence PROVEN for a directory never
            # read. That is the fresh-host verdict, which defaults to
            # community: the same conflation this function exists to remove,
            # one layer further down.
            #
            # `listed` is the proof that the listing actually happened. `.*`
            # matches `.` and `..` on every directory that was genuinely
            # opened — measured on an EMPTY directory, the loop still yields
            # both — so a literal `.*` means opendir did not happen, and a
            # genuinely empty directory still sets listed=1. No false refusal
            # on a fresh host.
            #
            # GLOBIGNORE is scoped to this function because bash imports it
            # from the environment as an ordinary variable: a non-null value
            # suppresses matching names AND unconditionally suppresses `.`
            # and `..`, so an exported `GLOBIGNORE=csq` would delete the
            # installed binary from this verdict's listing.
            local GLOBIGNORE=''
            local entry listed=0
            for entry in "$p"/* "$p"/.*; do
                # An unmatched glob stays literal in bash; those two forms
                # are the only ones that can appear, and neither is a real
                # entry name here.
                [ "$entry" = "$p/*" ] && continue
                [ "$entry" = "$p/.*" ] && continue
                listed=1
                if [ "${entry##*/}" = "$child" ]; then
                    # Present in the listing, whatever stat says about it.
                    return 1
                fi
            done
            # Nothing enumerated at all: the listing did not happen, so the
            # absence is UNKNOWN rather than proven. Fail closed.
            [ "$listed" -eq 1 ] || return 1
            return 0
        fi
        case "$p" in
            /|.) return 1 ;;
        esac
        child="$(basename -- "$p")"
        p="$(dirname -- "$p")"
    done
}

# Determine the edition of the csq binary at $1.
#
#   stdout : `enterprise` | `community` | `absent`   (determinate, status 0)
#            nothing                                  (indeterminate, status 1)
#   stderr : silent when determinate; a bounded diagnostic when not
#   status : 0 determinate, 1 indeterminate
csq_detect_edition() {
    local bin="${1:-}"

    if [ -z "$bin" ]; then
        printf 'csq: edition detection was called with no path (internal error).\n' >&2
        return 1
    fi

    # `-e` alone is FALSE for a symlink whose target is gone, which would file a
    # BROKEN install under "fresh host" — the exact conflation this file exists
    # to remove. `-L` keeps that case on the loud path. `absent` is the only
    # verdict that lets the caller default to community, so it has to mean
    # "there is genuinely nothing here", not "I found nothing usable" -- and
    # not "some ancestor directory could not be searched", which is the same
    # false shape one level up. See _csq_edition_confirm_absent.
    if [ ! -e "$bin" ] && [ ! -L "$bin" ]; then
        if _csq_edition_confirm_absent "$bin"; then
            printf 'absent\n'
            return 0
        fi
        _csq_edition_diag "$bin" 'parent-unconfirmed' \
            "Nothing appears to be at $bin, but that could not be confirmed: an ancestor" \
            'directory exists but cannot be searched into (permission denied), or is not' \
            'a directory where one was expected. A file-existence check reports false for' \
            'that exactly as it does for a genuinely missing path.' \
            'This is NOT a confirmed fresh host -- defaulting to community here is the' \
            'same downgrade this file exists to prevent, through a different door.' \
            'Check read+execute (search) permission on each directory in that path.'
        return 1
    fi

    # `-x` is TRUE for a searchable directory, so the `-d` half is load-bearing:
    # without it a directory at the install path falls through to being executed.
    if [ ! -x "$bin" ] || [ -d "$bin" ]; then
        _csq_edition_diag "$bin" 'not-executable' \
            'Something exists at that path but cannot be executed: wrong permissions,' \
            'a directory, or a symlink whose target is gone.' \
            'This is NOT a fresh host -- an install is present and unusable.'
        return 1
    fi

    # The binary's own stderr is discarded on purpose (inside the helper): a
    # corrupt or wrong-architecture binary can emit unbounded noise there, and
    # the exit status plus the bounded stdout echo below already name the
    # failure. stdout is bounded in TWO independent ways here: a wall-clock
    # deadline (a binary that never answers at all -- Desktop-mode's Tauri
    # event loop is exactly this) and a byte cap on what is read (a binary
    # that answers but never stops writing).
    _csq_edition_capture_version "$bin"
    local out="$_CSQ_V_OUT" status="$_CSQ_V_STATUS"

    if [ "$_CSQ_V_TIMED_OUT" -eq 2 ]; then
        _csq_edition_diag "$bin" 'setup-failed' \
            'Could not set up a bounded --version call: mktemp or mkfifo failed.' \
            'This is an environment problem (no writable temp dir, or mkfifo' \
            'unavailable), not a statement about the binary itself.'
        return 1
    fi
    if [ "$_CSQ_V_TIMED_OUT" -eq 1 ]; then
        _csq_edition_diag "$bin" 'no-answer' \
            "The --version call did not answer within ${CSQ_EDITION_VERSION_TIMEOUT_MS}ms and was killed." \
            'A csq binary that is a SYMLINK into the .app bundle canonicalizes back into' \
            'Desktop mode (csq/src/mode.rs checks the bundle sentinel before the tty guard)' \
            'and enters the Tauri event loop instead of printing a version and exiting -- it' \
            'never answers a --version call at all, no matter how long you wait.' \
            'This is NOT a fresh host -- an install is present and cannot be read this way.' \
            'Try: run the .app once so its own startup repairs the CLI shim, or replace the' \
            'symlink at that path with a real copy of the binary.'
        return 1
    fi

    if [ "$status" -ne 0 ]; then
        # 128 is not a tuned threshold. It is the POSIX shell's own encoding of
        # "the child died from signal N" as 128+N, so a status <= 128 is a plain
        # exit status by construction and a status >= 129 is that encoding.
        # There is no margin to size on either side; the boundary is exact.
        if [ "$status" -gt 128 ]; then
            local signum
            signum=$((status - 128))
            _csq_edition_diag "$bin" 'killed-by-signal' \
                "The --version call did not answer: the shell reported exit status $status," \
                "which is 128+$signum, i.e. killed by $(_csq_signal_name "$signum")." \
                'On macOS a SIGKILL here is the Gatekeeper provenance shape -- the binary was' \
                'copied into place with cp instead of install, so the kernel refuses to run it.' \
                "Try: xattr -cr $(_csq_shell_quote "$bin")   then re-run." \
                '(A program can also exit with this status deliberately; csq does not.)'
        elif [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then
            _csq_edition_diag "$bin" 'exec-failed' \
                "The --version call returned exit status $status. POSIX shells use 126 for" \
                '"found but not executable" and 127 for "not found" -- here that usually means a' \
                'wrong-architecture build, a missing dynamic loader, or a missing interpreter.' \
                '(A program can also exit with these statuses deliberately; csq does not.)'
        else
            _csq_edition_diag "$bin" 'nonzero-exit' \
                "The --version call exited $status instead of 0, so nothing it printed can be" \
                'trusted as an edition tag.' \
                "First line of its output: $(_csq_edition_echo "$out")"
        fi
        return 1
    fi

    # A TRUNCATED answer is refused BEFORE the tag scan, not scanned for
    # whatever tag happened to fit.
    #
    # The ambiguous-tags guard below exists to catch "a truncated or
    # concatenated binary carrying BOTH strings", but it can only see what
    # was captured — so a binary emitting `(community)`, then kilobytes of
    # junk, then `(enterprise)` past the cap would have the second tag cut
    # off, satisfy exactly one branch, and resolve DETERMINATELY to the
    # wrong edition. That is the accident the guard was written to prevent,
    # reachable through the cap that sits upstream of it.
    #
    # A real `--version` line is 23 bytes (see CSQ_EDITION_ECHO_MAX_CHARS
    # above); anything still writing at 4096 is not answering the question.
    # `unrecognized-format` is the right token — the output genuinely does
    # not have a readable edition shape — and reusing it keeps the reason
    # vocabulary fixed for the operator, the log grep and the self-test.
    if [ "${_CSQ_V_TRUNCATED:-0}" -eq 1 ]; then
        _csq_edition_diag "$bin" 'unrecognized-format' \
            "The --version call was still writing after ${CSQ_EDITION_CAPTURE_MAX_BYTES} bytes, so its" \
            'output could not be read whole and any edition tag found in the part that WAS' \
            'read may be contradicted by the part that was not.' \
            "First line of its output: $(_csq_edition_echo "$out")" \
            'A real --version line is a couple of dozen bytes; treating a runaway one as an' \
            'answer is how a truncated binary resolves to the wrong edition.'
        return 1
    fi

    local has_enterprise=0 has_community=0
    case "$out" in *"(enterprise)"*) has_enterprise=1 ;; esac
    case "$out" in *"(community)"*)  has_community=1  ;; esac

    # Both tags present names no single edition. Cheap to check, and it closes
    # the case where a truncated or concatenated binary happens to carry both
    # strings — which would otherwise be resolved by whichever branch is
    # written first, i.e. by accident.
    if [ "$has_enterprise" -eq 1 ] && [ "$has_community" -eq 1 ]; then
        _csq_edition_diag "$bin" 'ambiguous-tags' \
            'The --version output carries BOTH an (enterprise) and a (community) tag, so it' \
            'names no single edition.' \
            "First line of its output: $(_csq_edition_echo "$out")"
        return 1
    fi
    if [ "$has_enterprise" -eq 1 ]; then
        printf 'enterprise\n'
        return 0
    fi
    if [ "$has_community" -eq 1 ]; then
        printf 'community\n'
        return 0
    fi

    if [ -z "$out" ]; then
        _csq_edition_diag "$bin" 'no-output' \
            'The --version call exited 0 but printed nothing, so there is no edition tag to' \
            'read. A binary that answers with silence has not identified itself.'
    else
        _csq_edition_diag "$bin" 'unrecognized-format' \
            'The --version call succeeded but its output carries neither an (enterprise) nor a' \
            '(community) tag.' \
            "First line of its output: $(_csq_edition_echo "$out")" \
            'Treating an unknown format as "nothing is installed" is what silently downgrades' \
            'a host, so it is refused rather than guessed.'
    fi
    return 1
}

# Resolve which edition to BUILD, given the binary installed at $1.
#
# Precedence — unchanged from the original script except for arm 2, which used
# to not exist:
#
#   1. an explicit CSQ_EDITION wins, INCLUDING when the installed binary cannot
#      be read. That is the documented escape hatch, and it is the only way past
#      an unreadable install, so it has to keep working (a fail-closed check
#      with no way past it is a check operators route around permanently).
#   2. an unreadable install ABORTS with status 67. It used to fall through to
#      arm 4 and install community over it.
#   3. a readable install is PRESERVED.
#   4. a genuinely fresh host defaults to community.
#
# Sets on success:
#   CSQ_RESOLVED_EDITION   the edition to build (`enterprise` | `community`)
#   CSQ_INSTALLED_EDITION  what is installed now: `enterprise`, `community`, or
#                          "" when nothing is installed. "" keeps the caller's
#                          enterprise->community downgrade guard reading exactly
#                          the input shape it read before.
#
# Status: 0 resolved | 64 invalid CSQ_EDITION value | 67 edition indeterminate |
#         70 called with no path (caller error, not an install problem).
csq_resolve_edition() {
    local bin="${1:-}"
    local detected unknown=0

    # Reset first: a stale value from an earlier call must never be mistaken
    # for this call's answer, and both are read by the caller after a status
    # check that a future edit could get wrong.
    CSQ_RESOLVED_EDITION=""
    CSQ_INSTALLED_EDITION=""

    # An empty $bin is a CALLER bug -- csq_detect_edition already refuses it
    # with its own "internal error" diagnostic and returns 1, which would
    # otherwise fall into the SAME branch below as "a binary is installed here
    # but its edition could not be determined", printing
    # "FATAL: a csq binary is installed at  but its edition cannot be
    # determined" (note the blank %s) -- a caller bug reported as an install
    # problem, under a status (67) documented to mean the opposite. Caught
    # here, before csq_detect_edition ever runs, so it gets its own status and
    # its own, accurate message instead.
    if [ -z "$bin" ]; then
        printf 'FATAL: csq_resolve_edition was called with no binary path (internal error,\n' >&2
        printf '  not an install problem -- there is no install to have an opinion about).\n' >&2
        return 70
    fi

    if detected="$(csq_detect_edition "$bin")"; then
        if [ "$detected" != "absent" ]; then
            CSQ_INSTALLED_EDITION="$detected"
        fi
    else
        unknown=1
    fi

    if [ -n "${CSQ_EDITION:-}" ]; then
        CSQ_RESOLVED_EDITION="$CSQ_EDITION"
        if [ "$unknown" -eq 1 ]; then
            {
                printf '%s\n' 'NOTE: the installed binary could not be read (diagnostic above).'
                printf '      Proceeding on the explicit CSQ_EDITION=%s.\n' "$CSQ_RESOLVED_EDITION"
                printf '%s\n' '      The enterprise->community downgrade guard cannot run when the'
                printf '%s\n' '      installed edition is unknown, so this one is entirely your call.'
            } >&2
        fi
    elif [ "$unknown" -eq 1 ]; then
        {
            printf 'FATAL: a csq binary is installed at %s but its edition cannot be determined.\n' "$bin"
            printf '%s\n' '  The diagnostic above names what was actually observed.'
            printf '%s\n' '  Refusing to guess. Guessing here means defaulting to community and'
            printf '%s\n' '  installing a COMMUNITY build over what may be an ENTERPRISE host --'
            printf '%s\n' '  dropping the direct-API moat, the licensing gate and the kailash trust'
            printf '%s\n' '  plane -- after which the post-install check compares the new binary'
            printf '%s\n' '  against that same guess and reports the downgrade as verified.'
            printf '%s\n' '  Say which edition you want, and this proceeds:'
            printf '%s\n' '    CSQ_EDITION=enterprise scripts/dev-install.sh'
            printf '%s\n' '    CSQ_EDITION=community  scripts/dev-install.sh'
        } >&2
        return 67
    elif [ -n "$CSQ_INSTALLED_EDITION" ]; then
        CSQ_RESOLVED_EDITION="$CSQ_INSTALLED_EDITION"
        printf 'Preserving installed edition: %s (override with CSQ_EDITION=...)\n' "$CSQ_RESOLVED_EDITION"
    else
        CSQ_RESOLVED_EDITION="community"
    fi

    case "$CSQ_RESOLVED_EDITION" in
        enterprise|community) ;;
        *)
            printf "FATAL: CSQ_EDITION must be 'enterprise' or 'community', got '%s'\n" \
                "$CSQ_RESOLVED_EDITION" >&2
            # Cleared for the same reason detection prints nothing when it
            # fails: a caller that reads the global without checking the status
            # must not find a value that looks usable. An unvalidated string
            # here would reach the build as "not enterprise", i.e. community.
            # CSQ_INSTALLED_EDITION is cleared too, on the same rationale --
            # it is the SOLE input to the enterprise->community downgrade
            # guard in dev-install.sh, so a caller that skips the status check
            # must not find a value there that lets that guard silently
            # compare against a real edition while CSQ_RESOLVED_EDITION is
            # empty. Nothing currently reads it after this branch, but the
            # defense being documented as general (this whole comment) and
            # implemented as one-variable-specific is exactly the kind of gap
            # a future caller falls into.
            CSQ_RESOLVED_EDITION=""
            CSQ_INSTALLED_EDITION=""
            return 64
            ;;
    esac
    return 0
}

# Verifies a freshly-installed binary at $1 reports the intended edition $2.
# Factored out of dev-install.sh so the highest-consequence part of the
# script -- the check that runs AFTER the operator's previous binary has
# already been overwritten -- is exercisable from the self-test without
# needing a cargo build.
#
# Same tri-state posture as csq_detect_edition, on purpose: a binary that
# will not run has not demonstrated it is the edition that was asked for, and
# letting "cannot tell" through here would print "Verified: ..." about a
# binary that never answered -- the exact self-verifying-lie shape this whole
# file exists to close, in the worse place, because there is no previous
# binary left to fall back to.
#
#   $1 = path to the freshly-installed binary
#   $2 = the edition that was intended (`enterprise` | `community`)
#
# stdout : the binary's own `--version` line, then "Verified: installed
#          edition = <edition>." -- ONLY on success.
# stderr : a diagnostic on any failure path.
# status : 0 verified | 66 edition mismatch | 68 unreadable or absent.
csq_verify_post_install() {
    local installed="$1" intended="$2"
    local new_edition

    if ! new_edition="$(csq_detect_edition "$installed")"; then
        {
            printf 'FATAL: the binary just installed at %s cannot be read back.\n' "$installed"
            printf '%s\n' '  The diagnostic above names what was actually observed.'
            printf '%s\n' '  The previous binary has already been replaced, so this host now has a csq'
            printf '%s\n' '  that does not run. Do NOT trust this install.'
            printf '  On macOS, try: xattr -cr %s   then re-run this script.\n' \
                "$(_csq_shell_quote "$installed")"
        } >&2
        return 68
    fi
    if [ "$new_edition" = "absent" ]; then
        {
            printf 'FATAL: nothing is present at %s after a reportedly successful install.\n' "$installed"
            printf '%s\n' '  Do NOT trust this install.'
        } >&2
        return 68
    fi

    # The edition is already CONFIRMED above via csq_detect_edition -- this
    # second, raw call exists only to echo the binary's own version banner to
    # the operator, and it is NOT protected by the bounded-capture machinery
    # csq_detect_edition uses internally. Guarded with `||` so a transient
    # failure here (this script runs under `set -euo pipefail`) cannot abort
    # the whole install with a raw, unmapped exit status -- e.g. the exact
    # Gatekeeper-SIGKILL-137 shape this file exists to handle -- bypassing
    # every one of the named 66/68 refusals below and printing nothing.
    # Routed through the SAME bounded capture as detection, not a raw
    # invocation. This runs after the operator's previous binary has already
    # been replaced, which makes it the worst place in the file to hand an
    # unbounded, unsanitized, deadline-free call to a binary that has just
    # demonstrated it might misbehave. A raw call here would: hang forever on
    # the Desktop-mode/Tauri shape that CSQ_EDITION_VERSION_TIMEOUT_MS exists
    # for; emit megabytes to the terminal; and let ANSI sequences (scroll
    # region, alt-screen, cursor moves) reach the operator immediately BEFORE
    # the Verified/FATAL lines below — a diagnostic that can rewrite itself,
    # which is exactly what _csq_edition_echo's control-byte replacement
    # exists to prevent.
    #
    # Called directly, NOT in a $( ) subshell: the capture reports through
    # globals, and a subshell would discard them.
    #
    # This is informational only — the edition was already CONFIRMED above.
    # A second call that now fails says nothing about the verdict (and is a
    # real possibility: the FLAKY fixture exists because a binary can behave
    # differently on the second invocation), so it degrades to a note rather
    # than failing the install.
    _csq_edition_capture_version "$installed"
    if [ "$_CSQ_V_TIMED_OUT" -eq 0 ] && [ "$_CSQ_V_STATUS" -eq 0 ] && [ -n "$_CSQ_V_OUT" ]; then
        printf '%s\n' "$(_csq_edition_echo "$_CSQ_V_OUT")"
    else
        printf \
            'NOTE: could not re-invoke %s for its version banner (informational only --\n  the edition above was already confirmed via the bounded call).\n' \
            "$installed" >&2
    fi
    if [ "$new_edition" != "$intended" ]; then
        printf "FATAL: post-install edition mismatch -- intended '%s', binary reports '%s'.\n" \
            "$intended" "$new_edition" >&2
        printf '%s\n' '  The installed binary is NOT what was requested. Do not trust this install.' >&2
        return 66
    fi
    printf 'Verified: installed edition = %s.\n' "$new_edition"
    return 0
}
