#!/usr/bin/env bash
#
# resolve-python.sh — find a python3 that ACTUALLY RUNS, or fail loudly.
#
# # Why this exists
#
# csq's release tooling shells to `python3` in ~13 places: the cargo target-dir
# resolver (which gates dev-install.sh, build-enterprise-desktop.sh and
# release-enterprise-macos.sh), the edition-leak check, the worktree drift gate,
# the community extraction, the SBOM and third-party-license generators, and the
# publish path. Every one of them inherited whatever `python3` resolved to on
# the operator's PATH.
#
# MEASURED 2026-09-20. On this host `python3` resolved through a pyenv shim to a
# 54-byte shell stub that printed its own version directory and **exited 0 for
# every input**. `cargo_target_dir` therefore returned
# `/Users/example/.pyenv/versions/3.12.9`, and `dev-install.sh` chased
# `/Users/example/.pyenv/versions/3.12.9/release/csq` — reporting
# "No such file or directory" against a path that names neither python nor the
# real cause. The BUILD had succeeded; only the install broke.
#
# # Why a PROBE and not a lookup
#
# `command -v python3` and `test -x "$p"` BOTH PASS on that stub. It is
# executable, it is on PATH, and it exits 0. Only EXECUTING it and checking the
# ANSWER distinguishes a working interpreter from one that merely accepts being
# called — `instrument-discipline.md` MUST-1: the check must be able to return
# the other answer.
#
# The probe asks for a value the stub cannot produce by accident. The stub
# echoes a path; the probe demands a specific number.
#
# # Why the probe ALSO creates a pipe and checks the language level (2026-09-20)
#
# `print(3+4)` was still too weak, and the same host produced the counter-example
# within the hour. A pyenv 3.12.9 rebuilt at 09:27 that morning had
# `HAVE_PIPE2=1` from a `MACOSX_DEPLOYMENT_TARGET=26.6` SDK whose libSystem
# declares `pipe2`, while the RUNNING OS (macOS 26.6.2, build 25G83) does not
# export it — `dlsym(libSystem, "pipe2")` returns NULL, and `nm -m` on
# `libpython3.12.dylib` shows `(undefined) weak external _pipe2`. dyld binds an
# unresolvable weak import to 0, so `os.pipe()` — which calls `pipe2` first and
# only falls back to `pipe()` on ENOSYS — CALLED ADDRESS 0 and died with
# SIGSEGV. `python3 -c 'import os; print(os.pipe())'` alone reproduced it; the
# 3.9.6 / 3.10.16 / 3.11.11 builds on the same host return `(3, 4)`.
#
# `print(3+4)` made a pipe neither before nor after, so it passed this
# interpreter and handed it to every caller — including
# `scripts/tests/spec-metadata.test.sh`, whose suite spawns a child with
# `capture_output=True` and so was reported as `Segmentation fault: 11`
# (RC=139) instead of a verdict, and `scripts/check-edition-boundary.py`, a CI
# gate, which measured the same 139. An interpreter that dies on a core syscall
# is not one csq's tooling can use; the probe now says so at RESOLUTION time.
#
# The language-level check is the same class one version over: the reader suite
# imports `scripts/verify/spec_metadata.py`, which annotates `Located | None` in
# a class body — evaluated at runtime, so it needs 3.10+, and on 3.9.6 it dies
# with `unsupported operand type(s) for |` BEFORE any test runs. Handing that
# interpreter back would convert a cannot-measure into a FALSE FAILURE, which
# `product-completion-first.md` is explicit about: a gate that accuses correct
# code is worse than no gate. Both requirements are the CALLER's, stated once
# here rather than re-derived per script.
#
# # Why a caller DECLARES a capability requirement (2026-09-20, later the same day)
#
# The pipe + language probe fixed what EVERY caller needs in common, and that
# turned out not to be enough, because callers do not need the same thing. The
# same host, measured, minutes after the pipe fix landed:
#
#   path                                  version   os.pipe()   import yaml
#   python3 (pyenv shim)                  3.12.9    RC 139      ok
#   /usr/bin/python3                      3.9.6     ok          6.0.3
#   /opt/homebrew/bin/python3             3.14.6    ok          ABSENT
#   ~/.pyenv/versions/3.10.16/bin/python3 3.10.16   ok          ABSENT
#   ~/.pyenv/versions/3.11.11/bin/python3 3.11.11   ok          6.0.2
#
# `scripts/ci/job-budget-audit.mjs` reads the workflows through `python3+yaml`.
# The pipe fix made the resolver hand it `/opt/homebrew/bin/python3` — healthy,
# creates pipes, is >= 3.10, and has no PyYAML — so the audit died with
# `ModuleNotFoundError: No module named 'yaml'`. The interpreter that HAS PyYAML
# and pipes (`/usr/bin/python3`) is 3.9.6 and fails the language level. NO
# SINGLE FIXED CANDIDATE SATISFIES EVERY CALLER, and the resolver had no way to
# know which caller it was serving.
#
# So the requirement is a PARAMETER:
#
#   PY="$(resolve_python3 --require yaml)" || exit 70
#
# The zero-argument call is untouched — a caller that needs nothing gets exactly
# the resolution it got before. A candidate that lacks a declared module is
# REJECTED and the rejection is CLASSIFIED (see `CSQ_PY_NO_MODULE` below), so
# the operator reads "this interpreter cannot do what this caller asked for"
# rather than a bare non-zero exit — `durable-instruments.md` MUST-2.
#
# WHAT THE MODULE CHECK ESTABLISHES, AND WHAT IT DOES NOT. It EXECUTES
# `__import__(name)` in the candidate and requires it to return without raising
# — it does not grep for a file, which would pass on a module directory with no
# working contents. It therefore establishes exactly two things: the module is
# on THAT interpreter's `sys.path`, and its top-level import completes. It does
# NOT establish that a C extension inside it works at CALL time, that a
# specific attribute exists, or that a version floor is met. Those are the
# caller's business — a caller needing `yaml.safe_load` specifically is asking a
# narrower question than `--require yaml` answers.
#
# # Why the candidate list ALSO grew pyenv version dirs
#
# The measured table above is why. With `--require yaml` and the old fixed
# list, EVERY candidate is rejected on this host (segfault / too old / no
# module / absent) and the resolver would have concluded "no working python3
# exists" — while `~/.pyenv/versions/3.11.11/bin/python3` was healthy, new
# enough, and had PyYAML the whole time. The capability parameter is not
# sufficient on its own; the candidate SET has to be wide enough for some
# candidate to satisfy any requirement a caller may declare. The pyenv version
# dirs are appended AFTER the fixed list, so the zero-argument resolution (which
# succeeds at `/opt/homebrew/bin/python3` and never reaches them) is unchanged.
#
# Origin: 2026-09-20. The failure was found by csq's own pre-flight work and
# recorded as a live incident; this helper is the structural fix so the next
# broken or under-equipped interpreter fails LOUDLY at the first use rather than
# silently corrupting a path three scripts later.
#
# Usage:
#   . "$REPO_ROOT/scripts/lib/resolve-python.sh"
#   PY="$(resolve_python3)"                  || exit 70
#   PY="$(resolve_python3 --require yaml)"   || exit 70
#   "$PY" -c '...'

# Prints the path to a verified-working python3, or returns non-zero having
# printed the reason to stderr. NEVER returns a path it has not executed.
#
# Synopsis: resolve_python3 [--require MODULE]...
#   --require MODULE   reject any candidate that cannot `import MODULE`.
#                      Repeatable; every declared module must import.
#
# Exit status: 0 with a path on stdout, or 70 with the classified reasons on
# stderr. 70 is the single cannot-measure code for BOTH "no interpreter runs"
# and "no interpreter satisfies the declared requirements" — callers already
# write `|| exit 70`, and the reasons on stderr carry the distinction.
# Arguments are OPTIONAL by design: a caller with no capability requirement
# invokes this bare, which is the common case. SC2120 (and the SC2119 it
# raises at each bare call site) assumes a function that reads $1 must
# always be given one; here "no --require" is a meaningful, supported call.
# shellcheck disable=SC2120
resolve_python3() {
    # Every local is declared HERE, never inside a loop. zsh's `local` is
    # `typeset`, which PRINTS `name=value` when it re-declares an already-set
    # parameter, so a `local` in a loop body emits the previous iteration's
    # values on STDOUT — corrupting the path this function returns to a zsh
    # caller (measured: `zsh -c '. scripts/lib/resolve-python.sh; resolve_python3'`
    # printed `out=''`, `rc=139`, … before the path). Hoisting is the portable
    # fix; `setopt typeset_silent` is zsh-only and an error under bash.
    local requires=() mod mod_block mod_lit
    local candidates=() tried=() cand out rc pyv
    local min_major=3 min_minor=10
    local probe_too_old='CSQ_PY_TOO_OLD='
    local probe_no_module='CSQ_PY_NO_MODULE='

    # ── declared capability requirements ─────────────────────────────────────
    # An UNKNOWN argument is a hard error, not something to ignore. A silently
    # ignored flag is the whole failure class this file exists to close: a
    # caller who writes `--requrie yaml` would fall through to the zero-argument
    # path, receive an interpreter with no PyYAML, and discover the typo as a
    # ModuleNotFoundError three scripts later.
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --require)
                shift
                if [ "$#" -eq 0 ]; then
                    echo "FATAL: resolve_python3 --require needs a MODULE argument." >&2
                    return 70
                fi
                requires+=("$1") ;;
            --require=*)
                requires+=("${1#--require=}") ;;
            *)
                echo "FATAL: resolve_python3: unknown argument '$1'." >&2
                echo "       Synopsis: resolve_python3 [--require MODULE]..." >&2
                return 70 ;;
        esac
        shift
    done

    # The module names are interpolated into the probe program, so they are
    # validated rather than trusted. A dotted name is allowed (it imports the
    # submodule); anything that could terminate the Python string literal or
    # inject a statement is refused here, at the boundary. Guarded by the COUNT
    # rather than by an ${arr[@]+...} expansion, which zsh does not parse the
    # way bash does — and a loop guarded this way reads identically in both.
    if [ "${#requires[@]}" -gt 0 ]; then
        for mod in "${requires[@]}"; do
            case "$mod" in
                ''|*[!A-Za-z0-9_.]*|[0-9]*)
                    echo "FATAL: resolve_python3 --require '$mod' is not a valid module name." >&2
                    echo "       Expected [A-Za-z_][A-Za-z0-9_.]*" >&2
                    return 70 ;;
            esac
        done
    fi

    # Candidate order: an explicit override first, then PATH, then the well-known
    # system locations, then the pyenv version dirs. A caller that needs a
    # specific interpreter sets CSQ_PYTHON3; that candidate is held to the SAME
    # probe as the rest, so an override pointing at a stub fails here rather
    # than downstream.
    [ -n "${CSQ_PYTHON3:-}" ] && candidates+=("$CSQ_PYTHON3")
    candidates+=("python3" "/usr/bin/python3" "/opt/homebrew/bin/python3" "/usr/local/bin/python3")

    # The pyenv version dirs, discovered rather than hardcoded (the versions
    # installed on a given host are not knowable in advance) and appended AFTER
    # the fixed list so the zero-argument resolution is unaffected. `find | sort`
    # rather than a `"$dir"/*/bin/python3` glob: a non-matching glob is a FATAL
    # "no matches found" under zsh, which would break this function on every
    # host without pyenv.
    while IFS= read -r pyv; do
        [ -n "$pyv" ] && candidates+=("$pyv")
    done < <(find "$HOME/.pyenv/versions" -maxdepth 3 -path '*/bin/python3' 2>/dev/null | sort)

    # The minimum language level csq's own python tooling is written in: three
    # files in `scripts/` annotate with PEP 604 `X | None` at runtime
    # (check-edition-boundary.py, conformance-walk.py, verify/spec_metadata.py),
    # which 3.9 raises TypeError on. See the header.
    #
    # ONE probe, every question, ONE execution per candidate. The module block
    # below is emitted ONLY when a caller declared a requirement, so the
    # zero-argument probe program is byte-identical to the version that shipped
    # before `--require` existed.
    if [ "${#requires[@]}" -gt 0 ]; then
        mod_lit=""
        for mod in "${requires[@]}"; do
            mod_lit="${mod_lit}${mod_lit:+, }'${mod}'"
        done
        mod_block="
    _missing = []
    for _m in (${mod_lit},):
        try:
            __import__(_m)
        except Exception:
            _missing.append(_m)
    if _missing:
        print('${probe_no_module}%s' % ','.join(_missing))
        sys.exit(0)
    print(3 + 4)"
    else
        mod_block="
    print(3 + 4)"
    fi

    # A candidate is accepted only if it executes, can create a pipe, is new
    # enough, imports every declared module, and prints 7.
    local probe
    probe="import os, sys
if sys.version_info < (${min_major}, ${min_minor}):
    print('${probe_too_old}%d.%d' % sys.version_info[:2])
else:
    _r, _w = os.pipe()
    os.close(_r)
    os.close(_w)${mod_block}"

    for cand in "${candidates[@]}"; do
        # A bare name is looked up on PATH by the probe itself; a path is used
        # directly. Both go through the same execution check.
        out="$("$cand" -c "$probe" 2>/dev/null)"; rc=$?
        if [ "$out" = "7" ]; then
            # Resolve a bare name to its absolute path so callers can log it
            # and so a later PATH change cannot re-point the interpreter
            # between this check and the call.
            if command -v "$cand" > /dev/null 2>&1 && [ -x "$(command -v "$cand")" ]; then
                printf '%s\n' "$(command -v "$cand")"
            else
                printf '%s\n' "$cand"
            fi
            return 0
        fi

        # Classify WHY, so the operator reads the actual defect instead of a
        # generic "no python3". A SIGSEGV must be named as such — reporting it
        # as a bare non-zero exit is how `139` reaches a suite as if it were a
        # verdict (`durable-instruments.md` MUST-2). A missing module is the
        # same discipline: it is a MEASURED rejection ("this interpreter cannot
        # do what this caller asked"), distinct from an interpreter that cannot
        # run at all, and distinct from one that ran but answered wrongly.
        case "$out" in
            "$probe_too_old"*)
                tried+=("$cand (python ${out#"$probe_too_old"} — older than ${min_major}.${min_minor}, which csq's python tooling requires)") ;;
            "$probe_no_module"*)
                tried+=("$cand (cannot import: ${out#"$probe_no_module"} — healthy interpreter, but it lacks a module a caller DECLARED it requires)") ;;
            *)
                if [ "$rc" -ge 128 ]; then
                    tried+=("$cand (killed by signal $((rc - 128)) — NOT a working interpreter)")
                elif [ "$rc" -ne 0 ]; then
                    tried+=("$cand (exited $rc — NOT a working interpreter)")
                else
                    # It ran and exited 0 but did NOT print 7 — a stub, a wrapper,
                    # or an interpreter that swallowed the program.
                    tried+=("$cand (exited 0 but printed '${out}', not '7' — NOT a working interpreter)")
                fi ;;
        esac
    done

    {
        echo "FATAL: no working python3 found. csq's release tooling needs one;"
        echo "       a candidate is accepted only if it EXECUTES and prints the"
        echo "       expected value — an interpreter that merely exists is not enough."
        if [ "${#requires[@]}" -gt 0 ]; then
            echo "       This caller declared: --require ${requires[*]}"
            echo "       (a candidate rejected for 'cannot import' is HEALTHY but"
            echo "        under-equipped for THIS caller — a caller that needs no"
            echo "        module keeps working with the zero-argument call.)"
        fi
        echo "       Tried:"
        printf '         %s\n' "${tried[@]}"
        echo "       Fix: install python3, or set CSQ_PYTHON3=<path> to a known-good one."
        echo "       A candidate rejected for a SIGNAL is a broken BUILD, not a missing"
        echo "       one — rebuilding it against the SDK MATCHING the running OS is"
        echo "       what fixes it (2026-09-20: a build targeting the macOS 26.6 SDK"
        echo "       on this host emitted a call to a libSystem symbol the OS does not"
        echo "       export; check with: dlsym / nm -m <libpython> | grep pipe2)."
        echo "       Repairing a broken pyenv: pyenv install <version> --force (compiles from source)."
    } >&2
    return 70
}
