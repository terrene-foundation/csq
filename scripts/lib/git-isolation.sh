#!/usr/bin/env bash
#
# git-isolation.sh — make a shell test's git fixtures independent of the HOST's git config.
#
# # Why this exists
#
# Every fixture repo a shell test creates is read by git TOGETHER WITH the
# operator's config files. A maintainer with `commit.gpgsign=true` and
# `core.hooksPath→~/.githooks` therefore runs a different program from CI: the
# fixture `git commit` tries to sign with a key CI does not have, or a host
# pre-commit hook fires inside a throwaway repo and its exit status becomes the
# test's verdict. The test is then a measurement of the MACHINE, not of the code
# — the same class `resolve-python.sh` closed for interpreters (an instrument
# that reports the host's state as the artifact's).
#
# # What is neutralised, and by which layer
#
#   GIT_CONFIG_GLOBAL=<an empty FILE under the scratch root>
#                                 the host's ~/.gitconfig is not read at all
#   GIT_CONFIG_SYSTEM=/dev/null   the host's /etc/gitconfig is not read
#   GIT_CONFIG_NOSYSTEM=1         belt for the same brace (git honours both).
#                                 The two are a PAIR, not duplicates: MEASURED
#                                 2026-10-13 (git 2.54.0) — a hostile
#                                 GIT_CONFIG_SYSTEM is read when it is the only
#                                 one set and ignored when NOSYSTEM=1 is also
#                                 set, so /dev/null covers the no-NOSYSTEM case
#                                 and NOSYSTEM covers the pinned one.
#   HOME=<fresh dir>              anything git or a helper reads via $HOME. The
#                                 redirect is what keeps a fixture's own
#                                 `git config --global` from landing in the
#                                 operator's ~/.gitconfig.
#   XDG_CONFIG_HOME=<HOME>/.config  git's DEFAULT core.excludesFile
#                                 ($XDG_CONFIG_HOME/git/ignore) and
#                                 core.attributesFile resolve under XDG_CONFIG_HOME
#                                 and are NOT covered by GIT_CONFIG_GLOBAL or by
#                                 the HOME redirect while the host still exports
#                                 it. MEASURED 2026-10-13: with a host
#                                 XDG_CONFIG_HOME whose git/ignore listed a file,
#                                 `git status --porcelain` on a fixture holding
#                                 that untracked file printed nothing — the file
#                                 was hidden by host state.
#   GIT_CONFIG_COUNT=2 pair       the environment-config layer (see below)
#
# # Why a managed FILE and not /dev/null (MEASURED 2026-10-12, git 2.54.0)
#
# `GIT_CONFIG_GLOBAL=/dev/null git config --global user.name Probe` exits 255
# with `error: could not lock config file /dev/null: Operation not permitted` —
# git WRITES `/dev/null.lock` before it writes the config. A test that
# legitimately configures its own fixture global scope (`landing.test.sh`:
# `git config --global user.name "Landing Test"`) therefore fails at setup, and
# every later commit fails for the missing identity: sourcing this helper with
# /dev/null turned landing.test.sh from 55/0 green to 21/34 RED, the failures
# traced to four `could not lock config file /dev/null` lines. An empty file
# inside the scratch root excludes the host's global config exactly as
# completely and stays writable — `--get` returns 1 (unset) and `--global`
# writes land in the fixture's own file.
#
# Those four close every FILE source. They do not close the highest-precedence
# source, git's environment config, and they do not close a REPO-LOCAL config a
# fixture wrote itself — a repository's own config is always read (a clone does
# NOT copy the source repo's config; what the environment layer beats is config
# the fixture wrote itself, e.g. a fixture that sets its own core.hooksPath,
# or one built from a template dir). So the two keys that carry authority are
# ALSO set at environment-config scope:
#
#   GIT_CONFIG_COUNT=2
#   GIT_CONFIG_KEY_0=core.hooksPath  VALUE_0=<an EMPTY dir created under the root>
#   GIT_CONFIG_KEY_1=commit.gpgsign VALUE_1=false
#
# MEASURED 2026-10-12 (git 2.54.0): environment config OUTRANKS a repo-local
# `core.hooksPath` and a repo-local `commit.gpgsign=true`
# (`git config --get core.hooksPath` returned the env value, not the local one),
# so with this helper sourced a fixture can neither sign nor run a hook from ANY
# config file — host or fixture-written. An exported GIT_CONFIG_PARAMETERS would
# outrank even this pair (MEASURED, r1-correctness), which is why the inherited
# environment class is scrubbed before these assignments — see below.
#
# # The inherited GIT_* environment class is scrubbed
#
# The layers above are FILE- and assignment-level. They do not remove what git
# reads from the INHERITED environment: repo discovery (GIT_DIR, GIT_WORK_TREE,
# GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES,
# GIT_COMMON_DIR, GIT_PREFIX, …), the raw environment-config blob
# (GIT_CONFIG_PARAMETERS — `git -c … rebase -x '<cmd>'` exports it to the exec'd
# command), config-file redirection (GIT_CONFIG) and the attribute/SSH/ceiling
# knobs. MEASURED (r1-correctness, pinned by the hostile self-test): with
# GIT_DIR=<outer>/.git exported, `git -C fx init` created NO fixture `.git` and
# `git -C fx rev-parse --git-dir` printed the OUTER repo — fixture commits would
# mutate the operator's real repository. So the body unsets the whole class
# BEFORE it sets its own values: the names from `git rev-parse --local-env-vars`
# (enumerated from git itself, so the list follows the installed version), plus
# every inherited ^GIT_[A-Z0-9_]+$ name from `env` (which covers
# GIT_CONFIG_COUNT/KEY_n/VALUE_n and any knob a later git adds).
# Two families are deliberately NOT scrubbed, because this file defines or
# neutralises them immediately afterwards — and a pre-set hostile value must stay
# visible for the tests that prove this file wins over it:
#   GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM / GIT_CONFIG_NOSYSTEM  (re-exported below)
#   GIT_CONFIG_COUNT / GIT_CONFIG_KEY_* / GIT_CONFIG_VALUE_*     (the default
#   branch's COUNT=2 overwrites KEY_0/VALUE_0 and shadows any higher index; the
#   opt-out branch pins COUNT=0, which neutralises the whole family)
#
# # Callers that deliberately test repo-local hooks/signing
#
# Because environment config outranks local config, this helper also outranks a
# test's OWN deliberate local config. A test whose SUBJECT is a real hook (it
# installs .githooks and pushes expecting refusal) must set
# `CSQ_GIT_ISOLATION_KEEP_REPO_CONFIG=1` BEFORE sourcing: the file-level
# neutralisation above still applies, and the env-config pair is replaced by
# COUNT=0 so the repo-local config the test wrote is the one git reads — an
# inherited COUNT/KEY/VALUE trio cannot leak through this branch.
#
# # Cleanup — the scratch root is owned here and reaped three ways
#
# The root is a fresh `mktemp -d` under $TMPDIR keyed to the PID of the process
# that is actually running this file (`$BASHPID`, or on bash 3.2 — which has no
# BASHPID — the parent of a throwaway `sh`; NEVER `$$`, which inside `( … )` or
# `$( … )` is the PARENT shell's PID and let a second source's sweep delete a
# live subshell's root once that parent had exited), and this file owns its
# reaping:
#
#   1. An EXIT trap COMPOSED with the caller's: the caller's trap (if any) is
#      captured with `trap -p EXIT` BEFORE installing, and this file's handler
#      runs its own cleanup FIRST, then replays the caller's trap command (the
#      command text is recovered by letting the shell re-parse its own `trap -p`
#      output, so embedded single quotes survive; a replay that exits non-zero is
#      reported to stderr under a fixed tag, never swallowed), then re-exits with
#      the caller's status. The caller's teardown therefore still
#      runs exactly once, with the caller's positional parameters — installing a
#      plain trap from a sourced file is what
#      would silently disable every fixture teardown in scripts/tests/.
#      A caller that installs its OWN trap AFTER sourcing still replaces this
#      one (bash: the last trap wins) and the root then survives until (2) reaps
#      it. So every caller in scripts/tests/ installs its trap BEFORE this
#      source (or composes through it), and the census
#      (git-isolation-census.test.sh) turns red on a trap-after-source.
#   2. A SWEEP at source time: every `csq-git-isolation.<pid>.*` directory whose
#      owner PID is no longer alive is removed — which also covers a SIGKILLed
#      run, where no trap of any kind can fire. Directories are reaped only when
#      this user owns them; a foreign repo's second copy of this helper names its
#      roots the same way and is identified here by PID liveness, not by name.
#      Older roots written before this file recorded a PID at all are reaped only
#      past a 60-minute age gate, so a concurrently-running older copy is safe.
#   3. The root is deliberately NOT nested under $TMPROOT. $TMPROOT can be
#      INHERITED (an exported variable from an outer process), and keying on it
#      both collides between sibling children (same `$TMPROOT/git-isolation`
#      path, one child truncating another's `.gitconfig`) and writes into a tree
#      this shell was handed rather than created.
#
# # Idempotent re-source
#
# Sourcing twice is a no-op. That is load-bearing beyond hygiene: callers
# deliberately REPLACE these values later (dev-preflight.test.sh's SIGN_PROBE
# re-exports GIT_CONFIG_GLOBAL pointing at a hostile fixture config to prove the
# fixture ignores it), and a second source must not clobber the caller's
# deliberate override.
#
# Usage:
#   . "$HERE/../lib/git-isolation.sh"
#
# Falsifier: with this file sourced, `git config --get commit.gpgsign` inside a
# repo whose LOCAL config sets it true prints `false`; a hostile
# GIT_CONFIG_GLOBAL, GIT_CONFIG_PARAMETERS, GIT_DIR or XDG ignore file exported
# BEFORE the source has no effect; a foreign $TMPROOT is not written into; the
# scratch root is gone once the sourcing shell exits. Without it, the same
# fixture prints `true` and `git commit` fails against a signing program that
# exits non-zero — the discriminators scripts/tests/git-isolation-hostile-config.test.sh pins.

# Source-only helper: `. git-isolation.sh`. A failure below EXITS the sourcing
# script rather than returning — fail closed, so a test runs with no isolation
# only if someone deliberately ignores a FATAL line, never by default.
#
# Idempotent: a second source is a no-op (see the header — a re-source must not
# clobber a caller's later deliberate override).
if [ -n "${_CSQ_GIT_ISOLATION_SOURCED:-}" ]; then
    return 0
fi
_CSQ_GIT_ISOLATION_SOURCED=1

# ── internal helpers ────────────────────────────────────────────────────────

# Unset one inherited variable, except the config-layer families this file
# defines or neutralises itself (see the header: excluding them keeps a hostile
# pre-set value observable to the tests that prove this file wins).
_csq_git_isolation_unset_one() { # name
    case "$1" in
        GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_COUNT) return 0 ;;
        GIT_CONFIG_KEY_*|GIT_CONFIG_VALUE_*) return 0 ;;
    esac
    unset "$1" 2>/dev/null || true
    return 0
}

# Remove every inherited GIT_* variable the helper does not itself define.
_csq_git_isolation_scrub_env() {
    _csq_gi_names=""
    if command -v git >/dev/null 2>&1; then
        _csq_gi_names="$(git rev-parse --local-env-vars 2>/dev/null || true)"
    fi
    # Static fallback when git cannot be asked (absent, or made to fail by the
    # very environment being scrubbed). Never the only path: the `env` sweep
    # below is independent of it.
    if [ -z "$_csq_gi_names" ]; then
        _csq_gi_names='GIT_DIR
GIT_WORK_TREE
GIT_IMPLICIT_WORK_TREE
GIT_INDEX_FILE
GIT_OBJECT_DIRECTORY
GIT_ALTERNATE_OBJECT_DIRECTORIES
GIT_COMMON_DIR
GIT_NAMESPACE
GIT_CONFIG
GIT_CONFIG_PARAMETERS
GIT_TEMPLATE_DIR
GIT_PREFIX
GIT_GRAFT_FILE
GIT_NO_REPLACE_OBJECTS
GIT_REPLACE_REF_BASE
GIT_SHALLOW_FILE'
    fi
    while IFS= read -r _csq_gi_name; do
        case "$_csq_gi_name" in
            ''|*[!A-Za-z0-9_]*) continue ;;
        esac
        _csq_git_isolation_unset_one "$_csq_gi_name"
    done <<EOF
$(printf '%s\n' "$_csq_gi_names")
EOF
    # …then every inherited GIT_* name, from the environment itself. This is the
    # arm that follows a git version: GIT_CONFIG_COUNT/KEY_n/VALUE_n, GIT_ATTR_*,
    # GIT_SSH*, GIT_CEILING_DIRECTORIES and anything added later are covered
    # without this file naming them.
    while IFS= read -r _csq_gi_line; do
        _csq_gi_name="${_csq_gi_line%%=*}"
        case "$_csq_gi_name" in
            GIT_[A-Z0-9_]*) ;;
            *) continue ;;
        esac
        case "$_csq_gi_name" in
            *[!A-Za-z0-9_]*) continue ;;
        esac
        _csq_git_isolation_unset_one "$_csq_gi_name"
    done <<EOF
$(env)
EOF
    return 0
}

# 0 when a legacy (pre-PID) root is past the age gate. The verdict is find's
# OUTPUT, never its exit status: `find ... -mmin +60` exits 0 whether or not it
# printed anything, so an exit-status check would call every young directory
# aged. A `find` that cannot answer (an unsupported predicate errors on GNU and
# BSD alike) prints nothing, so an unmeasurable age never reaps anything.
_csq_git_isolation_old_enough() { # dir
    [ -n "$(find "$1" -maxdepth 0 -mmin +60 2>/dev/null || true)" ]
}

# Reap scratch roots whose owning shell is gone (see the header, arm 2).
_csq_git_isolation_sweep() {
    _csq_gi_swept="${_CSQ_GI_TMP:-${TMPDIR:-/tmp}}"
    for _csq_gi_dir in "$_csq_gi_swept"/csq-git-isolation.*; do
        [ -d "$_csq_gi_dir" ] || continue
        [ -O "$_csq_gi_dir" ] || continue            # never another user's directory
        _csq_gi_rest="${_csq_gi_dir##*/}"
        _csq_gi_rest="${_csq_gi_rest#csq-git-isolation.}"
        case "$_csq_gi_rest" in
            *.*) _csq_gi_pid="${_csq_gi_rest%%.*}" ;;
            *)   _csq_gi_pid="" ;;
        esac
        case "$_csq_gi_pid" in
            ''|*[!0-9]*)                             # no owner recorded: age gate only
                if _csq_git_isolation_old_enough "$_csq_gi_dir"; then
                    rm -rf "$_csq_gi_dir" 2>/dev/null || true
                fi
                continue ;;
        esac
        [ "$_csq_gi_pid" = "${_CSQ_GI_PID:-$$}" ] && continue        # our own root, if re-sourced oddly
        if ! kill -0 "$_csq_gi_pid" 2>/dev/null; then
            rm -rf "$_csq_gi_dir" 2>/dev/null || true
        fi
    done
    return 0
}

# Remove this shell's scratch root. Idempotent.
_csq_git_isolation_cleanup() {
    if [ -n "${_CSQ_GIT_ISOLATION_ROOT:-}" ] && [ -d "$_CSQ_GIT_ISOLATION_ROOT" ]; then
        rm -rf "$_CSQ_GIT_ISOLATION_ROOT" 2>/dev/null || true
    fi
    return 0
}

# Recover the caller's trap COMMAND from `trap -p EXIT` output by letting the
# shell parse its own quoting: the printed line is `trap -- 'CMD' EXIT` with each
# embedded single quote written `'\''`, so `eval "set -- <line>"` yields
# $1=trap $2=-- $3=CMD $4=EXIT with CMD exactly as the caller wrote it (MEASURED
# on bash 3.2). It runs in its own function so the `set --` cannot disturb the
# script's positional parameters, which the replay must still hand to the caller.
# Prints nothing and returns 1 for any other shape.
_csq_git_isolation_prev_cmd() { # <trap -p line>
    _csq_gi_line="$1"
    eval "set -- $_csq_gi_line" 2>/dev/null || return 1
    [ "$#" -eq 4 ] && [ "$1" = trap ] && [ "$2" = -- ] && [ "$4" = EXIT ] || return 1
    printf '%s' "$3"
}

# The composed EXIT handler: our cleanup first, then the caller's trap, then the
# caller's exit status. A trap line in a shape the shell does not print for
# `trap -p` is reported, not guessed at — and bash gives no fallback there (it
# will not run a trap installed from inside its own EXIT trap, MEASURED), so the
# caller's teardown is lost and only this file's cleanup runs.
_csq_git_isolation_on_exit() {
    _csq_gi_rc=$?
    _csq_git_isolation_cleanup
    if [ -n "${_CSQ_GIT_ISOLATION_PREV_TRAP:-}" ]; then
        if _csq_gi_prev_cmd="$(_csq_git_isolation_prev_cmd "$_CSQ_GIT_ISOLATION_PREV_TRAP")"; then
            if [ -n "$_csq_gi_prev_cmd" ]; then
                eval "$_csq_gi_prev_cmd"
                _csq_gi_prev_rc=$?
                if [ "$_csq_gi_prev_rc" -ne 0 ]; then
                    echo "git-isolation: caller EXIT trap exited rc=$_csq_gi_prev_rc" >&2
                fi
            fi
        else
            echo "git-isolation: caller EXIT trap not replayed (unrecognised trap -p shape)" >&2
        fi
    fi
    exit "$_csq_gi_rc"
}

# ── the body ────────────────────────────────────────────────────────────────

# The PID of THIS process. `$BASHPID` where bash has it (4+); bash 3.2 does not,
# and `$$` is wrong inside a subshell, so ask a child `sh` for its parent: in
# `$(exec sh -c …)` the forked subshell becomes `sh`, whose PPID is the process
# that forked it — this one, subshell or not.
if [ -n "${BASHPID:-}" ]; then
    _CSQ_GI_PID="$BASHPID"
else
    _CSQ_GI_PID="$(exec sh -c 'echo $PPID')"
fi
case "$_CSQ_GI_PID" in
    ''|*[!0-9]*) _CSQ_GI_PID="$$" ;;
esac

_CSQ_GI_TMP="${TMPDIR:-/tmp}"
_CSQ_GI_TMP="${_CSQ_GI_TMP%/}"
[ -n "$_CSQ_GI_TMP" ] || _CSQ_GI_TMP=/tmp

# Scrub BEFORE creating anything: a hostile GIT_DIR must not reach a single git
# invocation, and the sweep below must run under the same environment as the
# rest of this file.
_csq_git_isolation_scrub_env
_csq_git_isolation_sweep

# The scratch root: a fresh mktemp -d this file owns and reaps, PID-stamped for
# the sweep. Never keyed on $TMPROOT — see the header, arm 3.
_CSQ_GIT_ISOLATION_ROOT="$(mktemp -d "$_CSQ_GI_TMP/csq-git-isolation.$_CSQ_GI_PID.XXXXXX")" || {
    echo "FATAL: git-isolation: cannot create a scratch dir — no isolation applied" >&2
    exit 1
}
# The trap goes on as soon as a root exists, so every later FATAL exit reaps it.
_CSQ_GIT_ISOLATION_PREV_TRAP="$(trap -p EXIT 2>/dev/null || true)"
# "$@" is passed through so a caller's trap that reads positional parameters
# still sees the SCRIPT's, not the handler function's (bash gives a function its
# own "$@"; without this, a trap ending in `>> "$2"` would write to a path the
# caller never named).
trap '_csq_git_isolation_on_exit "$@"' EXIT

mkdir -p "$_CSQ_GIT_ISOLATION_ROOT/home" "$_CSQ_GIT_ISOLATION_ROOT/empty-hooks" || {
    echo "FATAL: git-isolation: cannot create $_CSQ_GIT_ISOLATION_ROOT — no isolation applied" >&2
    exit 1
}

# File-level sources, and $HOME. Never the real HOME: that would edit the
# operator's actual ~/.gitconfig, which no test fixture may do.
_GIT_ISO_GLOBAL_CONFIG="$_CSQ_GIT_ISOLATION_ROOT/home/.gitconfig"
: > "$_GIT_ISO_GLOBAL_CONFIG" || {
    echo "FATAL: git-isolation: cannot create $_GIT_ISO_GLOBAL_CONFIG" >&2
    exit 1
}
export GIT_CONFIG_GLOBAL="$_GIT_ISO_GLOBAL_CONFIG"
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1

_csq_git_isolation_real_home="$HOME"
export HOME="$_CSQ_GIT_ISOLATION_ROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"

# The HOME redirect must not break the toolchains a shell test may legitimately
# invoke (MEASURED: after the redirect, bare `cargo --version` fails with
# "rustup could not choose a version of cargo to run"). Each home is preserved
# from the pre-redirect HOME when the host already exported one, and otherwise
# pointed at the real one when it exists; when the directory does not exist
# there is nothing to preserve.
#
# gh is deliberately NOT in that list. Preserving GH_CONFIG_DIR would hand the
# operator's live gh login (a token able to act on real repositories) to every
# sourcing test, and no fixture needs it: the HOME redirect already leaves `gh`
# with no login, which is the state CI runs in. An inherited GH_CONFIG_DIR is
# unset for the same reason — as is every other inherited credential that gh,
# git or ssh would read: GH_TOKEN, GITHUB_TOKEN, GH_ENTERPRISE_TOKEN,
# GITHUB_ENTERPRISE_TOKEN, and the SSH agent/askpass family (SSH_AUTH_SOCK,
# SSH_ASKPASS, SSH_ASKPASS_REQUIRE). GIT_ASKPASS, GIT_SSH and GIT_SSH_COMMAND
# are already gone with the GIT_* scrub above (Case I pins all of them).
if [ -n "${RUSTUP_HOME:-}" ]; then
    export RUSTUP_HOME
elif [ -d "$_csq_git_isolation_real_home/.rustup" ]; then
    export RUSTUP_HOME="$_csq_git_isolation_real_home/.rustup"
fi
if [ -n "${CARGO_HOME:-}" ]; then
    export CARGO_HOME
elif [ -d "$_csq_git_isolation_real_home/.cargo" ]; then
    export CARGO_HOME="$_csq_git_isolation_real_home/.cargo"
fi
unset GH_CONFIG_DIR GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN \
    SSH_AUTH_SOCK SSH_ASKPASS SSH_ASKPASS_REQUIRE

# Environment-level overrides: the only layer that outranks a repo-LOCAL config
# (see the header). On the opt-out the pair is replaced by COUNT=0 — leaving the
# inherited COUNT/KEY/VALUE trio live would let it outrank the repo-local config
# this branch exists to preserve.
if [ "${CSQ_GIT_ISOLATION_KEEP_REPO_CONFIG:-}" = "1" ]; then
    export GIT_CONFIG_COUNT=0
else
    export GIT_CONFIG_COUNT=2
    export GIT_CONFIG_KEY_0=core.hooksPath
    export GIT_CONFIG_VALUE_0="$_CSQ_GIT_ISOLATION_ROOT/empty-hooks"
    export GIT_CONFIG_KEY_1=commit.gpgsign
    export GIT_CONFIG_VALUE_1=false
fi
