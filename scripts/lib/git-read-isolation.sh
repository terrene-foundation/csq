#!/usr/bin/env bash
#
# git-read-isolation.sh — ONE isolated `git` read, shared by every program that
# decides whether an untrusted push may land.
#
# Sourcing this file defines one public function:
#
#   git_ro [git args...]
#
# which runs `git --no-replace-objects` with every inherited GIT_* variable
# unset, system config disabled and the global config pinned to /dev/null.
# The caller's environment is left untouched — the isolation applies to the
# single invocation.
#
# CALLERS. scripts/verify/dev-push-guard.sh and .githooks/pre-push.
# Before this file existed the helper was inline in the guard, so the guard's
# eight reads were isolated and the hook's reads were not: exactly the
# per-call-site shape where a fix is forgotten at the next call site, written by
# someone who never read the first one. Both programs now source THIS file, so
# there is one isolation to maintain and one place to change.
#
# WHY A READ MUST BE ISOLATED AT ALL. `git replace <object> <benign>` substitutes
# an object REPOSITORY-WIDE, so a replaced HEAD, remote tip or guard blob makes
# every read see a benign history while the actual push carries anything.
# GIT_DIR / GIT_OBJECT_DIRECTORY / GIT_ALTERNATE_OBJECT_DIRECTORIES can point a
# read at a different repository entirely, and a hostile global or system config
# can inject a diff driver or alter pathspec matching. A guard that decides
# whether an untrusted party's push may land must not read that decision through
# state the same party can set.
#
# --no-replace-objects is the authoritative switch against replacement;
# GIT_NO_REPLACE_OBJECTS=1 is belt-and-braces. GIT_CONFIG_NOSYSTEM and
# GIT_CONFIG_GLOBAL=/dev/null drop system and user config.
#
# THE UNSET LIST IS DERIVED, NOT HAND-TYPED (R1 security H-1). The first version
# of this helper unsets seven variables chosen by hand, and a reviewer showed
# that was incorrect against git's OWN enumeration. Re-deriving a shorter list
# here was the mistake: a hand-maintained subset drifts below git's own surface
# every release. The block below therefore builds the list from three arms —
# git's enumeration, a fixed tail of names git honours without enumerating them,
# and a sweep of whatever the environment actually carries. The arms are a
# UNION, never a fallback chain: a dry first arm never hides a later one.
#
#   ARM 1  `git rev-parse --local-env-vars` — the authority for what THIS git
#          reads, and the arm that follows a git upgrade which adds a variable.
#          It prints names, not values, and works outside a repository (measured
#          on git 2.56.0 from cwd=/), so sourcing this file does not depend on
#          the caller's working directory.
#   ARM 2  names git honours but does NOT enumerate. MEASURED on git 2.54:
#          `--local-env-vars` omits GIT_NAMESPACE and the pathspec-magic four
#          entirely, so an enumeration-only scrub would leave them set on every
#          machine where git answers — which is every machine.
#   ARM 3  whatever the caller actually exported: every ^GIT_[A-Z0-9_]+$ name in
#          `env`. Arms 1 and 2 can only unset names someone predicted; this arm
#          unsets every GIT_* the environment carries, including one a later git
#          introduces.
#
# GIT_CONFIG_COUNT gates the numbered GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n
# family, and the family names ARE harvested by arm 3 (they match the ^GIT_[A-Z0-9_]+$
# filter). Unsetting the COUNT is therefore redundant belt-and-braces rather than
# the only cover: with COUNT unset git reads no environment config at all, so
# the whole family is disabled whatever KEY_n / VALUE_n names survive.
#
# GIT_NAMESPACE IS UNSET AS DEFENCE, NOT AS A DEMONSTRATED FIX. A reviewer
# reported it substitutes what `rev-parse HEAD` returns; a direct probe with a
# real refs/namespaces/<ns>/... ref created does NOT reproduce that on git 2.54
# (the un-namespaced HEAD comes back), and that negative result is recorded in
# scripts/tests/dev-push-guard.test.sh rather than being papered over by a green
# assertion. It remains a documented repository-selection variable, it costs
# nothing to unset, and a future git may honour it where this one does not.
#
# WHY NOT scripts/lib/git-isolation.sh. That helper isolates a whole TEST
# FIXTURE: it rewrites HOME and XDG_CONFIG_HOME, materialises a scratch global
# config file and installs a composed EXIT trap. That is the right shape for a
# test harness and the wrong shape for a per-command wrapper inside a gate an
# operator's push depends on — it must not edit the caller's HOME or its traps.
# Its ENUMERATION MODEL is reproduced here (arms 1–3 above); it is not sourced
# and its fixture machinery is not copied.
#
# CONTRACT
#   - Source it. It defines `git_ro` and `GIT_RO_UNSET`, and runs exactly one
#     `git` (arm 1) at source time. It sets no shell options, so it can never
#     turn on `set -e`/`set -u` behind the caller's back.
#   - Safe under `set -u` and under `set -e`. bash 3.2 compatible (this repo's
#     /bin/bash): no associative arrays, no BASHPID, no ${var,,}.
#   - Position-independent: the only path it names is absolute (/dev/null), and
#     it reads no file relative to the cwd. A caller that needs a specific
#     repository passes `-C <dir>` like any other git flag.
#   - Idempotent BY REBUILDING, never by skipping: every source redefines
#     `git_ro` and re-derives `GIT_RO_UNSET` from the CURRENT environment, so a
#     caller never inherits stale state and nothing the environment can pre-set
#     decides whether the definitions happen (see the H-1 note in the body).
#
# FALSIFIER. With this file sourced, `git_ro show <sha>:<path>` prints the REAL
# blob while bare git prints the replacement's, and a hostile GIT_DIR exported
# by the caller does not redirect a read. Both directions are pinned in
# scripts/tests/dev-push-guard.test.sh; the hook's rewind read is pinned in
# scripts/tests/githooks-pre-push.test.sh.

# Source-only helper: `. git-read-isolation.sh`. A caller that runs it as a
# program gets the usual bash "command not found" — it defines nothing itself.
#
# NO "ALREADY SOURCED" MARKER, DELIBERATELY (review finding H-1). A marker
# read from a variable can be pre-set in the environment of the very process
# that sources this file, and a non-emptiness test cannot tell that from a real
# re-source. Skipping would not even be merely fail-closed: bash imports
# exported functions from the environment into non-interactive shells, so an
# exported `git_ro` would survive precisely because our definition never runs,
# and every call site would be answered by the attacker's function. Rebuilding
# the definition and the unset list on every source is behaviourally idempotent
# — the same function for the same environment — and costs microseconds, so
# there is nothing worth skipping.

GIT_RO_UNSET=()
_git_ro_names=""
{
  # ARM 1 — git's own enumeration. The `|| true` is deliberate: a host with no
  # git (or one whose git refuses under the very environment being scrubbed)
  # must still get arms 2 and 3, and the caller's own `command -v git` check
  # decides what that means for it.
  _git_ro_names="$(git rev-parse --local-env-vars 2>/dev/null || true)"
  # ARM 2 — names git honours but does NOT enumerate (see the header).
  _git_ro_names="$_git_ro_names
GIT_NAMESPACE
GIT_LITERAL_PATHSPECS
GIT_GLOB_PATHSPECS
GIT_NOGLOB_PATHSPECS
GIT_ICASE_PATHSPECS
GIT_CONFIG_COUNT"
  # ARM 3 — whatever the caller actually exported (see the header).
  _git_ro_names="$_git_ro_names
$(env | sed -n 's/^\(GIT_[A-Z0-9_]*\)=.*/\1/p')"
  # The charset filter is not cosmetic: a name carrying `=` or a newline would
  # become two argv words to `env`, and `env -u a=b` is an error rather than an
  # unset. Anything that is not a plain shell identifier is skipped.
  while IFS= read -r _git_ro_name; do
    case "$_git_ro_name" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    GIT_RO_UNSET+=(-u "$_git_ro_name")
  done <<EOF
$_git_ro_names
EOF
}
# The accumulator is an implementation detail; leaving it set would leak a
# generic name into the caller's namespace.
unset _git_ro_names _git_ro_name

git_ro() {
  # "${GIT_RO_UNSET[@]}" is SAFE UNDER `set -u` because the array is never
  # empty: arm 2 contributes seven names unconditionally, so this holds on a
  # host with no git at all. (bash 3.2 treats an EMPTY array expansion as an
  # unbound variable, which is why the non-empty property is stated here rather
  # than left implicit.) If a future edit empties every arm, the first call
  # fails loudly instead of running git unisolated — fail closed, which is the
  # correct direction for this helper.
  env "${GIT_RO_UNSET[@]}" \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    git --no-replace-objects "$@"
}
