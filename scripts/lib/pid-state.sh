#!/usr/bin/env bash
#
# pid-state.sh — three-state process liveness for shell self-tests. Source it.
#
# WHY THIS EXISTS
# ---------------
# `kill -0 <pid>` answers "does a process-table ENTRY exist", not "is the process
# alive". A process that was SIGKILLed but not yet reaped is a ZOMBIE: its entry
# stays until its parent (or, once the parent is gone, the nearest
# PR_SET_CHILD_SUBREAPER ancestor or pid 1) calls wait. Under fleet load a
# reaper can be late, and `kill -0` then succeeds on a process that is dead —
# a self-test row that asks "did the kill land" reads a landed kill as a miss
# (test-watchdog.test.sh case B: "expected no, got yes", reproduced
# deterministically with a subreaper that never reaps: state Z, kill -0 ok).
# The same blindness flips the other way on "was NOT signalled" rows: a killed
# zombie reads as alive, so the row passes without observing the absence.
#
# CONTRACT
# --------
#   pid_state <pid> [identity]
#       stdout  dead | alive | UNDETERMINED:<reason>
#       rc      0 dead · 1 alive · 2 undetermined
#       dead    = no process-table entry, OR state Z/X (zombie / dead), OR an
#                 `identity` was given and the pid's CURRENT start identity
#                 differs (the original process is gone; the pid was recycled).
#       FAIL CLOSED: a state that cannot be read is NEVER dead. The reason is
#                 named (bad-pid, proc-entry-unreadable, proc-stat-unparsable,
#                 ps-unreadable-rc<N>).
#   pid_dead <pid> [identity]
#       rc 0 only for dead; 1 alive; 2 undetermined (also printed to stderr as
#       PID_STATE_UNDETERMINED pid=… reason=…, so a polling row that reads it as
#       "not dead" still names why).
#   pid_identity <pid>
#       stdout  a start-identity token (capture it while the process is alive,
#               pass it back to pid_state/pid_dead). rc 0 read · 1 gone · 2 unreadable.
#
# SOURCES: Linux reads /proc/<pid>/stat (state + starttime, field 22, no child
# process). Where /proc is unusable (darwin) it uses `ps -o stat= -o lstart= -p`,
# and calls a pid gone only when ps reports "no such process" (rc 1, empty) AND
# `kill -0` also fails. PID_STATE_PROC_ROOT overrides /proc (test seam).
# shellcheck shell=bash

# Sets _PS_STATE _PS_ID _PS_WHY. rc 0 read · 1 gone · 2 unreadable.
_pid_state_read() {
  local pid="$1" root="${PID_STATE_PROC_ROOT:-/proc}" raw="" rest out rc=0
  _PS_STATE=""; _PS_ID=""; _PS_WHY=""
  case "$pid" in '' | *[!0-9]*) _PS_WHY="bad-pid"; return 2 ;; esac
  if [ -r "$root/$$/stat" ]; then
    # The root is usable: this shell's own entry reads. A pid whose entry cannot
    # be read AND does not exist is gone; one that exists but cannot be read
    # (hidepid, permissions) is unreadable, never gone.
    if { read -r raw < "$root/$pid/stat"; } 2> /dev/null && [ -n "$raw" ]; then
      rest="${raw##*) }"
      # shellcheck disable=SC2086 # deliberate word split of the stat fields
      set -- $rest
      _PS_STATE="${1:-}"; _PS_ID="${20:-}"
      [ -n "$_PS_STATE" ] || { _PS_WHY="proc-stat-unparsable"; return 2; }
      return 0
    fi
    if [ -e "$root/$pid" ]; then _PS_WHY="proc-entry-unreadable"; return 2; fi
    return 1
  fi
  out="$(LC_ALL=C ps -o stat= -o lstart= -p "$pid" 2> /dev/null)" || rc=$?
  if [ -n "$out" ]; then
    # shellcheck disable=SC2086 # deliberate word split: "<stat> <lstart words>"
    set -- $out
    _PS_STATE="$1"; shift; _PS_ID="$*"
    return 0
  fi
  if [ "$rc" -eq 1 ] && ! kill -0 "$pid" 2> /dev/null; then return 1; fi
  _PS_WHY="ps-unreadable-rc$rc"
  return 2
}

pid_state() { # <pid> [identity]
  local rc=0
  _pid_state_read "$1" || rc=$?
  case $rc in
    1) echo dead; return 0 ;;
    2) echo "UNDETERMINED:$_PS_WHY"; return 2 ;;
  esac
  case "$_PS_STATE" in Z* | X* | x*) echo dead; return 0 ;; esac
  if [ -n "${2:-}" ] && [ "$_PS_ID" != "$2" ]; then echo dead; return 0; fi
  echo alive
  return 1
}

pid_dead() { # <pid> [identity]
  local s rc=0
  s="$(pid_state "$@")" || rc=$?
  if [ "$rc" -eq 2 ]; then
    printf 'PID_STATE_UNDETERMINED pid=%s reason=%s\n' "$1" "${s#UNDETERMINED:}" >&2
  fi
  return "$rc"
}

pid_identity() { # <pid>
  local rc=0
  _pid_state_read "$1" || rc=$?
  case $rc in
    0) printf '%s\n' "$_PS_ID"; return 0 ;;
    1) return 1 ;;
  esac
  printf 'PID_STATE_UNDETERMINED pid=%s reason=%s\n' "$1" "$_PS_WHY" >&2
  return 2
}
