#!/usr/bin/env bash
# ci-gate: runner capability
#
# assert-runner-prereqs — verify THIS runner provides what the job needs,
# before the job spends 40 minutes discovering it does not.
#
# WHY THIS EXISTS
# ---------------
# csq's org runner pool holds two disjoint Linux fleets that both answer to
# `[self-hosted, Linux, X64]`. Jobs that named only those three labels landed on
# the under-provisioned fleet ~20% of the time. The resulting failures did not
# look like a routing problem — they looked like three unrelated flakes:
#   * eval-harness tests asserting on empty output (`skipped_cli_missing`)
#   * `Rust tests (enterprise)`: "claude binary not found on PATH"
#   * "the runner lost passwordless sudo" (it never had it; an internal ticket)
# Pinning `ci-portable` routes around it. This asserts the capability directly,
# so a runner that is mislabelled, or a fleet provisioned differently next
# quarter, fails in SECONDS with a message that names the runner and the missing
# prerequisite — instead of late, and pointing at the wrong thing.
#
# USAGE
#   bash scripts/ci/assert-runner-prereqs.sh rust claude-cli
#   bash scripts/ci/assert-runner-prereqs.sh --selftest
#
# EXIT CODES — three outcomes, deliberately (durable-instruments.md MUST-2)
#   0  OK            every named profile is satisfied
#   1  MISSING       a prerequisite is genuinely absent on this runner
#   2  UNDETERMINED  the check could not be made (bad profile name, unreadable
#                    or unparseable manifest, no python3). NEVER folded into 0:
#                    "I could not look" and "it is present" are different claims,
#                    and collapsing them is how a green run certifies nothing.
#
# TEST HOOKS (self-test only; never set in CI)
#   PREREQ_FAKE_MISSING_BIN   colon-list of binaries to treat as absent
#   PREREQ_FAKE_MISSING_PKG   colon-list of packages to treat as absent
#   PREREQ_MANIFEST           override manifest path
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${PREREQ_MANIFEST:-$HERE/runner-prereqs.json}"

OK=0; MISSING=1; UNDETERMINED=2

undetermined() { echo "assert-runner-prereqs: UNDETERMINED — $*" >&2; exit "$UNDETERMINED"; }

# Runner identity, printed on every run. A failure that does not name the host
# sends the reader to the diff instead of to the fleet.
runner_id() {
  printf 'runner=%s host=%s user=%s labels=%s\n' \
    "${RUNNER_NAME:-<unset>}" "$(hostname 2>/dev/null || echo '<unknown>')" \
    "$(id -un 2>/dev/null || echo '<unknown>')" "${RUNNER_LABELS:-<unset>}"
}

have_bin() {
  case ":${PREREQ_FAKE_MISSING_BIN:-}:" in *":$1:"*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}

have_pkg() {
  case ":${PREREQ_FAKE_MISSING_PKG:-}:" in *":$1:"*) return 1 ;; esac
  # Absence of dpkg is not absence of the package — it is inability to tell.
  command -v dpkg-query >/dev/null 2>&1 || return 2
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"
}

[ "${1:-}" = "--selftest" ] && { exec bash "$HERE/../tests/assert-runner-prereqs.test.sh"; }
[ $# -eq 0 ] && undetermined "no profile named; usage: $0 <profile>..."
command -v python3 >/dev/null 2>&1 || undetermined "python3 is required to read the manifest"
[ -r "$MANIFEST" ] || undetermined "manifest not readable at $MANIFEST"

for profile in "$@"; do
  spec="$(python3 - "$MANIFEST" "$profile" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"__ERR__ manifest is not valid JSON: {e}"); raise SystemExit(0)
p = (d.get("profiles") or {}).get(sys.argv[2])
if p is None:
    print(f"__ERR__ no such profile '{sys.argv[2]}'; known: "
          + ",".join(sorted((d.get('profiles') or {}))))
    raise SystemExit(0)
print("BIN " + " ".join(p.get("binaries") or []))
print("PKG " + " ".join(p.get("packages") or []))
print("SUDO " + ("yes" if p.get("needs_sudo") else "no"))
print("WHY " + (p.get("why") or ""))
PY
)" || undetermined "manifest reader failed for profile '$profile'"

  case "$spec" in __ERR__*) undetermined "${spec#__ERR__ }" ;; esac

  bins=$(printf '%s\n' "$spec" | sed -n 's/^BIN //p')
  pkgs=$(printf '%s\n' "$spec" | sed -n 's/^PKG //p')
  sudo_req=$(printf '%s\n' "$spec" | sed -n 's/^SUDO //p')
  why=$(printf '%s\n' "$spec" | sed -n 's/^WHY //p')

  missing=""
  unknown=""
  for b in $bins; do have_bin "$b" || missing="$missing binary:$b"; done
  for p in $pkgs; do
    have_pkg "$p"; rc=$?
    [ "$rc" -eq 1 ] && missing="$missing package:$p"
    [ "$rc" -eq 2 ] && unknown="$unknown package:$p"
  done
  if [ "$sudo_req" = "yes" ] && ! sudo -n true 2>/dev/null; then
    missing="$missing capability:passwordless-sudo"
  fi

  if [ -n "$unknown" ]; then
    runner_id >&2
    undetermined "cannot verify$unknown on this runner (no dpkg-query). Profile '$profile' status UNKNOWN — not assumed present."
  fi
  if [ -n "$missing" ]; then
    echo "::error::assert-runner-prereqs: profile '$profile' NOT satisfied on this runner —$missing"
    echo "  profile purpose: $why" >&2
    echo "  $(runner_id)" >&2
    echo "  This is a RUNNER PROVISIONING problem, not a code problem. csq's jobs" >&2
    echo "  are pinned to the 'ci-portable' fleet; a runner reaching this line is" >&2
    echo "  either mislabelled or under-provisioned. Do not retry — re-provision," >&2
    echo "  or correct the label. See scripts/ci/runner-prereqs.json." >&2
    exit "$MISSING"
  fi
  echo "assert-runner-prereqs: profile '$profile' OK"
done
echo "assert-runner-prereqs: all profile(s) satisfied — $(runner_id)"
exit "$OK"
