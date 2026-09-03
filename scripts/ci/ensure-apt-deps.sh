#!/usr/bin/env bash
# Ensure apt packages are present on a (usually self-hosted, persistent) runner.
#
# WHY THIS EXISTS
# ---------------
# The previous inline pattern was, at 16 call sites:
#
#   sudo apt-get -o DPkg::Lock::Timeout=300 update \
#     || echo "::warning::apt-get update skipped (lists-lock contention ...)"
#   sudo apt-get -o DPkg::Lock::Timeout=300 install -y <pkgs>
#
# It had two defects, and the second hid the first for days:
#
#   1. It required sudo unconditionally, even when every package was ALREADY
#      installed — which is the normal state of a persistent self-hosted
#      runner. When the runner lost passwordless sudo (2026-08-28) every
#      Linux job broke instantly, including on `main`.
#
#   2. The `|| echo` attributed EVERY failure to lists-lock contention. On
#      2026-08-28 the actual output was `sudo: a password is required`, and
#      the step failed in 30ms rather than after the 300s lock timeout — but
#      the warning still announced lock contention, so the failure was
#      repeatedly misdiagnosed as capacity contention (an internal ticket / task
#      #60). A catch-all that names one cause for every failure is a
#      non-discriminating instrument (`instrument-discipline.md` MUST-1):
#      it cannot produce a different answer when its claim is false.
#
# CONTRACT
#   exit 0 — every package is present (installed here, or already there)
#   exit 1 — packages are genuinely missing AND cannot be installed; the
#            message names the REAL blocker
#   exit 2 — UNDETERMINED: cannot even query package state (no dpkg-query),
#            which is not the same as "they are missing"
#
# Test seams (self-test only; unset in CI):
#   APT_DEPS_FAKE_INSTALLED  space-separated list treated as installed
#   APT_DEPS_FAKE_SUDO       "ok" | "denied"  — stubs the sudo -n probe
set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: ensure-apt-deps.sh <package>..." >&2
  exit 2
fi

pkg_installed() {
  local pkg="$1"
  if [ -n "${APT_DEPS_FAKE_INSTALLED+x}" ]; then
    case " $APT_DEPS_FAKE_INSTALLED " in *" $pkg "*) return 0 ;; *) return 1 ;; esac
  fi
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'
}

sudo_usable() {
  if [ -n "${APT_DEPS_FAKE_SUDO+x}" ]; then
    [ "$APT_DEPS_FAKE_SUDO" = "ok" ]; return
  fi
  sudo -n true 2>/dev/null
}

# UNDETERMINED: without dpkg-query we cannot distinguish present from missing.
if [ -z "${APT_DEPS_FAKE_INSTALLED+x}" ] && ! command -v dpkg-query >/dev/null 2>&1; then
  echo "::error::ensure-apt-deps: dpkg-query not found — cannot determine package state (UNDETERMINED, not 'missing')" >&2
  exit 2
fi

missing=()
for pkg in "$@"; do
  pkg_installed "$pkg" || missing+=("$pkg")
done

if [ "${#missing[@]}" -eq 0 ]; then
  echo "ensure-apt-deps: all ${#@} package(s) already installed; no sudo needed"
  exit 0
fi

echo "ensure-apt-deps: missing: ${missing[*]}"

if ! sudo_usable; then
  # Name the REAL blocker. Do not claim lock contention we have not observed.
  echo "::error::ensure-apt-deps: cannot install ${missing[*]} — passwordless sudo is unavailable on this runner (\`sudo -n true\` failed). This is a RUNNER HOST configuration problem, not apt lock contention: restore the NOPASSWD sudoers entry for the runner user, or pre-install these packages on the image." >&2
  exit 1
fi

# apt-get update is genuinely best-effort (cached lists are usually fine), but
# report what ACTUALLY failed instead of asserting a cause.
# Capture rather than redirect-under-sudo (SC2024), and report what ACTUALLY
# failed instead of asserting a cause we have not observed.
if ! update_out="$(sudo -n apt-get -o DPkg::Lock::Timeout=300 update 2>&1)"; then
  echo "::warning::ensure-apt-deps: apt-get update failed; proceeding with cached lists. Actual output: $(printf '%s' "$update_out" | tail -3 | tr '\n' ' ')"
fi

if ! sudo -n apt-get -o DPkg::Lock::Timeout=300 install -y "${missing[@]}"; then
  echo "::error::ensure-apt-deps: apt-get install failed for: ${missing[*]}" >&2
  exit 1
fi

echo "ensure-apt-deps: installed ${missing[*]}"
