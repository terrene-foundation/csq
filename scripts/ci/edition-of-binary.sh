#!/usr/bin/env bash
# edition-of-binary — print the csq edition a BUILT artifact reports.
#
# `csq/src/main.rs::VERSION_LINE` is a compile-time
# `concat!(env!("CARGO_PKG_VERSION"), " (enterprise)")` / " (community)", and the
# two arms are #[cfg]-exclusive, so exactly ONE of those literals sits
# contiguously in a built binary's rodata — the same constant `--version` prints.
# Reading it needs no execution, so this works on a foreign-arch artifact and on
# one whose executable bit CI stripped.
#
# WHAT IT DOES AND DOES NOT WORK ON
# Raw binaries carry the literal. COMPRESSED BUNDLES DO NOT: measured against the
# published v2.19.0 assets, `csq-desktop-linux.deb` and
# `csq-desktop-windows-setup.exe` each yield ZERO literals, because the inner
# binary is packed. That is why the desktop legs emit a `.edition` sidecar from
# the RAW binary before bundling rather than relying on a scan of the bundle.
#
# THE VERSION ANCHOR IS LOAD-BEARING. Matching a bare `(enterprise)` token would
# false-positive on ordinary prose ("built for enterprise customers") and BLOCK a
# clean release — and a gate that falsely accuses is the failure mode that
# teaches operators to override gates (durable-instruments.md MUST-1).
#
# EXIT CODES — three outcomes, never two (durable-instruments.md MUST-2)
#   0  classified; prints `community` or `enterprise` on stdout
#   2  UNDETERMINED — unreadable, or no edition literal present. NOT a default,
#      NOT "community" — an unclassifiable artifact must stay unclassified.
#
# Ambiguity fails toward ENTERPRISE: if both literals appear, print `enterprise`.
# For the consumer (the license gate) refusing is the safe direction.
#
# Usage: edition-of-binary.sh <path>
set -uo pipefail

BIN="${1:-}"
if [ -z "$BIN" ]; then
  echo "edition-of-binary: UNDETERMINED — usage: $(basename "$0") <path>" >&2
  exit 2
fi
if [ ! -f "$BIN" ]; then
  echo "edition-of-binary: UNDETERMINED — not a regular file: '$BIN'" >&2
  exit 2
fi

eds="$(LC_ALL=C grep -a -o -E '[0-9]+\.[0-9]+\.[0-9]+ \((community|enterprise)\)' "$BIN" 2>/dev/null \
       | sed -E 's/.*\((community|enterprise)\)/\1/' | sort -u)"

case "$eds" in
  *enterprise*) echo "enterprise"; exit 0 ;;
  community)    echo "community";  exit 0 ;;
  *)
    echo "edition-of-binary: UNDETERMINED — no '<version> (community|enterprise)'" >&2
    echo "literal in '$BIN'. A packed or compressed artifact cannot be classified" >&2
    echo "in place; classify the raw binary before bundling instead." >&2
    exit 2 ;;
esac
