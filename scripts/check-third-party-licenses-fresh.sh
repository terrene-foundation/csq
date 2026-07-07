#!/usr/bin/env bash
# Fail if THIRD-PARTY-LICENSES.md is STALE w.r.t. the current dependency tree.
#
# Usage: scripts/check-third-party-licenses-fresh.sh
#
# Regenerates the attribution bundle to a temp file (--locked) and compares it
# WHITESPACE-NORMALIZED against the committed THIRD-PARTY-LICENSES.md. A surviving
# diff means a dependency was added/removed/bumped without regenerating the
# attribution — the committed snapshot under-/over-counts the shipped crates,
# which for a redistribution-attribution doc is a real compliance gap.
#
# Intended as a PR-time gate on dependency changes (Cargo.lock). Pairs with
# scripts/generate-third-party-licenses.sh (the regenerator the fix message names).
# The crate set + license CONTENT are host-independent (about.toml pins explicit
# `targets` + `no-clearly-defined` disables the only run-to-run-drifting input,
# clearlydefined.io). cargo-about's license-TEXT whitespace rendering, however,
# varies benignly per platform (e.g. a trailing blank line in a body) — so the
# comparison is whitespace-normalized (below), NOT byte-exact, to stay reliable
# when the committing host differs from the CI host.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMMITTED="THIRD-PARTY-LICENSES.md"
if [ ! -f "$COMMITTED" ]; then
  echo "ERROR: $COMMITTED is missing — run scripts/generate-third-party-licenses.sh" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FRESH="$WORK/THIRD-PARTY-LICENSES.md"

bash scripts/generate-third-party-licenses.sh "$FRESH" >/dev/null

# Compare WHITESPACE-NORMALIZED, not byte-exact. cargo-about's license-text
# rendering carries benign per-platform whitespace variance (a license body's
# trailing blank line can differ between APFS/ext4 filesystem ordering of a
# crate's multiple license files) — so a byte-exact diff false-STALEs whenever
# the committing host differs from the CI host. The gate's job is to catch
# DEPENDENCY drift (a crate added / removed / its license content changed), and
# every such change adds or removes NON-blank lines (a `## <license>` heading, a
# `- [crate version]` ref, or license body text) — which survive normalization.
# Normalize each side (strip trailing whitespace + drop blank lines); neither
# file is mutated. A surviving diff is a real crate-set / license-content change.
_norm() { sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' "$1"; }

if ! diff -q <(_norm "$COMMITTED") <(_norm "$FRESH") >/dev/null 2>&1; then
  echo "STALE: $COMMITTED differs (beyond whitespace) from a fresh generation against the current Cargo.lock." >&2
  echo "Regenerate and commit:" >&2
  echo "    bash scripts/generate-third-party-licenses.sh && git add $COMMITTED" >&2
  echo "--- first 40 normalized-diff lines ---" >&2
  diff <(_norm "$COMMITTED") <(_norm "$FRESH") | head -40 >&2
  exit 1
fi

echo "$COMMITTED is fresh (crate set + license content match a fresh regeneration)."
