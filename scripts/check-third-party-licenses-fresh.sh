#!/usr/bin/env bash
# Check attribution through the one generator. No option checks both editions in
# the full source tree, community only in the official extract.
# Usage: check-third-party-licenses-fresh.sh [--edition community|enterprise]
# 0=fresh, 1=missing/stale, 2=could not generate or compare.
set -euo pipefail
# Freshness is a measurement, never a tool-provisioning or network operation.
# This also covers the unchanged licenses-fresh sign-off command.
export CARGO_NET_OFFLINE=true
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/scripts/lib/resolve-python.sh" || exit 2
PY="$(resolve_python3 --require tomllib)" || exit 2
EDITION="auto"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --edition)
      [ "$#" -ge 2 ] || { echo "ERROR: --edition requires community or enterprise" >&2; exit 2; }
      EDITION="$2"; shift 2 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$EDITION" in
  community|enterprise) EDITIONS=("$EDITION") ;;
  auto)
    AVAILABLE="$("$PY" - csq/Cargo.toml <<'TOML'
import sys, tomllib
with open(sys.argv[1], "rb") as stream:
    features = tomllib.load(stream).get("features", {})
if not isinstance(features, dict):
    raise ValueError("invalid Cargo features table")
print("enterprise" if "enterprise" in features else "community")
TOML
    )" || { echo "UNDETERMINED: cannot read edition feature surface" >&2; exit 2; }
    EDITIONS=(community)
    if [ "$AVAILABLE" = "enterprise" ]; then
      EDITIONS+=(enterprise)
    elif [ -d csq-core/src/phase2b ]; then
      echo "UNDETERMINED: full source tree is missing its enterprise feature" >&2
      exit 2
    fi ;;
  *) echo "ERROR: unknown edition: $EDITION" >&2; exit 2 ;;
esac
WORK="$(mktemp -d)" || exit 2
trap 'rm -rf "$WORK"' EXIT
for EDITION in "${EDITIONS[@]}"; do
  case "$EDITION" in
    community) COMMITTED="THIRD-PARTY-LICENSES.md" ;;
    enterprise) COMMITTED="THIRD-PARTY-LICENSES-ENTERPRISE.md" ;;
  esac
  if [ ! -f "$COMMITTED" ]; then
    echo "MISSING: $COMMITTED — run scripts/generate-third-party-licenses.sh --edition $EDITION" >&2
    exit 1
  fi
  FRESH="$WORK/$COMMITTED"
  if ! bash scripts/generate-third-party-licenses.sh --edition "$EDITION" "$FRESH" >/dev/null; then
    echo "UNDETERMINED: could not regenerate $EDITION attribution" >&2
    exit 2
  fi
  # Normalize only comparison copies; real crate/content changes survive.
  sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' "$COMMITTED" > "$WORK/committed.norm" || exit 2
  sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' "$FRESH" > "$WORK/fresh.norm" || exit 2
  RC=0
  diff -u "$WORK/committed.norm" "$WORK/fresh.norm" > "$WORK/diff" || RC=$?
  case "$RC" in
    0) echo "$COMMITTED is fresh (crate set + license content match $EDITION)." ;;
    1)
      echo "STALE: $COMMITTED differs from the current $EDITION dependency graph." >&2
      echo "Regenerate: bash scripts/generate-third-party-licenses.sh --edition $EDITION" >&2
      sed -n '1,40p' "$WORK/diff" >&2
      exit 1 ;;
    *) echo "UNDETERMINED: attribution comparison failed (diff exit $RC)" >&2; exit 2 ;;
  esac
done
