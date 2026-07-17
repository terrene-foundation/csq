#!/usr/bin/env bash
# check-oq1-fixtures.sh — fail-closed provenance gate for the OQ-1
# special-category content-probe corpus (OQ1-S5).
#
# Thin wrapper over `coc-eval/lib/oq1_provenance.py` (the testable implementation)
# for parity with the sibling gate scripts (check-community-specs.sh etc). Scans
# the synthetic fixture corpus + fixture tree for missing SYNTHETIC: markers,
# real-PII heuristics (email / long digit runs / SSN shapes), and non-vocabulary
# category tags. Optionally also scans an emitted predictions/probes JSONL.
#
# Usage:
#   bash scripts/check-oq1-fixtures.sh                 # scan the corpus + tree
#   bash scripts/check-oq1-fixtures.sh --results P.jsonl  # also scan results
#
# Exit codes: 0 = clean; 1 = at least one violation (INCLUDING a required path
# absent — cannot verify is a denial, not a skip). Mirrors lib/oq1_provenance.py.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT/coc-eval"
exec python3 -m lib.oq1_provenance "$@"
