#!/usr/bin/env bash
#
# Fixture-substitution audit (R2-MED-03 / H6).
#
# Per `csq/.claude/rules/independence.md`: fixture content MUST NOT reference
# proprietary product names like "Kailash" or "DataFlow Inc". Compliance
# fixtures were ported from loom and substituted with fictional names
# (Foobar Workflow Studio / Acme DataCorp). This script is the regression
# guard.
#
# Run from the repository root:
#   ./coc-eval/scripts/check-fixture-substitution.sh
#
# Exits 0 on no match (success), 1 on any match found, 2 on script error.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="${ROOT_DIR}/fixtures"
SCAFFOLDS_DIR="${ROOT_DIR}/scaffolds"

if [ ! -d "${FIXTURES_DIR}" ]; then
    echo "error: fixtures dir not found: ${FIXTURES_DIR}" >&2
    exit 2
fi

# H7 R1-C-MED-1: extend audit to scan scaffolds/ as well — the H7
# implementation suite layers per-test scaffold trees on top of the
# coc-env base fixture, so commercial-name regressions could land
# in a scaffold and bypass a fixtures-only scan.
SEARCH_DIRS=("${FIXTURES_DIR}")
if [ -d "${SCAFFOLDS_DIR}" ]; then
    SEARCH_DIRS+=("${SCAFFOLDS_DIR}")
fi

# `-l` lists matching files; `-q` would suppress them. We want filenames
# in the failure message so the developer knows where to look.
# `-i` case-insensitive — the rule covers "Kailash", "kailash", "DATAFLOW", etc.
# `-I` skip binary files (defense-in-depth; fixtures are text but commit
# could land an asset later).
# `--include` restricts to text-style files — `.md`, `.txt`, `.yaml`, `.yml`,
# `.json`, `.toml`, `.py` (rare in fixtures but possible). Catches
# everything fixtures legitimately ship.
# R1-C-M1: `--` end-of-options sentinel guards against future refactors
# that compute the search root dynamically (a path beginning with `-`
# would otherwise be interpreted as a flag). Today FIXTURES_DIR is a
# fixed absolute path, so the protection is defensive only.
#
# R1-C-L1: regex is ASCII-only and case-sensitive-via-`-i`. Unicode
# homoglyphs ("kаilash" with Cyrillic а) and word-break obfuscation
# ("k_a_i_l_a_s_h") will NOT trip this audit — they require PR review.
# This is the same threat boundary as `independence.md` text rules:
# adversarial obfuscation by a project contributor is out of scope.
#
# R1-C-L2: `--include` filter list is intentionally narrow. New fixture
# extensions (e.g. `.j2`, `.html`) MUST be added here when introduced;
# a fixture template in an unincluded extension would silently bypass
# the audit. The grep below maps to fixture types we ship today.
matches=$(grep -rIli \
    --include="*.md" \
    --include="*.txt" \
    --include="*.yaml" \
    --include="*.yml" \
    --include="*.json" \
    --include="*.toml" \
    --include="*.py" \
    --include="*.js" \
    --include="*.ts" \
    -E "kailash|dataflow" \
    -- "${SEARCH_DIRS[@]}" || true)

if [ -n "${matches}" ]; then
    echo "ERROR: fixture content references commercial product names:" >&2
    echo "${matches}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "  Substitute per coc-eval/fixtures/compliance/CLAUDE.md header:" >&2
    echo "    Kailash Python SDK  → Foobar Workflow Studio" >&2
    echo "    DataFlow Inc        → Acme DataCorp" >&2
    echo "  See csq/.claude/rules/independence.md for the no-commercial-" >&2
    echo "  coupling policy." >&2
    exit 1
fi

echo "OK: fixtures contain no proprietary product references"
exit 0
