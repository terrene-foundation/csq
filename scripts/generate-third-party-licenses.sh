#!/usr/bin/env bash
# Generate THIRD-PARTY-LICENSES.md — the third-party attribution bundle for csq.
#
# Usage: scripts/generate-third-party-licenses.sh [output-file.md]
#
# Emits the full license TEXT of every third-party dependency bundled in the
# default (cli + desktop) csq build, for attribution compliance. Run from the
# repo root. Auto-installs a PINNED cargo-about if absent (mirrors
# generate-sbom.sh).
#
# Three distinct license-adjacent surfaces, do not conflate:
#   - cargo deny check  → license POLICY      (blocks copyleft at the dep tree)
#   - generate-sbom.sh  → license ENUMERATION  (CycloneDX SBOM; ids/expressions)
#   - THIS script        → license ATTRIBUTION (full text bundle; the gap above)
#
# PRIMARY permissive guarantee: about.toml `accepted` (an SPDX-expression
# allowlist) + cargo-about `--fail` — a license outside that allowlist aborts
# generation. The python block below is structural defense-in-depth on the
# published artifact, NOT the primary gate.
set -euo pipefail

OUT="${1:-THIRD-PARTY-LICENSES.md}"
case "$OUT" in
  *.md) ;;
  *) echo "ERROR: output file must end in .md (got: $OUT)" >&2; exit 2 ;;
esac

# Pin the attribution toolchain — reproducible, supply-chain-pinned like the
# SBOM toolchain. Bump deliberately (a new cargo-about can change clarification
# heuristics → different text resolution).
ABOUT_VERSION="0.7.1"
if ! command -v cargo-about >/dev/null 2>&1; then
  cargo install cargo-about --version "=${ABOUT_VERSION}" --locked
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Write to a side file and only move it over the committed artifact AFTER the
# defense-in-depth checks pass (mirrors generate-sbom.sh's write-then-copy
# discipline). `> "$OUT"` directly would truncate the committed file at shell
# setup, BEFORE cargo-about runs — so a `--fail`/`--locked` abort under
# `set -e` would leave the committed snapshot truncated. The trap cleans the
# side file on ANY exit until the final mv succeeds.
TMP="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

# Generate against the default features (cli + desktop). Opt-in feature sets are
# NOT in `default`, so they are excluded from the attribution surface here.
#   --fail   : an unresolvable/unaccepted license is a hard error (fail-closed).
#   --locked : generate against the committed Cargo.lock exactly; abort if the
#              lock would need changing (so the attribution always matches the
#              shipped dependency graph, never a silently-updated one).
# Determinism comes from `no-clearly-defined = true` in about.toml (no network
# enrichment), NOT from offline mode — so this runs reproducibly with normal
# registry access (the freshness gate can run on CI without an offline cache).
cargo about generate \
  --manifest-path csq/Cargo.toml \
  -c about.toml \
  --locked \
  --fail \
  about.hbs > "$TMP"

# Defense-in-depth on the side file. All checks are structural — they describe
# the SHAPE the file must have, not a denylist of crate names:
#   (a) no copyleft / viral license appears in the Overview. cargo-about renders
#       SPDX *full_names* (which spell the family out — "... General Public
#       License", "Server Side Public License"), so we match on those phrases,
#       not on acronyms (the rendered names never contain "GPL"). This is a
#       backstop for the one realistic miss the primary gate cannot catch: a
#       copyleft id mistakenly ADDED to about.toml `accepted` (then cargo-about
#       --fail would pass it). The Overview is the authoritative license-type
#       list, so scanning it (not license bodies) avoids false-positives from
#       body prose that merely references a copyleft license.
#   (b) no token-shaped secret (attribution text is published — mirror generate-sbom.sh).
#   (c) the file is non-trivial and well-formed.
python3 - "$TMP" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()

# Overview lines look like: "- **<License full_name>** — N crate(s)"
overview = re.findall(r"^- \*\*(.+?)\*\* — \d+ crate\(s\)", text, re.MULTILINE)
assert overview, "no Overview license lines parsed — generation likely failed"

# (a) copyleft / viral / reciprocal / source-available families, matched on the
#     spelled-out full_name phrase (case-insensitive). This is a CURATED subset
#     of the known restrictive families — NOT exhaustive; the exhaustive gate is
#     the about.toml `accepted` allowlist + cargo-about `--fail` (a license
#     outside that allowlist never reaches this file). This list is the backstop
#     for the one realistic miss the allowlist cannot self-catch: a restrictive
#     id mistakenly ADDED to `accepted`. MPL ("Mozilla Public License") is weak
#     file-level copyleft and intentionally NOT listed — it is accepted.
COPYLEFT = [
    "General Public License",            # GPL / LGPL / AGPL all render as "... General Public License"
    "Affero",                            # AGPL
    "Server Side Public",                # SSPL
    "Common Development and Distribution",  # CDDL
    "Common Public",                     # CPL / CPAL
    "European Union Public",             # EUPL
    "Open Software License",             # OSL
    "Eclipse Public",                    # EPL
    "Reciprocal",                        # RPL / MS-RL ("... Reciprocal License")
    "CeCILL",                            # French copyleft family
    "Business Source",                   # BUSL / BSL (source-available, not OSS)
    "PolyForm",                          # source-available
    "Parity",                            # strong copyleft (source-available)
    "Sleepycat",                         # strong copyleft
]
for name in overview:
    low = name.lower()
    hit = next((p for p in COPYLEFT if p.lower() in low), None)
    assert not hit, f"copyleft/viral license in attribution Overview: {name!r} (matched {hit!r})"

# (b) token-shaped secret (mirror generate-sbom.sh's scan).
m = re.search(
    r"x-access-token|gh[pousr]_|github_pat_|sk-ant|sk-proj-|ya29\."
    r"|AIza[0-9A-Za-z_-]{10}|BEGIN [A-Z ]*PRIVATE KEY",
    text,
)
assert not m, f"possible secret in attribution file: {m.group(0)!r}"

# (c) structural sanity.
assert "# Third-Party Licenses" in text, "missing document header"
assert "## Overview" in text, "missing overview section"
n_used = text.count("Used by:")
assert n_used >= 10, f"implausibly few attributed crates ({n_used}) — generation likely failed"
print(f"THIRD-PARTY-LICENSES OK: {path} — {len(overview)} license types, {n_used} groups, {len(text.encode('utf-8'))} bytes")
PY

# Validation passed — atomically replace the committed artifact, then disarm the
# cleanup trap (the side file is now the artifact).
mv "$TMP" "$OUT"
trap - EXIT
echo "wrote $OUT"
