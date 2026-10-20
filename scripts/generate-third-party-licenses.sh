#!/usr/bin/env bash
# Generate the selected edition's third-party attribution bundle for csq.
#
# Usage: scripts/generate-third-party-licenses.sh [--edition community|enterprise] [output-file.md]
#
# Emits the full license TEXT of every third-party dependency bundled in the
# selected shipping build, retaining default cli + desktop features and adding
# enterprise when selected. Run from the repo root. Uses pinned cargo-about;
# offline mode requires it to be cached and never installs it.
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

# Resolve a VERIFIED python3 before the structural checks below (see
# scripts/lib/resolve-python.sh). A bare `python3` inherits whatever the
# operator's PATH resolves to, and a stub that exits 0 without running the
# program would make those checks vacuous over this published artifact.
# shellcheck source=/dev/null
. "$(cd "${BASH_SOURCE[0]%/*}" && pwd)/lib/resolve-python.sh" || {
  echo "FATAL: cannot source scripts/lib/resolve-python.sh (next to this script)." >&2
  echo "       The interpreter probe is unavailable, so no verified python3 can be" >&2
  echo "       resolved. A missing tool lib is NOT a clean run." >&2
  exit 70
}
PY="$(resolve_python3)" || exit 70

EDITION="community"
OUT=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --edition)
      [ "$#" -ge 2 ] || { echo "ERROR: --edition requires community or enterprise" >&2; exit 2; }
      EDITION="$2"; shift 2 ;;
    --*) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
    *)
      [ -z "$OUT" ] || { echo "ERROR: only one output path is accepted" >&2; exit 2; }
      OUT="$1"; shift ;;
  esac
done
case "$EDITION" in
  community) OUT="${OUT:-THIRD-PARTY-LICENSES.md}" ;;
  enterprise) OUT="${OUT:-THIRD-PARTY-LICENSES-ENTERPRISE.md}" ;;
  *) echo "ERROR: unknown edition: $EDITION" >&2; exit 2 ;;
esac
case "$OUT" in
  *.md) ;;
  *) echo "ERROR: output file must end in .md (got: $OUT)" >&2; exit 2 ;;
esac

# Pin the attribution toolchain — reproducible, supply-chain-pinned like the
# SBOM toolchain. Bump deliberately (a new cargo-about can change clarification
# heuristics → different text resolution).
ABOUT_VERSION="0.7.1"
if ! command -v cargo-about >/dev/null 2>&1; then
  case "${CARGO_NET_OFFLINE:-false}" in
    true|1|yes)
      echo "UNDETERMINED: cargo-about ${ABOUT_VERSION} is not cached; offline generation cannot install it" >&2
      echo "Install explicitly: cargo install cargo-about --version =${ABOUT_VERSION} --locked" >&2
      exit 2 ;;
  esac
  cargo install cargo-about --version "=${ABOUT_VERSION}" --locked || {
    echo "UNDETERMINED: unable to provision cargo-about ${ABOUT_VERSION}" >&2; exit 2;
  }
fi
ACTUAL_VERSION="$(cargo-about --version 2>&1)" || {
  echo "UNDETERMINED: cannot read cargo-about version" >&2
  echo "Install explicitly: cargo install cargo-about --version =${ABOUT_VERSION} --locked" >&2
  exit 2;
}
[ "$ACTUAL_VERSION" = "cargo-about ${ABOUT_VERSION}" ] || {
  echo "UNDETERMINED: cargo-about ${ABOUT_VERSION} is required (found: $ACTUAL_VERSION)" >&2
  echo "Install explicitly: cargo install cargo-about --version =${ABOUT_VERSION} --locked" >&2
  exit 2;
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Write to a side file and only move it over the committed artifact AFTER the
# defense-in-depth checks pass (mirrors generate-sbom.sh's write-then-copy
# discipline). `> "$OUT"` directly would truncate the committed file at shell
# setup, BEFORE cargo-about runs — so a `--fail`/`--locked` abort under
# `set -e` would leave the committed snapshot truncated. The trap cleans the
# side file on ANY exit until the final mv succeeds.
TMP="$(mktemp "${OUT}.XXXXXX")" || exit 2
trap 'rm -f "$TMP"' EXIT

# Community uses defaults (cli + desktop); enterprise adds its shipping feature
# to those defaults, matching the enterprise desktop build. The same config
# pins all four shipping targets for both editions.
#   --fail   : an unresolvable/unaccepted license is a hard error (fail-closed).
#   --locked : generate against the committed Cargo.lock exactly; abort if the
#              lock would need changing (so the attribution always matches the
#              shipped dependency graph, never a silently-updated one).
# `no-clearly-defined = true` disables network license enrichment. Explicit
# generation may fetch unless offline is requested; freshness always runs
# offline and requires all locked sources cached. CI warms that cache with one
# online `cargo fetch --locked` before invoking the offline freshness checker.
ABOUT_ARGS=(--manifest-path csq/Cargo.toml -c about.toml --locked --fail)
[ "$EDITION" != "enterprise" ] || ABOUT_ARGS+=(--features enterprise)
case "${CARGO_NET_OFFLINE:-false}" in
  true|1|yes) ABOUT_ARGS+=(--offline) ;;
esac
if ! cargo about generate "${ABOUT_ARGS[@]}" about.hbs > "$TMP"; then
  echo "UNDETERMINED: $EDITION license generation failed; attribution was not published" >&2
  exit 2
fi

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
# Isolated Python ignores PYTHONOPTIMIZE, so structural assertions stay active.
if ! "$PY" -I - "$TMP" <<'PY'
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
# Canonicalize insignificant whitespace in generated license copies. This also
# keeps registry-cache CRLF/blank-line differences from changing shipped bytes.
text = "\n".join(line.rstrip(" \t\r") for line in text.split("\n")).rstrip("\n") + "\n"
with open(path, "w", encoding="utf-8", newline="\n") as stream:
    stream.write(text)
print(f"THIRD-PARTY-LICENSES OK: {path} — {len(overview)} license types, {n_used} groups, {len(text.encode('utf-8'))} bytes")
PY
then
  echo "UNDETERMINED: generated attribution failed structural validation" >&2
  exit 2
fi

# Validation passed — atomically replace the committed artifact, then disarm the
# cleanup trap (the side file is now the artifact).
mv "$TMP" "$OUT" || exit 2
trap - EXIT
echo "wrote $OUT"
