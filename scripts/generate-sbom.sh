#!/usr/bin/env bash
# Generate a CycloneDX SBOM for the released `csq` binary.
#
# Usage: scripts/generate-sbom.sh <output-file.cdx.json>
#
# Emits one CycloneDX 1.5 JSON SBOM describing the `csq` binary and its full
# transitive dependency tree (default/community feature set — no
# enterprise/kailash deps). Run from the repo root. Auto-installs a PINNED
# cargo-cyclonedx if absent.
#
# An SBOM enumerates the released binary's transitive dependency tree and the
# licenses of those components for downstream supply-chain review. NOTE: license
# POLICY is enforced separately by `cargo deny check` against the enterprise
# tree's deny.toml in CI (edition-seam.yml) — deny.toml is intentionally absent
# from the community tree this script runs against, so this SBOM ENUMERATES
# licenses but does not itself gate them.
set -euo pipefail

OUT="${1:?usage: generate-sbom.sh <output-file.cdx.json>}"
# Enforce the .cdx.json suffix so $OUT can never collide with the per-member
# `csq-sbom.json` files the cleanup below deletes.
case "$OUT" in
  *.cdx.json) ;;
  *) echo "ERROR: output file must end in .cdx.json (got: $OUT)" >&2; exit 2 ;;
esac

# Pin the SBOM toolchain — reproducible, and supply-chain-pinned like the rest
# of the tree (this runs in a credential-bearing release job).
CYCLONEDX_VERSION="0.5.9"
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo install cargo-cyclonedx --version "=${CYCLONEDX_VERSION}" --locked
fi

# cargo-cyclonedx emits one SBOM per workspace member next to its Cargo.toml,
# all named csq-sbom.json (via --override-filename). Pre-clean any stale ones,
# generate with the default (community) feature set, copy out csq's, then remove
# the per-member files. $OUT ends in .cdx.json so the cleanup never touches it.
find . -name 'csq-sbom.json' -not -path './target/*' -delete 2>/dev/null || true
cargo cyclonedx --manifest-path csq/Cargo.toml --all --format json \
  --spec-version 1.5 --override-filename csq-sbom
test -f csq/csq-sbom.json || {
  echo "ERROR: cargo-cyclonedx did not emit csq/csq-sbom.json (filename convention changed?)" >&2
  exit 1
}
cp csq/csq-sbom.json "$OUT"
find . -name 'csq-sbom.json' -not -path './target/*' -delete 2>/dev/null || true

# Sanity + defense-in-depth: assert CycloneDX rooted at `csq`, and no
# token-shaped secret for ANY provider csq integrates (SBOMs are published).
python3 - "$OUT" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
assert d.get("bomFormat") == "CycloneDX", f"not a CycloneDX SBOM: {d.get('bomFormat')}"
root = d.get("metadata", {}).get("component", {}).get("name")
assert root == "csq", f"unexpected root component: {root!r}"
blob = json.dumps(d)
secret = re.compile(
    r"x-access-token|gh[pousr]_|github_pat_|sk-ant|sk-proj-|ya29\."
    r"|AIza[0-9A-Za-z_-]{10}|BEGIN [A-Z ]*PRIVATE KEY"
)
assert not secret.search(blob), "possible secret in SBOM — refusing to emit"
print(f"SBOM OK: {sys.argv[1]} — {len(d.get('components', []))} components, root={root}")
PY
