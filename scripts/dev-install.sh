#!/usr/bin/env bash
# Build + (on macOS) Developer-ID-sign + install the csq CLI locally.
#
# WHY THIS EXISTS
# ---------------
# macOS grants a keychain item's "Always Allow" based on the requesting app's
# CODE SIGNATURE. A plain `cargo build` on macOS ad-hoc-signs the binary at link
# time, and an ad-hoc signature's identity is derived from the binary's CONTENTS
# — so it changes on every rebuild. macOS then treats each rebuild as a brand-new
# app and re-prompts for access to every keychain item csq uses (the audit
# signing key `csq-audit-signing`, per-dev keys `csq-dev-signing-*`, Codex creds).
#
# Signing with the stable Developer ID identity gives the binary a fixed
# "designated requirement" (tied to the Team ID, not the content hash), so
# "Always Allow" persists across rebuilds and the prompts stop.
#
# ONE-TIME COST: the FIRST Developer-ID build still prompts once per keychain
# item (the identity changed from ad-hoc → Developer ID); click "Always Allow"
# once and it sticks for every future Developer-ID-signed build. `codesign` may
# also prompt once to use the signing key — also "Always Allow".
#
# See memory: discovery_keychain_reprompt_adhoc_signing.
#
# Usage:
#   scripts/dev-install.sh
#   CSQ_BIN_DIR=~/bin scripts/dev-install.sh
#   CSQ_SIGN_IDENTITY="Developer ID Application: ... (TEAMID)" scripts/dev-install.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IDENTITY="${CSQ_SIGN_IDENTITY:-Developer ID Application: Terrene Foundation Limited (4Y4U35PJHX)}"
BIN_DIR="${CSQ_BIN_DIR:-$HOME/.local/bin}"

echo "Building csq CLI (release)…"
cargo build --release -p csq --features cli --no-default-features

if [ "$(uname -s)" = "Darwin" ]; then
    # Confirm the signing identity exists before attempting to sign.
    if ! security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
        echo "WARNING: signing identity not found in keychain:" >&2
        echo "  $IDENTITY" >&2
        echo "  Falling back to ad-hoc (keychain prompts will persist). Override with CSQ_SIGN_IDENTITY." >&2
    else
        echo "Signing with: $IDENTITY"
        # --timestamp=none: no secure-timestamp round-trip (offline; the keychain
        # ACL keys on the signing identity, not the timestamp). No hardened
        # runtime: not needed for keychain-ACL stability, and avoids surprising
        # a local dev binary with hardened-runtime restrictions.
        codesign --force --timestamp=none --sign "$IDENTITY" target/release/csq
        codesign --verify --strict target/release/csq
        echo "Signed (Developer ID). First keychain access prompts once — click 'Always Allow'."
    fi
fi

mkdir -p "$BIN_DIR"
install -m 0755 target/release/csq "$BIN_DIR/csq"
echo "Installed csq → $BIN_DIR/csq"
"$BIN_DIR/csq" --version
