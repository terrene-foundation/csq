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
# EDITION SAFETY (2026-07-09)
# ---------------------------
# csq ships in two editions: `community` (`--features cli --no-default-features`)
# and `enterprise` (`--features cli,enterprise …`). Installing the wrong edition
# over an existing install silently DOWNGRADES it (enterprise → community loses
# the direct-API moat, licensing, kailash trust plane). To make that mistake
# structurally impossible this script:
#   1. Detects the edition of the currently-installed binary (if any).
#   2. Defaults the build to MATCH it (preserve-edition), overridable via
#      CSQ_EDITION=community|enterprise.
#   3. Refuses to DOWNGRADE enterprise → community unless CSQ_EDITION=community
#      is set explicitly.
#   4. Verifies the freshly-installed binary reports the intended edition, and
#      fails loudly on mismatch.
# See memory: feedback_cli_enterprise_build_and_rebuild_after_checkout,
#             discovery_keychain_reprompt_adhoc_signing.
#
# Usage:
#   scripts/dev-install.sh                       # preserve installed edition (default community)
#   CSQ_EDITION=enterprise scripts/dev-install.sh
#   CSQ_EDITION=community  scripts/dev-install.sh # explicit; allows downgrade
#   CSQ_BIN_DIR=~/bin scripts/dev-install.sh
#   CSQ_SIGN_IDENTITY="Developer ID Application: ... (TEAMID)" scripts/dev-install.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IDENTITY="${CSQ_SIGN_IDENTITY:-Developer ID Application: Terrene Foundation Limited (4Y4U35PJHX)}"
BIN_DIR="${CSQ_BIN_DIR:-$HOME/.local/bin}"
INSTALLED="$BIN_DIR/csq"

# ── Detect the currently-installed edition (if any) ─────────────────────────
# `csq --version` prints e.g. "csq 2.17.1 (enterprise)" or "... (community)".
detect_edition() {
    local bin="$1"
    [ -x "$bin" ] || { echo ""; return; }
    local v
    v="$("$bin" --version 2>/dev/null || true)"
    case "$v" in
        *"(enterprise)"*) echo "enterprise" ;;
        *"(community)"*)  echo "community" ;;
        *)                echo "" ;;
    esac
}

INSTALLED_EDITION="$(detect_edition "$INSTALLED")"

# ── Resolve the edition to build ────────────────────────────────────────────
# Precedence: explicit CSQ_EDITION > preserve installed > community default.
if [ -n "${CSQ_EDITION:-}" ]; then
    EDITION="$CSQ_EDITION"
elif [ -n "$INSTALLED_EDITION" ]; then
    EDITION="$INSTALLED_EDITION"
    echo "Preserving installed edition: $EDITION (override with CSQ_EDITION=…)"
else
    EDITION="community"
fi

case "$EDITION" in
    enterprise|community) ;;
    *) echo "FATAL: CSQ_EDITION must be 'enterprise' or 'community', got '$EDITION'" >&2; exit 64 ;;
esac

# ── Downgrade guard: never silently drop enterprise → community ─────────────
if [ "$INSTALLED_EDITION" = "enterprise" ] && [ "$EDITION" = "community" ] \
   && [ "${CSQ_EDITION:-}" != "community" ]; then
    echo "FATAL: refusing to downgrade the installed ENTERPRISE binary to community." >&2
    echo "  The installed $INSTALLED is the enterprise edition; a community build would" >&2
    echo "  drop the direct-API moat, licensing, and kailash trust plane." >&2
    echo "  To do this deliberately: CSQ_EDITION=community $0" >&2
    exit 65
fi

# ── Build ───────────────────────────────────────────────────────────────────
if [ "$EDITION" = "enterprise" ]; then
    FEATURES="cli,enterprise"
    # Enterprise pulls private git dependencies; using the git CLI transport
    # avoids libgit2 authentication flakiness against the private remote.
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
else
    FEATURES="cli"
fi

echo "Building csq CLI (release, edition=$EDITION, features=$FEATURES)…"
cargo build --release -p csq --features "$FEATURES" --no-default-features

# ── Sign (macOS) ────────────────────────────────────────────────────────────
if [ "$(uname -s)" = "Darwin" ]; then
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

# ── Install ─────────────────────────────────────────────────────────────────
mkdir -p "$BIN_DIR"
install -m 0755 target/release/csq "$INSTALLED"
echo "Installed csq → $INSTALLED"

# ── Post-install verification (fail loud on edition mismatch) ───────────────
NEW_EDITION="$(detect_edition "$INSTALLED")"
"$INSTALLED" --version
if [ "$NEW_EDITION" != "$EDITION" ]; then
    echo "FATAL: post-install edition mismatch — intended '$EDITION', binary reports '$NEW_EDITION'." >&2
    echo "  The installed binary is NOT what was requested. Do not trust this install." >&2
    exit 66
fi
echo "Verified: installed edition = $NEW_EDITION."
