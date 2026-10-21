#!/usr/bin/env bash
#
# bundle-guard.sh — the two structural gates that stand between a macOS
# enterprise tarball and the auto-update channel. Source it; do not execute it.
#
# WHY THIS IS A LIB, NOT INLINE
# -----------------------------
# These guards are trust-bearing: an internal ticket (an .app published without the standalone
# CLI helper makes every client's shim fall back to the bundle-bound binary,
# which Gatekeeper SIGKILLs once copied) and the version check (a stale bundle
# published under a new version label freezes clients). Their failure modes are
# only observable by DRIVING them with crafted archives — a corrupt gzip, an
# archive with the helper, one without, a mismatched Info.plist — which is
# impossible while the code sits inline in a script that also publishes. This
# extraction exists so `scripts/tests/bundle-guard.test.sh` can red on each.
#
# CONTRACT — require_enterprise_bundle ARTIFACTS_DIR VERSION
#   0   the bundle (if present) is publishable
#   65  the .app's CFBundleShortVersionString differs from VERSION
#   70  the bundle is unreadable, unlistable, lacks the CLI helper, or its
#       version cannot be read — UNMEASURED, never a pass
# A missing csq-desktop-macos.app.tar.gz is NOT a failure: a Linux-only
# publish has no macOS bundle to check.
#
# The membership tests are bash builtins (scripts/lib/strmatch.sh): `tar -tzf |
# grep -q` SIGPIPEs tar on an early match under pipefail (a PRESENT helper
# reads absent), and a here-string's tempfile failure exits 1 — the same code
# as "no match".

# shellcheck source=/dev/null
. "$(cd "${BASH_SOURCE[0]%/*}" && pwd)/strmatch.sh" || {
    echo "FATAL: cannot source scripts/lib/strmatch.sh — bundle membership would be unmeasurable" >&2
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then return 70; fi
    exit 70
}

require_enterprise_bundle() {
    local artifacts_dir="${1-}" version="${2-}"
    local tarball="$artifacts_dir/csq-desktop-macos.app.tar.gz"
    local listing="" member="" ptmp="" plist_ver=""

    if [ -z "$artifacts_dir" ] || [ -z "$version" ]; then
        echo "FATAL: require_enterprise_bundle needs <artifacts-dir> <version>" >&2
        return 70
    fi
    if [ ! -f "$tarball" ]; then
        # A Linux-only publish has no macOS bundle to check. Say so rather than
        # skipping silently: an unmeasured step must not look like a measured one.
        echo "==> NOT APPLICABLE: no macOS bundle at $tarball — no version measured"
        return 0
    fi

    # tar's OWN status first: a truncated/corrupt archive must not reach the
    # membership test, or its partial listing can satisfy an internal ticket.
    if ! listing="$(tar -tzf "$tarball" 2>/dev/null)"; then
        echo "FATAL (an internal ticket): cannot list $tarball — the archive is unreadable or truncated." >&2
        echo "  Publishing it would ship an .app that no client can extract. Refusing." >&2
        return 70
    fi
    if ! strmatch_regex "$listing" '^(\./)?[^/]+\.app/Contents/Helpers/csq-cli$'; then
        echo "FATAL (an internal ticket): $tarball does NOT contain .app/Contents/Helpers/csq-cli." >&2
        echo "  Publishing it would ship an .app whose CLI shim falls back to the" >&2
        echo "  bundle-bound main executable, which Gatekeeper SIGKILLs (exit 137) once" >&2
        echo "  copied to a standalone path — automatically, to every client that" >&2
        echo "  auto-updates." >&2
        return 70
    fi
    echo "==> OK: macOS tarball contains Contents/Helpers/csq-cli (an internal ticket)"

    # The version check needs PlistBuddy. Absent (a Linux publish host), the
    # version is UNMEASURED — and publishing an unmeasured bundle is exactly the
    # silent skip this guard exists to prevent. Refuse (70), unless an EXPLICIT
    # named waiver is set; the waiver is the security.md Rule 10 shape: named,
    # printed, and reviewable. CSQ_PLISTBUDDY is a test seam (a fixture can point
    # it at a path that does not exist).
    PLISTBUDDY="${CSQ_PLISTBUDDY:-/usr/libexec/PlistBuddy}"
    if [ ! -x "$PLISTBUDDY" ]; then
        if [ "${CSQ_BUNDLE_GUARD_WAIVE_VERSION:-0}" = "1" ]; then
            echo "WARN: CSQ_BUNDLE_GUARD_WAIVE_VERSION=1 — the bundle version was NOT measured (security.md Rule 10 waiver)" >&2
            return 0
        fi
        echo "FATAL: no PlistBuddy at $PLISTBUDDY — the bundle version cannot be measured." >&2
        echo "  Refusing to publish an unmeasured bundle. Set CSQ_BUNDLE_GUARD_WAIVE_VERSION=1" >&2
        echo "  with a written justification (security.md Rule 10) to waive this check." >&2
        return 70
    fi

    # Anchor to the TOP-LEVEL <name>.app/Contents/Info.plist (optionally
    # ./-prefixed) so a nested framework/helper-app Info.plist cannot be
    # selected and read the wrong version.
    while IFS= read -r _m; do
        if strmatch_regex "$_m" '^(\./)?[^/]+\.app/Contents/Info\.plist$'; then member="$_m"; break; fi
    done <<< "$listing"
    if [ -z "$member" ]; then
        echo "FATAL: $tarball has no top-level .app/Contents/Info.plist — the bundle version is unmeasured." >&2
        return 70
    fi
    ptmp="$(mktemp)" || { echo "FATAL: mktemp failed — cannot stage the Info.plist." >&2; return 70; }
    if ! tar -xzOf "$tarball" "$member" > "$ptmp" 2>/dev/null; then
        rm -f "$ptmp"
        echo "FATAL: cannot extract $member from $tarball — the bundle version is unmeasured." >&2
        return 70
    fi
    plist_ver="$("$PLISTBUDDY" -c 'Print :CFBundleShortVersionString' "$ptmp" 2>/dev/null)" || true
    rm -f "$ptmp"
    if [ -z "$plist_ver" ]; then
        echo "FATAL: cannot read CFBundleShortVersionString from $member — the bundle version is unmeasured." >&2
        return 70
    fi
    if [ "$plist_ver" != "$version" ]; then
        echo "FATAL: macOS .app is version $plist_ver but publishing as $version (stale bundle in $artifacts_dir)." >&2
        return 65
    fi
    echo "==> OK: macOS .app version ($plist_ver) matches publish version"
    return 0
}
