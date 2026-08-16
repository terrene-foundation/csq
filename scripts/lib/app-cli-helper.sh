#!/usr/bin/env bash
#
# app-cli-helper.sh — create the standalone CLI helper inside a macOS .app
# bundle (Contents/Helpers/csq-cli), the structural fix for an internal ticket.
#
# WHY THIS EXISTS
# ----------------
# The desktop app refreshes `~/.local/bin/csq` on launch by copying a binary
# out of its own bundle (`csq_core::cli_deps::cli_shim::resolve_shim_source`,
# which looks for exactly `Contents/Helpers/csq-cli`). If that path is
# absent, the shim falls back to the bundle's MAIN executable
# (`Contents/MacOS/<CFBundleExecutable>`) — whose signature is BUNDLE-BOUND
# (Info.plist + sealed resources). That signature is INVALID once the file
# is copied to a standalone path, so hardened-runtime Gatekeeper SIGKILLs
# every subsequent CLI invocation (exit 137). See docs/release-signing.md §2
# for the full rationale and the `codesign --display --verbose=4` check that
# confirms the helper signs as a standalone (Info.plist=not bound) Mach-O.
#
# This manual-step omission — the helper existed only in release-signing.md
# prose and in scripts/release-enterprise-macos.sh, never in
# scripts/build-enterprise-desktop.sh — broke the operator's CLI in three
# separate sessions (2026-06-22, 2026-07-19, 2026-08-02) before this fix.
# It is a script defect, not a knowledge gap; this file is the structural
# close so it cannot regress a fourth time via a forgotten manual step.
#
# ORDERING IS LOAD-BEARING
# ------------------------
# `add_cli_helper` MUST be called BEFORE any `codesign --deep` pass. `--deep`
# propagates the Developer-ID signature into every nested Mach-O AND seals
# the bundle's resource envelope; a helper added AFTER that pass is captured
# by neither, invalidates the seal, and fails notarization
# (docs/release-signing.md lines 216-219).
#
# WHY THIS FUNCTION IS SHARED, NOT DUPLICATED PER CALLER
# ---------------------------------------------------------
# scripts/build-enterprise-desktop.sh (local/dev builds) and
# scripts/release-enterprise-macos.sh (signed/notarized release builds) both
# need this step. Before this file existed, only release-enterprise-macos.sh
# had it — build-enterprise-desktop.sh produced a .app with NO helper at
# all, which is exactly the defect this file exists to close. A single
# shared function means the two paths cannot drift apart again.

# add_cli_helper "$APP_DIR"
#
# Locates the bundle's main executable — CFBundleExecutable from
# Info.plist, falling back to the sole file in Contents/MacOS (the same
# resolution scripts/build-enterprise-desktop.sh's endpoint guard already
# uses) — copies it byte-for-byte to Contents/Helpers/csq-cli, and verifies
# the result is present, non-empty, and executable.
#
# Returns 0 on success (prints an OK line to stdout). Returns non-zero on
# ANY failure — bundle missing, main executable not found, helpers dir
# cannot be created, copy fails, or the copy is missing / zero-length /
# non-executable — printing a diagnostic naming an internal ticket to stderr and
# leaving NO partial artifact behind (a failed or truncated copy is removed,
# not assumed atomic).
#
# This function is meant to be `source`d, not executed directly — it uses
# `return`, not `exit`, so it never disturbs a caller's own `set -e` /
# exit-code scheme. Callers translate a non-zero return into their own exit
# code (see scripts/build-enterprise-desktop.sh and
# scripts/release-enterprise-macos.sh for the two current call sites).
add_cli_helper() {
    local app_dir="$1"

    if [[ -z "$app_dir" || ! -d "$app_dir" ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: bundle not found at '${app_dir:-<empty>}'" >&2
        return 1
    fi

    # Resolution order matches build-enterprise-desktop.sh's existing
    # endpoint guard: CFBundleExecutable first, "sole file in
    # Contents/MacOS" fallback. PlistBuddy is macOS-only; on a host without
    # it (e.g. the Linux shell-gate-selftest CI job that lints and RUNS
    # this file — .github/workflows/test.yml) the command substitution
    # fails closed to an empty string and this function falls straight to
    # the fallback below. No special-casing needed: `-f` on an empty `$exe`
    # is simply false.
    #
    # PLISTBUDDY_BIN is overridable (default: the real absolute path) SOLELY
    # so the self-test can point it at a stub and exercise the
    # CFBundleExecutable-resolution branch deterministically on hosts (e.g.
    # the Linux shell-gate-selftest CI runner) that have no real
    # /usr/libexec/PlistBuddy. Neither production caller
    # (build-enterprise-desktop.sh, release-enterprise-macos.sh) sets this —
    # they always get the real PlistBuddy on the macOS hosts they run on.
    local plist="$app_dir/Contents/Info.plist"
    local main_bin=""
    if [[ -f "$plist" ]]; then
        local exe
        exe="$("${PLISTBUDDY_BIN:-/usr/libexec/PlistBuddy}" -c 'Print :CFBundleExecutable' "$plist" 2>/dev/null || true)"
        if [[ -n "$exe" && -f "$app_dir/Contents/MacOS/$exe" ]]; then
            main_bin="$app_dir/Contents/MacOS/$exe"
        fi
    fi
    if [[ -z "$main_bin" ]]; then
        # `sort` before `head -1`: `find`'s traversal order is filesystem-
        # dependent, so on a bundle with no readable Info.plist AND more than
        # one file in Contents/MacOS this picked an arbitrary one — the same
        # input could resolve to a different "main executable" on two hosts, or
        # on the same host after a rebuild. Sorting makes the fallback
        # deterministic (still a guess, but a reproducible one, so a wrong
        # guess is diagnosable instead of intermittent). A well-formed Tauri
        # bundle never reaches here: it always has a valid CFBundleExecutable.
        main_bin="$(find "$app_dir/Contents/MacOS" -maxdepth 1 -type f 2>/dev/null | sort | head -1 || true)"
    fi

    if [[ -z "$main_bin" || ! -f "$main_bin" ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: could not locate the bundle's main executable under $app_dir/Contents/MacOS" >&2
        return 1
    fi

    local helpers_dir="$app_dir/Contents/Helpers"
    if ! mkdir -p "$helpers_dir"; then
        echo "FATAL (an internal ticket): add_cli_helper: could not create $helpers_dir" >&2
        return 1
    fi

    local dest="$helpers_dir/csq-cli"
    # Byte copy, not a symlink or hardlink: the whole point (see header
    # above) is a STANDALONE Mach-O the shim can copy to ~/.local/bin/csq
    # and have its signature remain valid. A symlink/hardlink to the
    # bundle-bound original would still resolve to bundle-bound content
    # once `--deep` signs it.
    #
    # `cat ... >dest` rather than `cp`: macOS `cp` invokes copyfile(3) and
    # carries extended attributes — including com.apple.provenance / a
    # quarantine flag on $main_bin — onto the copy by default (verified
    # empirically: `cp` AND `install -m` both preserved a test xattr here;
    # only a fresh-content write did not). csq-core's own shim refresh
    # (csq-core/src/cli_deps/cli_shim.rs) bans `cp` for exactly this reason
    # and instead does a fresh `std::fs::write` of the source bytes; `cat >`
    # is the shell equivalent — it opens $dest as a brand-new inode and
    # writes content only, with no copyfile(3) involved. This helper
    # doesn't currently reach a provenance-sensitive install path
    # (ensure_cli_shim writes its own fresh bytes downstream), but it is the
    # one file whose whole purpose is producing a binary that survives
    # being copied to a standalone path, so it shouldn't use the primitive
    # the codebase bans two files away.
    # Remove any prior helper FIRST. `>` truncates an existing file in place,
    # reusing its inode — and extended attributes live on the inode, not the
    # content. A `Contents/Helpers/csq-cli` left by an earlier build (this
    # directory is not one Tauri owns, so it is not guaranteed to be wiped
    # between builds, and the header above targets exactly this iterative
    # local-build use) would therefore keep its quarantine/provenance xattrs
    # through the rewrite, defeating the entire reason this is `cat >` and not
    # `cp`. `rm -f` forces a brand-new inode with no xattrs.
    rm -f "$dest"
    if ! cat "$main_bin" >"$dest" 2>/dev/null; then
        echo "FATAL (an internal ticket): add_cli_helper: copy from '$main_bin' to '$dest' failed" >&2
        rm -f "$dest"
        return 1
    fi
    chmod +x "$dest" 2>/dev/null || true

    # Assert a real, independent regular file — NOT a symlink, and NOT a
    # hardlink to $main_bin. `cmp -s` (the self-test's byte-identity check)
    # and `[ -x ]` both resolve THROUGH a symlink or a hardlink to the
    # bundle-bound original, so neither catches a regression back to
    # `ln -s`/`ln` here. This is the only guard standing between that
    # regression and a fourth recurrence of an internal ticket — see the header
    # comment above: a symlink/hardlink to the bundle-bound original still
    # resolves to bundle-bound (invalid, once copied out) content once
    # `--deep` signs it.
    if [[ -L "$dest" ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: $dest is a symlink, not a standalone copy" >&2
        rm -f "$dest"
        return 1
    fi
    # Compare device+inode (works whether the host's `stat` is BSD/macOS
    # `-f '%d:%i'` or GNU/Linux `-c '%d:%i'` — the CI shell-gate-selftest
    # job runs on Linux).
    local dest_id main_id
    dest_id="$(stat -f '%d:%i' "$dest" 2>/dev/null || stat -c '%d:%i' "$dest" 2>/dev/null || true)"
    main_id="$(stat -f '%d:%i' "$main_bin" 2>/dev/null || stat -c '%d:%i' "$main_bin" 2>/dev/null || true)"
    if [[ -n "$dest_id" && -n "$main_id" && "$dest_id" == "$main_id" ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: $dest is a hardlink to the bundle-bound main executable, not a standalone copy" >&2
        rm -f "$dest"
        return 1
    fi

    if [[ ! -f "$dest" ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: $dest missing immediately after copy" >&2
        return 1
    fi
    local dest_size
    dest_size="$(wc -c <"$dest" 2>/dev/null | tr -d '[:space:]')"
    if [[ -z "$dest_size" || "$dest_size" -eq 0 ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: $dest is zero-length after copy" >&2
        rm -f "$dest"
        return 1
    fi
    if [[ ! -x "$dest" ]]; then
        echo "FATAL (an internal ticket): add_cli_helper: $dest is not executable after chmod" >&2
        rm -f "$dest"
        return 1
    fi

    echo "==> OK: standalone CLI helper created at $dest (an internal ticket)"
    return 0
}
