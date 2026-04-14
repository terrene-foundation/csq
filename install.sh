#!/usr/bin/env bash
set -euo pipefail

# Code Session Quota (csq) installer
#
# Downloads the latest csq CLI binary from GitHub Releases for the host
# platform, verifies its SHA256 against the release's SHA256SUMS file,
# and installs it to ~/.local/bin/csq.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/terrene-foundation/csq/main/install.sh | bash
#
# Or with a specific version:
#   curl -sSL https://raw.githubusercontent.com/terrene-foundation/csq/main/install.sh | CSQ_VERSION=v2.0.0-alpha.3 bash
#
# Options (env vars):
#   CSQ_VERSION  — tag to install (default: latest)
#   CSQ_BIN_DIR  — install directory (default: ~/.local/bin or ~/bin if on $PATH)
#   CSQ_NO_VERIFY — if set to 1, skip SHA256 verification (NOT RECOMMENDED)

REPO="terrene-foundation/csq"
CSQ_VERSION="${CSQ_VERSION:-latest}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}!${NC} %s\n" "$*" >&2; }
err()  { printf "${RED}✗${NC} %s\n" "$*" >&2; }
info() { printf "${BOLD}%s${NC}\n" "$*"; }

# ─── Detect platform ──────────────────────────────────────
detect_platform() {
    local os arch
    case "$(uname -s)" in
        Darwin) os="macos" ;;
        Linux)  os="linux" ;;
        MINGW*|MSYS*|CYGWIN*)
            err "Windows is not supported by this script. Build from source:"
            err "  https://github.com/${REPO}#cli"
            exit 1
            ;;
        *) err "unsupported OS: $(uname -s)"; exit 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)    arch="x86_64" ;;
        arm64|aarch64)
            if [ "$os" = "linux" ]; then
                err "Linux aarch64 is not yet published. Build from source:"
                err "  https://github.com/${REPO}#cli"
                exit 1
            fi
            arch="aarch64"
            ;;
        *) err "unsupported architecture: $(uname -m)"; exit 1 ;;
    esac

    echo "${os}-${arch}"
}

# ─── Pick install directory ──────────────────────────────
pick_bin_dir() {
    if [ -n "${CSQ_BIN_DIR:-}" ]; then
        echo "$CSQ_BIN_DIR"
        return
    fi

    if [ -d "$HOME/bin" ] && echo ":$PATH:" | grep -q ":$HOME/bin:"; then
        echo "$HOME/bin"
    else
        echo "$HOME/.local/bin"
    fi
}

# ─── Resolve tag to download from ────────────────────────

# Validates that a tag name looks like a semver release. Rejects
# arbitrary characters that could alter the download path or
# resolve to an unexpected artifact.
#
# Bash `case` globs use `*` as "any char including /, ;, newline",
# which is too permissive here — we use a strict `=~` regex anchor
# so only vMAJOR.MINOR.PATCH[-prerelease] shapes pass.
validate_tag() {
    local tag="$1"
    if [[ ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
        err "refusing unexpected tag name: '$tag'"
        err "  expected format: vMAJOR.MINOR.PATCH[-prerelease]"
        exit 1
    fi
}

resolve_tag() {
    if [ "$CSQ_VERSION" != "latest" ]; then
        validate_tag "$CSQ_VERSION"
        echo "$CSQ_VERSION"
        return
    fi

    # We do NOT use `/releases/latest` — that endpoint excludes
    # prereleases and returns the old Python-era `v1.x` stable line
    # while the current Rust tool is in `v2.0.0-alpha.*`.
    #
    # We also do NOT trust the server order of `/releases`. Observed
    # live on the csq repo: GitHub returned `alpha.9` ahead of
    # `alpha.11` even though `alpha.11` has a later `created_at` AND
    # `published_at`. The server-side sort appears to be based on an
    # internal `updated_at` that bumps when a second pass updates a
    # release (e.g. a delayed asset upload). Client-side sort is the
    # only reliable answer.
    #
    # Strategy: fetch 30 releases, extract every valid semver tag,
    # sort with `sort -V` (GNU/BSD version sort), pick the highest.
    local response
    response=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=30" 2>/dev/null)
    if [ -z "$response" ]; then
        err "could not fetch releases from GitHub API"
        err "  set CSQ_VERSION=vX.Y.Z to install a specific version"
        exit 1
    fi

    # Extract all tag_name fields. GitHub's API always emits
    # `"tag_name": "vX.Y.Z..."` so a grep+sed line-level match works
    # without needing a JSON parser in the installer.
    local tags
    tags=$(printf '%s' "$response" \
        | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | sed -E 's/.*"([^"]+)"$/\1/')

    if [ -z "$tags" ]; then
        err "could not parse any tag_name from GitHub API response"
        err "  set CSQ_VERSION=vX.Y.Z to install a specific version"
        exit 1
    fi

    # Filter to strict-semver shapes and sort descending. `sort -V`
    # orders prerelease suffixes correctly (alpha.9 < alpha.10 <
    # alpha.11), which `sort` without `-V` does not. Both GNU coreutils
    # and macOS Ventura+ `sort` support `-V`.
    local tag
    tag=$(printf '%s\n' "$tags" \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' \
        | sort -Vr \
        | head -1)

    if [ -z "$tag" ]; then
        err "no valid semver tag found in GitHub API response"
        err "  set CSQ_VERSION=vX.Y.Z to install a specific version"
        exit 1
    fi

    validate_tag "$tag"

    # Look up the `prerelease` flag for the selected tag. This is a
    # second grep on the response; the JSON is ordered so each tag's
    # prerelease field is the closest one that follows. We match in
    # line order: find the line with our tag, then the next
    # "prerelease":(true|false). Best-effort; if it fails we silently
    # skip the PRE-RELEASE warning rather than block the install.
    local is_prerelease
    is_prerelease=$(printf '%s' "$response" \
        | awk -v t="\"$tag\"" '
            index($0, t) { found=1 }
            found && /"prerelease"[[:space:]]*:[[:space:]]*(true|false)/ {
                match($0, /(true|false)/);
                print substr($0, RSTART, RLENGTH);
                exit;
            }' \
        || true)
    if [ "$is_prerelease" = "true" ]; then
        warn "installing PRE-RELEASE build $tag"
        warn "pin a specific version with CSQ_VERSION=vX.Y.Z if needed"
    fi
    echo "$tag"
}

# ─── Download + verify + install ──────────────────────────
main() {
    info "Code Session Quota (csq) installer"
    echo

    command -v curl >/dev/null 2>&1 || { err "curl is required"; exit 1; }
    command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 || {
        err "shasum or sha256sum is required"
        exit 1
    }

    local platform tag bin_dir artifact url checksum_url tmp
    platform=$(detect_platform)
    tag=$(resolve_tag)
    bin_dir=$(pick_bin_dir)
    artifact="csq-${platform}"
    url="https://github.com/${REPO}/releases/download/${tag}/${artifact}"
    checksum_url="https://github.com/${REPO}/releases/download/${tag}/SHA256SUMS"

    echo "  Platform: ${BOLD}${platform}${NC}"
    echo "  Version:  ${BOLD}${tag}${NC}"
    echo "  Target:   ${BOLD}${bin_dir}/csq${NC}"
    echo

    tmp=$(mktemp -d)
    # `tmp` is declared `local` inside main, so it goes out of scope
    # when main returns. The EXIT trap fires at SCRIPT exit, after
    # main has already returned — `${tmp:-}` handles the out-of-scope
    # case so `set -u` doesn't fail on unbound variable at teardown.
    # shellcheck disable=SC2064  # expand tmp now, not at trap time
    trap "rm -rf \"$tmp\"" EXIT

    # Distinguish "tag does not exist" from "asset not in this
    # release" so the user gets an actionable error. We resolved
    # `tag` above; check the tag's release page first.
    info "Verifying tag ${tag} exists..."
    local tag_status
    tag_status=$(curl -fsI -o /dev/null -w "%{http_code}" \
        "https://api.github.com/repos/${REPO}/releases/tags/${tag}" 2>/dev/null || echo "000")
    if [ "$tag_status" = "404" ]; then
        err "tag ${tag} not found in ${REPO}"
        err "  list releases:   https://github.com/${REPO}/releases"
        err "  build from source: https://github.com/${REPO}#cli--from-source"
        exit 1
    fi

    info "Downloading ${artifact}..."
    if ! curl -fsSL -o "$tmp/$artifact" "$url"; then
        err "no ${artifact} asset in release ${tag}"
        err "  your platform may not be published for this version"
        err "  build from source: https://github.com/${REPO}#cli--from-source"
        exit 1
    fi

    if [ "${CSQ_NO_VERIFY:-0}" = "1" ]; then
        warn "skipping SHA256 verification (CSQ_NO_VERIFY=1)"
    else
        info "Verifying SHA256..."
        if ! curl -fsSL -o "$tmp/SHA256SUMS" "$checksum_url"; then
            err "failed to download SHA256SUMS"
            exit 1
        fi

        local expected actual
        # Use awk field-match instead of grep substring to avoid
        # false matches on filenames that share a suffix.
        expected=$(awk -v a="$artifact" '$2 == a {print $1}' "$tmp/SHA256SUMS")
        if [ -z "$expected" ]; then
            err "SHA256SUMS does not contain an entry for ${artifact}"
            exit 1
        fi

        if command -v sha256sum >/dev/null 2>&1; then
            actual=$(sha256sum "$tmp/$artifact" | awk '{print $1}')
        else
            actual=$(shasum -a 256 "$tmp/$artifact" | awk '{print $1}')
        fi

        if [ "$actual" != "$expected" ]; then
            err "SHA256 mismatch for ${artifact}"
            err "  expected: $expected"
            err "  actual:   $actual"
            err "  (this is a SECURITY failure — refusing to install)"
            exit 1
        fi
        ok "SHA256 verified"
    fi

    mkdir -p "$bin_dir"
    install -m 0755 "$tmp/$artifact" "$bin_dir/csq"
    ok "Installed csq to ${bin_dir}/csq"

    echo
    if echo ":$PATH:" | grep -q ":$bin_dir:"; then
        info "Next steps:"
        echo "  csq --version         # verify install"
        echo "  csq doctor            # run diagnostics"
        echo "  csq login 1           # authenticate your first account"
    else
        warn "$bin_dir is not on your PATH."
        echo "  Add this to your shell rc file:"
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

main "$@"
