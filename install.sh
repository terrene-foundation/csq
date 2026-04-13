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
warn() { printf "${YELLOW}!${NC} %s\n" "$*"; }
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
    # Use /releases?per_page=1 rather than /releases/latest because
    # /releases/latest skips prereleases and would hand back the old
    # Python-era v1.x stable line even while the current Rust tool is
    # in v2.0.0-alpha.* pre-release. Users running `install.sh` expect
    # the newest csq regardless of prerelease flag.
    #
    # /releases returns entries sorted by published_at descending, so
    # the first tag is always the most recently published release.
    local tag is_prerelease
    local response
    response=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=1" 2>/dev/null)
    tag=$(printf '%s' "$response" \
        | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | head -1 \
        | sed -E 's/.*"([^"]+)"$/\1/')
    is_prerelease=$(printf '%s' "$response" \
        | grep -oE '"prerelease"[[:space:]]*:[[:space:]]*(true|false)' \
        | head -1 \
        | sed -E 's/.*:[[:space:]]*(true|false).*/\1/')
    if [ -z "$tag" ]; then
        err "could not resolve latest csq version from GitHub API"
        err "  set CSQ_VERSION=vX.Y.Z to install a specific version"
        exit 1
    fi
    validate_tag "$tag"
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
    trap 'rm -rf "$tmp"' EXIT

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
