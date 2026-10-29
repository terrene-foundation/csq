#!/usr/bin/env bash
# Pre-whole-leg admission; the payload inherits a shared advisory target lease.
# This policy neither bounds peak growth nor excludes uncooperating Cargo writers.
set -euo pipefail
here="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)"
workspace="$PWD"
selected=""
cap=34359738368
ephemeral=""
refuse() {
    printf '{"instrument":"cargo-target-highwater","scope":"exclusive-cargo-target","status":"UNDETERMINED","cap_bytes":null,"before_bytes":null,"after_bytes":null,"actions":[],"reason":"%s","remediation":"%s","skipped_profiles":[]}\n' "$1" "$2" >&2
    exit 75
}
while (($#)); do
    case "$1" in
        --workspace|--target-dir|--cap-bytes|--ephemeral-root)
            (($# >= 2)) || refuse missing-option-value "Supply a value for every admission option."
            case "$1" in
                --workspace) workspace="$2" ;;
                --target-dir) selected="$2" ;;
                --cap-bytes) cap="$2" ;;
                --ephemeral-root) ephemeral="$2" ;;
            esac
            shift 2 ;;
        --) shift; break ;;
        *) refuse unknown-option "Use only supported admission options before --." ;;
    esac
done
(($#)) || refuse whole-leg-command-required "Supply the complete workload command after --."
case "$cap" in ''|*[!0-9]*) refuse invalid-cap "Supply a positive integer cap no greater than 32 GiB." ;; esac
# Reject raw parent traversal before Cargo can normalize it in metadata output.
for raw_target in "${CARGO_TARGET_DIR-}" "${CARGO_BUILD_TARGET_DIR-}"; do
    case "/$raw_target/" in
        */../*) refuse path-traversal "Supply an absolute target path without parent traversal." ;;
    esac
done
# Resolve from the final environment, including Cargo's actual config precedence.
# shellcheck source=scripts/lib/cargo-target-dir.sh
. "$here/../lib/cargo-target-dir.sh"
resolved="$(cargo_target_dir "$workspace")" || refuse target-resolution-failed "Restore Cargo metadata target resolution before retrying."
py="$(resolve_python3)" || refuse python-resolution-failed "Install a working Python 3 interpreter before retrying."
exec "$py" "$here/cargo-target-highwater.py" \
    --workspace "$workspace" --resolved-target "$resolved" \
    --target-dir "$selected" --cap-bytes "$cap" \
    --ephemeral-root "$ephemeral" -- "$@"
