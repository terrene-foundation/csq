#!/usr/bin/env bash
# Finite, clean-environment consumers of bootstrap-release-rust step outputs.
set -euo pipefail
export PATH=/usr/bin:/bin

fail() { printf 'release-rust-runner: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 ]] || fail 'unsupported command mode'
case "$1" in build-sign-release|install-cyclonedx|generate-sbom) mode=$1 ;; *) fail 'unsupported command mode' ;; esac
[[ -n "${BOOTSTRAP_CARGO_HOME:-}" && -n "${BOOTSTRAP_RUSTUP_HOME:-}" &&
   "${CARGO_HOME:-}" == "$BOOTSTRAP_CARGO_HOME" && "${RUSTUP_HOME:-}" == "$BOOTSTRAP_RUSTUP_HOME" ]] || fail 'bootstrap output mismatch'
for path_value in "$BOOTSTRAP_CARGO_HOME" "$BOOTSTRAP_RUSTUP_HOME" "${RUNNER_TEMP:-}" "${GITHUB_WORKSPACE:-}" "${HOME:-}"; do
  [[ "$path_value" == /* && "$path_value" != *$'\n'* && "$path_value" != *$'\r'* ]] || fail 'invalid private prefix'
done
[[ -d "$RUNNER_TEMP" && -O "$RUNNER_TEMP" ]] || fail 'invalid private prefix'
runner_temp=$(/usr/bin/realpath -e -- "$RUNNER_TEMP") || fail 'invalid private prefix'
checkout=$(/bin/pwd -P)
[[ "$GITHUB_WORKSPACE" == "$checkout" && "$checkout" == "$(/usr/bin/realpath -e -- "$GITHUB_WORKSPACE")" ]] || fail 'invalid checkout identity'
[[ "$RUNNER_TEMP" == "$runner_temp" ]] || fail 'invalid private prefix'
cargo_home=$BOOTSTRAP_CARGO_HOME
rustup_home=$BOOTSTRAP_RUSTUP_HOME
state_dir=${cargo_home%/cargo}
case "$state_dir" in "$runner_temp"/csq-rust.*) ;; *) fail 'invalid private prefix' ;; esac
[[ "$cargo_home" == "$state_dir/cargo" && "$rustup_home" == "$state_dir/rustup" && "${state_dir%/*}" == "$runner_temp" ]] || fail 'invalid private prefix'

verify_private_homes() {
  local private_dir
  for private_dir in "$state_dir" "$cargo_home" "$rustup_home"; do
    [[ -d "$private_dir" && -O "$private_dir" && ! -L "$private_dir" ]] || fail 'invalid private prefix'
    [[ "$(/usr/bin/realpath -e -- "$private_dir")" == "$private_dir" ]] || fail 'invalid private prefix'
    [[ "$(/usr/bin/stat -c '%a:%u' -- "$private_dir")" == "700:$EUID" ]] || fail 'invalid private prefix'
  done
}
verify_private_homes

# Cargo discovers .cargo/config{,.toml} above its working directory, even
# with a fresh CARGO_HOME. Reject those outside the reviewed checkout.
refuse_external_config() {
  local directory=$1 cargo_config_dir
  [[ -d "$directory" && -r "$directory" && -x "$directory" ]] || fail 'unmeasurable Cargo config ancestry'
  cargo_config_dir="$directory/.cargo"
  if [[ -e "$cargo_config_dir" || -L "$cargo_config_dir" ]]; then
    [[ -d "$cargo_config_dir" && -r "$cargo_config_dir" && -x "$cargo_config_dir" ]] || fail 'unmeasurable Cargo config ancestry'
    if [[ -e "$cargo_config_dir/config" || -L "$cargo_config_dir/config" ||
          -e "$cargo_config_dir/config.toml" || -L "$cargo_config_dir/config.toml" ]]; then
      fail 'external Cargo config'
    fi
  fi
}
ancestor=${checkout%/*}
[[ -n "$ancestor" ]] || ancestor=/
while :; do
  refuse_external_config "$ancestor"
  [[ "$ancestor" != / ]] || break
  ancestor=${ancestor%/*}
  [[ -n "$ancestor" ]] || ancestor=/
done
runner_home=$(/usr/bin/realpath -e -- "$HOME") || fail 'unmeasurable Cargo config ancestry'
[[ "$runner_home" == "$HOME" ]] || fail 'unmeasurable Cargo config ancestry'
case "$runner_home" in "$checkout"|"$checkout"/*) ;; *) refuse_external_config "$runner_home" ;; esac

[[ -n "${TAG:-}" && "$TAG" != */* && "$TAG" != *$'\n'* && "$TAG" != *$'\r'* ]] || fail 'invalid release tag'
# Recheck the immutable output binding and canonical homes immediately before
# execution. Private Cargo configs are allowed inside the verified CARGO_HOME.
[[ "${CARGO_HOME:-}" == "$cargo_home" && "${RUSTUP_HOME:-}" == "$rustup_home" ]] || fail 'bootstrap output mismatch'
verify_private_homes
for executable in cargo rustc rustup; do
  resolved=$(/usr/bin/realpath -e -- "$cargo_home/bin/$executable") || fail 'missing private executable'
  [[ -f "$resolved" && -x "$resolved" && -O "$resolved" ]] || fail 'missing private executable'
  case "$resolved" in "$cargo_home"/*) ;; *) fail 'private executable escaped its home' ;; esac
done
readonly cargo_home rustup_home checkout runner_home state_dir runner_temp mode
clean_env=(/usr/bin/env -i "PATH=$cargo_home/bin:/usr/bin:/bin" "HOME=$runner_home"
  "CARGO_HOME=$cargo_home" "RUSTUP_HOME=$rustup_home" "RUSTUP_TOOLCHAIN=1.98.1" "TAG=$TAG" "LC_ALL=C")
case "$mode" in
  build-sign-release)
    exec "${clean_env[@]}" "$cargo_home/bin/cargo" build --locked --release --bin sign-release -p csq-core ;;
  install-cyclonedx)
    exec "${clean_env[@]}" "$cargo_home/bin/cargo" install cargo-cyclonedx --version '=0.5.9' --locked ;;
  generate-sbom)
    exec "${clean_env[@]}" /bin/bash --noprofile --norc "$checkout/enterprise-src/scripts/generate-sbom.sh" "csq-sbom-${TAG}.cdx.json" ;;
esac
