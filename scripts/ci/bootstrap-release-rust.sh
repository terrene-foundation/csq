#!/usr/bin/env bash
# Fresh hosted-Linux Rust bootstrap for signer-producer and sbom only.
# Never reuse the runner image's Cargo/rustup homes or edit shell profiles.
set -euo pipefail
umask 077
# Ignore image-local Rust binaries and clear inherited Rustup controls.
export PATH=/usr/bin:/bin
unset BASH_ENV ENV CDPATH
for inherited_rustup_name in "${!RUSTUP_@}"; do
  unset "$inherited_rustup_name"
done

fail() { printf 'bootstrap-release-rust: %s\n' "$1" >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'requires Linux x86_64'
[[ -n "${RUNNER_TEMP:-}" && "$RUNNER_TEMP" == /* && -d "$RUNNER_TEMP" && -O "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] || fail 'RUNNER_TEMP must be an owned absolute directory'
[[ "$RUNNER_TEMP" != *$'\n'* && "$RUNNER_TEMP" != *$'\r'* ]] || fail 'invalid RUNNER_TEMP path'
for output in "${GITHUB_ENV:-}" "${GITHUB_PATH:-}" "${GITHUB_OUTPUT:-}"; do
  [[ -n "$output" && -f "$output" && -O "$output" && -w "$output" && ! -L "$output" ]] || fail 'runner output files must be owned writable regular files'
done

# Even the private Cargo version probe must not discover host configuration.
checkout=$(/bin/pwd -P)
[[ "${GITHUB_WORKSPACE:-}" == "$checkout" && "$checkout" == "$(/usr/bin/realpath -e -- "$GITHUB_WORKSPACE")" ]] || fail 'invalid checkout identity'
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
runner_home=$(/usr/bin/realpath -e -- "${HOME:?missing HOME}") || fail 'unmeasurable Cargo config ancestry'
[[ "$runner_home" == "$HOME" ]] || fail 'unmeasurable Cargo config ancestry'
case "$runner_home" in "$checkout"|"$checkout"/*) ;; *) refuse_external_config "$runner_home" ;; esac

state_dir=$(mktemp -d "${RUNNER_TEMP%/}/csq-rust.XXXXXX")
chmod 700 "$state_dir"
export CARGO_HOME="$state_dir/cargo"
export RUSTUP_HOME="$state_dir/rustup"
mkdir -m 700 "$CARGO_HOME" "$RUSTUP_HOME"
export RUSTUP_TOOLCHAIN=1.98.1
export RUSTUP_DIST_SERVER=https://static.rust-lang.org
export RUSTUP_UPDATE_ROOT=https://static.rust-lang.org/rustup
unset RUSTC RUSTDOC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER

# These constants are bound to the reviewed versioned official installer.
rustup_init_url='https://static.rust-lang.org/rustup/archive/1.29.2/x86_64-unknown-linux-gnu/rustup-init'
rustup_init_sha256='5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4'
rustup_version_expected='1.29.2'
curl -q --fail --silent --show-error --location --retry 3 --proto '=https' --proto-redir '=https' "$rustup_init_url" --output "$state_dir/rustup-init"
printf '%s  %s\n' "$rustup_init_sha256" "$state_dir/rustup-init" | sha256sum --check --strict
chmod 700 "$state_dir/rustup-init"
"$state_dir/rustup-init" -y --no-modify-path --profile minimal --default-host x86_64-unknown-linux-gnu --default-toolchain 1.98.1

# Only explicit private paths may satisfy the post-install checks.
rustup_version=$("$CARGO_HOME/bin/rustup" --version)
rustc_version=$("$CARGO_HOME/bin/rustc" --version)
cargo_version=$("$CARGO_HOME/bin/cargo" --version)
active_toolchain=$("$CARGO_HOME/bin/rustup" show active-toolchain)
case "$rustup_version" in "rustup $rustup_version_expected ("*')') ;; *) fail 'unexpected private rustup version' ;; esac
case "$rustc_version" in 'rustc 1.98.1 ('*')') ;; *) fail 'unexpected private rustc version' ;; esac
case "$cargo_version" in 'cargo 1.98.1 ('*')') ;; *) fail 'unexpected private cargo version' ;; esac
case "$active_toolchain" in '1.98.1-x86_64-unknown-linux-gnu '*) ;; *) fail 'unexpected private active toolchain' ;; esac

# Bind later steps to immutable bootstrap outputs, independently of GITHUB_ENV.
printf 'cargo_home=%s\nrustup_home=%s\n' "$CARGO_HOME" "$RUSTUP_HOME" >> "$GITHUB_OUTPUT"
# The current step and subsequent steps receive only the verified private home.
printf 'CARGO_HOME=%s\nRUSTUP_HOME=%s\nRUSTUP_TOOLCHAIN=1.98.1\n' "$CARGO_HOME" "$RUSTUP_HOME" >> "$GITHUB_ENV"
printf '%s\n' "$CARGO_HOME/bin" >> "$GITHUB_PATH"
printf 'bootstrap-release-rust: verified private Rust 1.98.1\n'
