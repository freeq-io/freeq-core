#!/usr/bin/env bash
# Detect host OS/arch and map to FreeQ release target triple.
# Source this file, or run: freeq-platform.sh [--triple|--os|--arch|--asset-prefix]
set -euo pipefail

freeq_host_os() {
  local u
  u="$(uname -s 2>/dev/null || echo unknown)"
  case "$u" in
    Darwin) printf 'macos\n' ;;
    Linux) printf 'linux\n' ;;
    *) printf '%s\n' "$(printf '%s' "$u" | tr '[:upper:]' '[:lower:]')" ;;
  esac
}

freeq_host_arch() {
  local m
  m="$(uname -m 2>/dev/null || echo unknown)"
  case "$m" in
    x86_64|amd64) printf 'x86_64\n' ;;
    arm64|aarch64) printf 'aarch64\n' ;;
    *) printf '%s\n' "$m" ;;
  esac
}

# Cargo/Rust target triple used in release asset names.
freeq_target_triple() {
  local os arch
  os="$(freeq_host_os)"
  arch="$(freeq_host_arch)"
  case "${os}-${arch}" in
    macos-aarch64) printf 'aarch64-apple-darwin\n' ;;
    macos-x86_64) printf 'x86_64-apple-darwin\n' ;;
    linux-aarch64) printf 'aarch64-unknown-linux-gnu\n' ;;
    linux-x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
    *)
      echo "Unsupported FreeQ install platform: os=${os} arch=${arch}" >&2
      return 1
      ;;
  esac
}

# Asset basename without .tar.gz: freeq-core-<version>-<triple>
freeq_asset_stem() {
  local version="$1"
  local triple
  triple="$(freeq_target_triple)"
  version="${version#v}"
  printf 'freeq-core-v%s-%s\n' "$version" "$triple"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
    --os) freeq_host_os ;;
    --arch) freeq_host_arch ;;
    --triple|"") freeq_target_triple ;;
    --asset-stem)
      freeq_asset_stem "${2:?version required, e.g. 0.2.1 or v0.2.1}"
      ;;
    -h|--help)
      cat <<'EOF'
FreeQ platform helper

  freeq-platform.sh              print rustc target triple
  freeq-platform.sh --os         macos|linux
  freeq-platform.sh --arch       aarch64|x86_64
  freeq-platform.sh --asset-stem v0.2.1
EOF
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
fi
