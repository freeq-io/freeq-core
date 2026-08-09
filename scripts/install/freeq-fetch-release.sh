#!/usr/bin/env bash
# Download a FreeQ Core release tarball (prebuilt binaries + scripts) from GitHub.
set -euo pipefail

_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$_src")" && pwd)"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
fi
if [ -z "${SCRIPT_DIR:-}" ] || [ ! -f "$SCRIPT_DIR/freeq-platform.sh" ]; then
  echo "freeq-fetch-release.sh: freeq-platform.sh not found next to this script" >&2
  exit 1
fi
# shellcheck source=freeq-platform.sh
source "$SCRIPT_DIR/freeq-platform.sh"

REPO="${FREEQ_GITHUB_REPO:-freeq-io/freeq-core}"
API_BASE="${FREEQ_GITHUB_API:-https://api.github.com}"
DOWNLOAD_BASE="${FREEQ_GITHUB_DOWNLOAD:-https://github.com/${REPO}/releases/download}"
VERSION="${FREEQ_VERSION:-latest}"
DEST_DIR="${FREEQ_INSTALL_DIR:-${HOME}/.freeq/dist}"
BIN_LINK_DIR="${FREEQ_BIN_DIR:-${HOME}/.freeq/bin}"
DRY_RUN=0

usage() {
  cat <<'EOF'
Download FreeQ Core prebuilt release binaries.

Usage:
  freeq-fetch-release.sh [--version vX.Y.Z|latest] [--dest DIR] [--dry-run]

Environment:
  FREEQ_VERSION          release tag or "latest" (default: latest)
  FREEQ_INSTALL_DIR      extract root (default: ~/.freeq/dist)
  FREEQ_BIN_DIR          symlink bin dir (default: ~/.freeq/bin)
  FREEQ_GITHUB_REPO      owner/name (default: freeq-io/freeq-core)
  FREEQ_GITHUB_TOKEN     optional token for higher API rate limits
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dest) DEST_DIR="$2"; shift 2 ;;
    --bin-dir) BIN_LINK_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 1
  }
}

need curl
need tar
need uname

api_curl() {
  local url="$1"
  if [ -n "${FREEQ_GITHUB_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer ${FREEQ_GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "$url"
  else
    curl -fsSL -H "Accept: application/vnd.github+json" "$url"
  fi
}

resolve_tag() {
  local ver="$1"
  if [ "$ver" = "latest" ]; then
    api_curl "${API_BASE}/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -1
  else
    # normalize to v-prefixed tag
    case "$ver" in
      v*) printf '%s\n' "$ver" ;;
      *) printf 'v%s\n' "$ver" ;;
    esac
  fi
}

say() { printf '%s\n' "$*"; }

TAG="$(resolve_tag "$VERSION")"
if [ -z "$TAG" ]; then
  echo "Could not resolve FreeQ release tag (version=${VERSION})." >&2
  echo "Check https://github.com/${REPO}/releases" >&2
  exit 1
fi

TRIPLE="$(freeq_target_triple)"
STEM="$(freeq_asset_stem "$TAG")"
ASSET="${STEM}.tar.gz"
URL="${DOWNLOAD_BASE}/${TAG}/${ASSET}"
STAGE_ROOT="${DEST_DIR%/}"
EXTRACT_DIR="${STAGE_ROOT}/${TAG}"
TARBALL="${STAGE_ROOT}/${ASSET}"

say "FreeQ release fetch"
say "  repo:    ${REPO}"
say "  tag:     ${TAG}"
say "  target:  ${TRIPLE}"
say "  asset:   ${ASSET}"
say "  url:     ${URL}"
say "  dest:    ${EXTRACT_DIR}"
say "  bin dir: ${BIN_LINK_DIR}"

if [ "$DRY_RUN" -eq 1 ]; then
  say "Dry run only. Nothing was downloaded."
  exit 0
fi

mkdir -p "$STAGE_ROOT" "$BIN_LINK_DIR"

TMP_TAR="$(mktemp "${TMPDIR:-/tmp}/freeq-release.XXXXXX.tar.gz")"
cleanup() { rm -f "$TMP_TAR"; }
trap cleanup EXIT

say "Downloading..."
if ! curl -fL --retry 3 --retry-delay 1 -o "$TMP_TAR" "$URL"; then
  echo "Download failed: $URL" >&2
  echo "This platform may not have a published binary yet, or the tag is wrong." >&2
  exit 1
fi

rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$TMP_TAR" -C "$EXTRACT_DIR" --strip-components=1

# Expected layout after strip: bin/*, scripts/*, VERSION
if [ ! -x "$EXTRACT_DIR/bin/freeqd" ] || [ ! -x "$EXTRACT_DIR/bin/freeq" ]; then
  echo "Release archive missing bin/freeq or bin/freeqd: $EXTRACT_DIR" >&2
  exit 1
fi

# Symlink binaries into ~/.freeq/bin
for b in freeq freeqd freeq-gateway freeq-perf-identity; do
  if [ -x "$EXTRACT_DIR/bin/$b" ]; then
    ln -sfn "$EXTRACT_DIR/bin/$b" "$BIN_LINK_DIR/$b"
  fi
done

# Current pointer for scripts / FREEQ_INSTALL_DIR default
ln -sfn "$EXTRACT_DIR" "${STAGE_ROOT}/current"

# Record metadata
printf '%s\n' "$TAG" >"$EXTRACT_DIR/RELEASE_TAG"
printf '%s\n' "$TRIPLE" >"$EXTRACT_DIR/TARGET"
printf '%s\n' "$URL" >"$EXTRACT_DIR/DOWNLOAD_URL"

say "Installed release tree: $EXTRACT_DIR"
say "Binaries linked in:     $BIN_LINK_DIR"
say "Current pointer:        ${STAGE_ROOT}/current"
say ""
say "Add binaries to your PATH (recommended):"
say "  export PATH=\"${BIN_LINK_DIR}:\$PATH\""

# Export for callers that source-and-run patterns
export FREEQ_INSTALL_DIR="$EXTRACT_DIR"
export FREEQ_BIN_DIR="$BIN_LINK_DIR"
export FREEQ_RELEASE_TAG="$TAG"
