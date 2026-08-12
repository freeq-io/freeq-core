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
  FREEQ_RELEASE_TARBALL  path to a pre-downloaded .tar.gz (skip network)
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
download_ok=0

# Prefer a pre-copied tarball (e.g. scp when GitHub CDN is flaky).
if [ -n "${FREEQ_RELEASE_TARBALL:-}" ] && [ -f "${FREEQ_RELEASE_TARBALL}" ]; then
  say "Using local tarball: $FREEQ_RELEASE_TARBALL"
  cp -f "$FREEQ_RELEASE_TARBALL" "$TMP_TAR"
  download_ok=1
fi

# GitHub API asset download (often works when browser CDN returns 503).
if [ "$download_ok" -eq 0 ]; then
  say "Trying GitHub API asset download…"
  asset_id="$(
    api_curl "${API_BASE}/repos/${REPO}/releases/tags/${TAG}" 2>/dev/null \
      | python3 -c '
import json,sys
name=sys.argv[1]
try:
    data=json.load(sys.stdin)
except Exception:
    sys.exit(0)
for a in data.get("assets") or []:
    if a.get("name")==name:
        print(a.get("id") or "")
        break
' "$ASSET" 2>/dev/null || true
  )"
  if [ -n "${asset_id:-}" ]; then
    api_headers=(-H "Accept: application/octet-stream")
    if [ -n "${FREEQ_GITHUB_TOKEN:-}" ]; then
      api_headers+=(-H "Authorization: Bearer ${FREEQ_GITHUB_TOKEN}")
    fi
    if curl -fL \
      --connect-timeout 30 \
      --max-time 600 \
      --retry 5 \
      --retry-delay 2 \
      --retry-all-errors \
      "${api_headers[@]}" \
      -o "$TMP_TAR" \
      "${API_BASE}/repos/${REPO}/releases/assets/${asset_id}"; then
      download_ok=1
    fi
  fi
fi

if [ "$download_ok" -eq 0 ] && command -v gh >/dev/null 2>&1; then
  say "Trying gh release download…"
  if (
    cd "$(dirname "$TMP_TAR")" \
      && gh release download "$TAG" -R "$REPO" -p "$ASSET" -O "$(basename "$TMP_TAR")" --clobber
  ); then
    download_ok=1
  fi
fi

if [ "$download_ok" -eq 0 ]; then
  # Browser CDN (github.com/…/releases/download/…) — can 503 intermittently.
  say "Trying browser CDN download…"
  if curl -fL \
    --connect-timeout 30 \
    --max-time 600 \
    --retry 10 \
    --retry-delay 2 \
    --retry-all-errors \
    -o "$TMP_TAR" \
    "$URL"; then
    download_ok=1
  fi
fi

if [ "$download_ok" -eq 0 ]; then
  echo "Download failed for asset: $ASSET" >&2
  echo "CDN URL: $URL" >&2
  echo "" >&2
  echo "Workarounds:" >&2
  echo "  1) Re-run installer (GitHub CDN sometimes 503s)" >&2
  echo "  2) On a Mac that works:" >&2
  echo "       gh release download $TAG -R $REPO -p $ASSET -D /tmp" >&2
  echo "       scp /tmp/$ASSET pwmfreeq@freeq.local:/tmp/" >&2
  echo "       ssh freeq.local 'FREEQ_RELEASE_TARBALL=/tmp/$ASSET curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh | bash'" >&2
  echo "  3) FREEQ_FROM_SOURCE=1 if Rust is installed on the host" >&2
  exit 1
fi

# Sanity: refuse tiny error HTML bodies (e.g. 503 page saved as file)
if [ ! -s "$TMP_TAR" ] || [ "$(wc -c <"$TMP_TAR" | tr -d ' ')" -lt 100000 ]; then
  echo "Downloaded file is too small to be a FreeQ release tarball." >&2
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
