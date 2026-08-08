#!/usr/bin/env bash
# Build FreeQ release binaries and pack bin/ + scripts into a platform tarball.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../install/freeq-platform.sh
source "$ROOT/scripts/install/freeq-platform.sh"

VERSION="${FREEQ_PACKAGE_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
fi
VERSION="${VERSION#v}"
TAG="v${VERSION}"

TRIPLE="${FREEQ_TARGET_TRIPLE:-$(freeq_target_triple)}"
OUT_DIR="${FREEQ_PACKAGE_OUT:-$ROOT/dist}"
STEM="freeq-core-${TAG}-${TRIPLE}"
STAGE="$OUT_DIR/${STEM}"

PACKAGES="${FREEQ_PACKAGE_CRATES:-freeq freeqd freeq-gateway freeq-perf-identity}"

say() { printf '%s\n' "$*"; }

say "Packaging FreeQ ${TAG} for ${TRIPLE}"
say "  root: $ROOT"
say "  out:  $OUT_DIR"

mkdir -p "$OUT_DIR"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/scripts" "$STAGE/docs"

if [ "${FREEQ_PACKAGE_SKIP_BUILD:-0}" != "1" ]; then
  say "Building release crates: $PACKAGES"
  # shellcheck disable=SC2086
  cargo build --release --locked $(printf ' -p %s' $PACKAGES)
fi

copy_bin() {
  local name="$1"
  local src="$ROOT/target/release/${name}"
  if [ ! -x "$src" ]; then
    # Windows would use .exe; not packaged yet.
    echo "Missing built binary: $src" >&2
    exit 1
  fi
  cp "$src" "$STAGE/bin/$name"
  chmod 755 "$STAGE/bin/$name"
}

for b in freeq freeqd freeq-gateway freeq-perf-identity; do
  if [ -x "$ROOT/target/release/$b" ] || [ "${FREEQ_PACKAGE_SKIP_BUILD:-0}" != "1" ]; then
    copy_bin "$b"
  fi
done

# Ship scripts needed for install/pair/start/stop/doctor (not full repo).
copy_tree() {
  local src="$1"
  local dst="$2"
  mkdir -p "$dst"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.DS_Store' "$src" "$dst"
  else
    rm -rf "$dst"
    mkdir -p "$(dirname "$dst")"
    cp -R "$src" "$dst"
  fi
}
copy_tree "$ROOT/scripts/install/" "$STAGE/scripts/install/"
copy_tree "$ROOT/scripts/setup/" "$STAGE/scripts/setup/"
# Optional helpers used by docs / advanced ops
if [ -d "$ROOT/scripts/perf" ]; then
  mkdir -p "$STAGE/scripts/perf"
  for f in freeq-bidirectional-smoke-macos.sh freeq-perf-preflight-macos.sh; do
    if [ -f "$ROOT/scripts/perf/$f" ]; then
      cp "$ROOT/scripts/perf/$f" "$STAGE/scripts/perf/$f"
      chmod 755 "$STAGE/scripts/perf/$f"
    fi
  done
fi

for doc in simple-install.md auto-pair-install.md setup-macos.md threat-model.md; do
  if [ -f "$ROOT/docs/$doc" ]; then
    cp "$ROOT/docs/$doc" "$STAGE/docs/$doc"
  fi
done

printf '%s\n' "$VERSION" >"$STAGE/VERSION"
printf '%s\n' "$TAG" >"$STAGE/RELEASE_TAG"
printf '%s\n' "$TRIPLE" >"$STAGE/TARGET"
cat >"$STAGE/README.txt" <<EOF
FreeQ Core ${TAG} (${TRIPLE})

Contents:
  bin/freeq              CLI
  bin/freeqd             node daemon
  bin/freeq-gateway      accept-only gateway
  bin/freeq-perf-identity  identity generator used by installers
  scripts/               install, setup, pair helpers
  docs/                  user-facing install docs

Quick install (preferred):
  curl installer from GitHub releases / main scripts/install/

Or manually:
  export PATH="\$PWD/bin:\$PATH"
  freeq --help
EOF

# Flatten path for tarball: freeq-core-vX-triple/{bin,scripts,...}
TARBALL="$OUT_DIR/${STEM}.tar.gz"
tar -czf "$TARBALL" -C "$OUT_DIR" "$STEM"

say "Wrote $TARBALL"
ls -lh "$TARBALL"
# checksum
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$TARBALL" | tee "$OUT_DIR/${STEM}.tar.gz.sha256"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$TARBALL" | tee "$OUT_DIR/${STEM}.tar.gz.sha256"
fi
