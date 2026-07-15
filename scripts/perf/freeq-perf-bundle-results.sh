#!/usr/bin/env bash
set -euo pipefail

PERF_DIR="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
RESULT_ROOT="${FREEQ_PERF_RESULT_ROOT:-perf-results}"
LABEL="${1:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$PERF_DIR/bundles"
mkdir -p "$OUT_DIR"
ARCHIVE="$OUT_DIR/freeq-perf-results-$LABEL.tar.gz"
TMP_DIR="$(mktemp -d -t freeq-perf-bundle.XXXXXX)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$TMP_DIR/$dest")"
    cp -R "$src" "$TMP_DIR/$dest"
  fi
}

mkdir -p "$TMP_DIR/freeq-perf-results"

{
  echo "schema_version=freeq.perf_bundle.v1"
  echo "label=$LABEL"
  echo "created_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "hostname=$(hostname)"
  echo "uname=$(uname -a)"
} > "$TMP_DIR/freeq-perf-results/bundle.env"

copy_if_exists "$PERF_DIR/install-summary.txt" "freeq-perf-results/install-summary.txt"
copy_if_exists "$PERF_DIR/node-exchange.json" "freeq-perf-results/node-exchange.json"
copy_if_exists "$PERF_DIR/node.env" "freeq-perf-results/node.env"
copy_if_exists "$PERF_DIR/freeq.toml" "freeq-perf-results/freeq.toml"
copy_if_exists "$PERF_DIR/freeqd.log" "freeq-perf-results/freeqd.log"
copy_if_exists "$PERF_DIR/freeqd.pid" "freeq-perf-results/freeqd.pid"

if [ -d "$RESULT_ROOT" ]; then
  copy_if_exists "$RESULT_ROOT" "freeq-perf-results/perf-results"
fi

if command -v ifconfig >/dev/null 2>&1; then
  ifconfig > "$TMP_DIR/freeq-perf-results/ifconfig.txt" 2>&1 || true
fi
if command -v netstat >/dev/null 2>&1; then
  netstat -rn > "$TMP_DIR/freeq-perf-results/routes.txt" 2>&1 || true
fi

tar -czf "$ARCHIVE" -C "$TMP_DIR" freeq-perf-results

echo "Created result bundle:"
echo "  $ARCHIVE"
echo ""
echo "This bundle excludes identity.key private material."
