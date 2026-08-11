#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/scripts/install/freeq-install-linux.sh"
START="$ROOT/scripts/setup/freeq-start-linux.sh"
STOP="$ROOT/scripts/setup/freeq-stop-linux.sh"
FIXTURES="$ROOT/scripts/fixtures/linux-os-release"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/freeq-linux-install.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$file"; then
    echo "FAIL: $file does not contain: $needle" >&2
    exit 1
  fi
}

echo "== linux install: shell syntax =="
bash -n "$INSTALLER" "$START" "$STOP" \
  "$ROOT/scripts/install/freeq-platform.sh" \
  "$ROOT/scripts/install/freeq-fetch-release.sh"

echo "== linux install: dry-run =="
bash "$INSTALLER" --dry-run >"$TMP_DIR/dry.out"
assert_contains "$TMP_DIR/dry.out" "FreeQ Linux installer"
assert_contains "$TMP_DIR/dry.out" "Dry run only"
assert_contains "$TMP_DIR/dry.out" "portable"
assert_contains "$TMP_DIR/dry.out" "high-throughput"
assert_contains "$TMP_DIR/dry.out" "FREEQ_FROM_SOURCE=1"

echo "== linux install: help mentions native option =="
bash "$INSTALLER" --help >"$TMP_DIR/help.out"
assert_contains "$TMP_DIR/help.out" "portable prebuilt"
assert_contains "$TMP_DIR/help.out" "--from-source"
assert_contains "$TMP_DIR/help.out" "native"
echo "== linux install: preflight fixtures =="
for fixture_id_family in "ubuntu:ubuntu:debian" "fedora:fedora:rhel" "alpine:alpine:alpine" "arch:arch:arch" "unknown:unknown:unknown"; do
  IFS=: read -r fixture expected_id expected_family <<<"$fixture_id_family"
  out="$TMP_DIR/${fixture}.out"
  FREEQ_LINUX_OS_RELEASE="$FIXTURES/${fixture}.os-release" \
    bash "$INSTALLER" --preflight >"$out"
  assert_contains "$out" "FreeQ Linux preflight"
  assert_contains "$out" "Distribution ID: $expected_id"
  assert_contains "$out" "Distribution family: $expected_family"
  assert_contains "$out" "Preflight result: PASS"
done

echo "== linux install: docs mention binary path =="
assert_contains "$ROOT/docs/simple-install.md" "freeq-install-linux.sh"
assert_contains "$ROOT/docs/binary-releases.md" "unknown-linux-gnu"

echo "== linux install: helper scripts present =="
test -x "$START"
test -x "$STOP"
test -x "$ROOT/scripts/setup/freeq-doctor-linux.sh"

echo "linux install flow checks passed"
