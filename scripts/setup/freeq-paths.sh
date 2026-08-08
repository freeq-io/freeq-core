#!/usr/bin/env bash
# Canonical FreeQ Core local state paths (shared by install/pair/connect).
# Source this file; do not execute it directly.
#
# Prefer ~/.freeq/** over legacy ~/FreeQ/01-send / 02-put folders.
# Legacy paths remain readable for one release as a fallback only.

: "${HOME:?HOME must be set}"

FREEQ_HOME="${FREEQ_HOME:-$HOME/.freeq}"
FREEQ_NODE_DIR="${FREEQ_NODE_DIR:-$FREEQ_HOME/node}"
FREEQ_PEERS_DIR="${FREEQ_PEERS_DIR:-$FREEQ_HOME/peers}"
FREEQ_PEERS_RECEIVED="${FREEQ_PEERS_RECEIVED:-$FREEQ_PEERS_DIR/received}"
FREEQ_PAIR_DIR="${FREEQ_PAIR_DIR:-$FREEQ_HOME/pair}"
FREEQ_PERF_DIR="${FREEQ_PERF_DIR:-$FREEQ_HOME/perf}"
FREEQ_DIST_DIR="${FREEQ_DIST_DIR:-$FREEQ_HOME/dist}"
FREEQ_BIN_DIR="${FREEQ_BIN_DIR:-$FREEQ_HOME/bin}"
# Prebuilt release extract (symlink to active tag tree)
FREEQ_INSTALL_DIR="${FREEQ_INSTALL_DIR:-$FREEQ_DIST_DIR/current}"
FREEQ_CONFIG="${FREEQ_CONFIG:-$FREEQ_PERF_DIR/freeq.toml}"
FREEQ_LOCAL_ENV="${FREEQ_LOCAL_ENV:-$FREEQ_PERF_DIR/node.env}"
FREEQ_LOCAL_PEER_ENV="${FREEQ_LOCAL_PEER_ENV:-$FREEQ_PERF_DIR/peer.env}"
FREEQ_API="${FREEQ_API:-http://127.0.0.1:6789}"

# Legacy (compat only — do not require for new flows)
FREEQ_SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
FREEQ_LEGACY_SEND="${FREEQ_LEGACY_SEND:-$FREEQ_SETUP_DIR/01-send-this-file}"
FREEQ_LEGACY_RECEIVE="${FREEQ_LEGACY_RECEIVE:-$FREEQ_SETUP_DIR/02-put-peer-file-here}"

freeq_ensure_dirs() {
  mkdir -p \
    "$FREEQ_NODE_DIR" \
    "$FREEQ_PEERS_RECEIVED" \
    "$FREEQ_PAIR_DIR" \
    "$FREEQ_PERF_DIR" \
    "$FREEQ_DIST_DIR" \
    "$FREEQ_BIN_DIR" \
    "$FREEQ_LEGACY_SEND" \
    "$FREEQ_LEGACY_RECEIVE"
}

# Prefer prebuilt release binary, then package bin/, then cargo target/, then PATH.
freeq_resolve_bin() {
  local name="$1"
  local c
  for c in \
    "${FREEQ_BIN_DIR}/${name}" \
    "${FREEQ_INSTALL_DIR}/bin/${name}" \
    "${FREEQ_DIST_DIR}/current/bin/${name}" \
    "bin/${name}" \
    "target/release/${name}"; do
    if [ -n "$c" ] && [ -x "$c" ]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  return 1
}

# Find the newest peer.env under received (and legacy fallback).
freeq_find_peer_envs() {
  local found=()
  local p
  for p in "$FREEQ_PEERS_RECEIVED"/*-peer.env "$FREEQ_PEERS_RECEIVED"/*.env \
           "$FREEQ_LEGACY_RECEIVE"/*-peer.env "$FREEQ_LEGACY_RECEIVE"/*.env; do
    if [ -f "$p" ]; then
      found+=("$p")
    fi
  done
  if [ "${#found[@]}" -gt 0 ]; then
    printf '%s\n' "${found[@]}"
  fi
}
