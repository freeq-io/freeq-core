#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
SEND_DIR="$SETUP_DIR/01-send-this-file"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
EXPECTED_LOCAL_NODE="${FREEQ_NODE_NAME:-patrick-mac}"
EXPECTED_LOCAL_ADDRESS="${FREEQ_OVERLAY_ADDRESS:-10.66.0.1/24}"
EXPECTED_PEER="${FREEQ_EXPECTED_PEER:-david-florida-mac}"
PEER_ENV="${FREEQ_PEER_ENV:-}"

usage() {
  cat <<'EOF'
Start Patrick's FreeQ daemon for David's Mac to connect.

Run from Terminal:

  cd ~/freeq-core
  scripts/field/freeq-patrick-start-for-david-macos.sh

Before running, put David's peer file here:

  ~/FreeQ/02-put-peer-file-here/david-florida-mac-peer.env

Then send David Patrick's visible peer file from:

  ~/FreeQ/01-send-this-file/patrick-mac-peer.env

This script only asks for this Mac's local admin password when macOS needs sudo
for the utun interface. It never asks for David's password.

Options:
  --peer-env PATH        David peer file path; otherwise auto-detect
  --no-interface         start freeqd but skip ifconfig/route setup
  --help, -h             show this help
EOF
}

START_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --peer-env)
      PEER_ENV="$2"
      START_ARGS+=("--peer-env" "$2")
      shift 2
      ;;
    --no-interface)
      START_ARGS+=("--no-interface")
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

cd "$REPO_ROOT"

find_peer_env() {
  local expected="$RECEIVE_DIR/$EXPECTED_PEER-peer.env"
  local candidates=()
  local path

  if [ -n "$PEER_ENV" ]; then
    if [ -f "$PEER_ENV" ]; then
      printf '%s\n' "$PEER_ENV"
      return 0
    fi
    echo "Peer env was specified but does not exist: $PEER_ENV" >&2
    exit 1
  fi

  if [ -f "$expected" ]; then
    printf '%s\n' "$expected"
    return 0
  fi

  for path in "$RECEIVE_DIR"/*.env; do
    if [ -f "$path" ]; then
      candidates+=("$path")
    fi
  done

  if [ "${#candidates[@]}" -eq 1 ]; then
    printf '%s\n' "${candidates[0]}"
    return 0
  fi

  echo "Missing David's peer file." >&2
  echo "Put it here:" >&2
  echo "  $expected" >&2
  echo
  echo "Send David Patrick's peer file from:" >&2
  echo "  $SEND_DIR/$EXPECTED_LOCAL_NODE-peer.env" >&2
  echo "Then rerun this script after David sends his peer file back." >&2
  exit 1
}

echo "FreeQ field start: Patrick for David"
echo "Repo:       $REPO_ROOT"
echo "Setup dir:  $SETUP_DIR"
echo

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper is for macOS." >&2
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "No FreeQ setup profile found, so this script will run setup first."
  echo "Use Return to accept the Patrick defaults unless you need different values."
  echo
  FREEQ_NODE_NAME="$EXPECTED_LOCAL_NODE" \
  FREEQ_OVERLAY_ADDRESS="$EXPECTED_LOCAL_ADDRESS" \
    scripts/setup/freeq-setup-macos.sh
fi

PEER_ENV="$(find_peer_env)"
echo "Using David peer file:"
echo "  $PEER_ENV"
echo

scripts/setup/freeq-connect-macos.sh --peer-env "$PEER_ENV" "${START_ARGS[@]}"
