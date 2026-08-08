#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
EXPECTED_LOCAL_NODE="${FREEQ_NODE_NAME:-david-florida-mac}"
EXPECTED_LOCAL_ADDRESS="${FREEQ_OVERLAY_ADDRESS:-10.66.0.2/24}"
EXPECTED_PEER="${FREEQ_EXPECTED_PEER:-patrick-mac}"
PEER_ENV="${FREEQ_PEER_ENV:-}"
CHECK_ONLY=0

usage() {
  cat <<'EOF'
Connect David's Mac to Patrick's FreeQ node.

Run from Terminal:

  cd ~/freeq-core
  scripts/field/freeq-david-connect-to-patrick-macos.sh

Before running, put Patrick's peer file here:

  ~/FreeQ/02-put-peer-file-here/<patrick-node-name>-peer.env

This script only asks for this Mac's local admin password when macOS needs sudo
for the utun interface. It never needs Patrick's SSH password.

Options:
  --peer-env PATH        Patrick peer file path; otherwise auto-detect
  --check-peer-file      only detect and validate Patrick's peer file
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
    --check-peer-file)
      CHECK_ONLY=1
      shift
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
  if [ "${#candidates[@]}" -gt 1 ]; then
    echo "Found multiple peer env files in Patrick's drop folder:" >&2
    printf '  %s\n' "${candidates[@]}" >&2
    echo "Leave only Patrick's intended peer.env in: $RECEIVE_DIR" >&2
    exit 1
  fi

  return 1
}

peer_env_node_name() {
  sed -n "s/^FREEQ_NODE_NAME='\([^']*\)'$/\1/p" "$1" | head -1
}

echo "FreeQ field connect: David -> Patrick"
echo "Repo:       $REPO_ROOT"
echo "Setup dir:  $SETUP_DIR"
echo

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper is for macOS." >&2
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "No FreeQ setup profile found, so this script will run setup first."
  echo "Use Return to accept the David defaults unless you need different values."
  echo
  FREEQ_NODE_NAME="$EXPECTED_LOCAL_NODE" \
  FREEQ_OVERLAY_ADDRESS="$EXPECTED_LOCAL_ADDRESS" \
    scripts/setup/freeq-setup-macos.sh
fi

if PEER_ENV="$(find_peer_env)"; then
  peer_node="$(peer_env_node_name "$PEER_ENV")"
  echo "Using Patrick peer file:"
  echo "  $PEER_ENV"
  if [ -n "$peer_node" ]; then
    echo "  node: $peer_node"
  fi
  echo
  scripts/setup/freeq-validate-peer-env.sh "$PEER_ENV"
  echo
  if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "Peer file check passed. Rerun without --check-peer-file to start FreeQ."
    exit 0
  fi
  scripts/setup/freeq-connect-macos.sh --restart --peer-env "$PEER_ENV" "${START_ARGS[@]}"
  exit 0
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "Patrick's peer file was not found in:"
  echo "  $RECEIVE_DIR"
  echo
  echo "Any single *.env file in that folder will be accepted; it does not have to"
  echo "be named $EXPECTED_PEER-peer.env."
  exit 1
fi

echo "Patrick's peer file is not here yet."
echo "Starting David in listen-only mode now, so this node is up while you wait."
echo
echo "Send Patrick David's peer file from:"
echo "  $SETUP_DIR/01-send-this-file/$EXPECTED_LOCAL_NODE-peer.env"
echo
echo "When Patrick sends his peer file back, put it here:"
echo "  $RECEIVE_DIR/<patrick-node-name>-peer.env"
echo "Any single *.env file in that folder will be accepted."
echo "Then rerun this script to render the full two-node tunnel config."
echo

scripts/setup/freeq-render-config.sh --listen-only
scripts/setup/freeq-start-macos.sh --no-interface
