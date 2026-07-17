#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
SEND_DIR="$SETUP_DIR/01-send-this-file"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
PEER_ENV="${FREEQ_PEER_ENV:-}"

usage() {
  cat <<'EOF'
Render and start a local macOS FreeQ tunnel.

Run this from a normal Terminal shell so sudo can prompt for your local Mac
admin password:

  scripts/setup/freeq-connect-macos.sh

Options:
  --peer-env PATH        peer env file; otherwise auto-detect in ~/FreeQ/02-put-peer-file-here
  --no-interface         start freeqd but skip ifconfig/route setup
  --restart              stop an existing freeqd pid from this setup before starting
  --help, -h             show this help

This script does not need, ask for, or use the other person's SSH password.
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
    --restart)
      START_ARGS+=("--restart")
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

say_next_steps_for_missing_peer() {
  cat >&2 <<EOF
Missing the peer env file.

Ask the other node operator to send their peer file from:
  ~/FreeQ/01-send-this-file/<peer-node-name>-peer.env

Put it here on this Mac:
  $RECEIVE_DIR/<peer-node-name>-peer.env

Then rerun:
  cd $REPO_ROOT
  scripts/setup/freeq-connect-macos.sh
EOF
}

env_value() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    index($0, key "=") == 1 {
      value = substr($0, length(key) + 2)
      if (value ~ /^'\''.*'\''$/) {
        value = substr(value, 2, length(value) - 2)
      }
      print value
      exit
    }
  ' "$file"
}

select_remote_peer_env() {
  local candidates=("$@")
  local remote_candidates=()
  local local_name=""
  local local_address=""
  local path peer_name peer_address

  if [ -f "$LOCAL_ENV" ]; then
    local_name="$(env_value "$LOCAL_ENV" FREEQ_NODE_NAME)"
    local_address="$(env_value "$LOCAL_ENV" FREEQ_NODE_ADDRESS)"
  fi

  for path in "${candidates[@]}"; do
    peer_name="$(env_value "$path" FREEQ_NODE_NAME)"
    peer_address="$(env_value "$path" FREEQ_NODE_ADDRESS)"
    if { [ -n "$local_name" ] && [ "$peer_name" = "$local_name" ]; } || \
       { [ -n "$local_address" ] && [ "$peer_address" = "$local_address" ]; }; then
      echo "Ignoring local node peer file in receive folder: $path" >&2
      continue
    fi
    remote_candidates+=("$path")
  done

  if [ "${#remote_candidates[@]}" -eq 1 ]; then
    printf '%s\n' "${remote_candidates[0]}"
    return 0
  fi
  if [ "${#remote_candidates[@]}" -gt 1 ]; then
    echo "Found multiple remote peer env files:" >&2
    printf '  %s\n' "${remote_candidates[@]}" >&2
    echo "Leave only the intended peer file in: $RECEIVE_DIR" >&2
    exit 1
  fi

  return 1
}

find_peer_env() {
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

  for path in "$RECEIVE_DIR"/*.env; do
    if [ -f "$path" ]; then
      candidates+=("$path")
    fi
  done

  if [ "${#candidates[@]}" -gt 0 ] && select_remote_peer_env "${candidates[@]}"; then
    return 0
  fi
  if [ "${#candidates[@]}" -gt 1 ]; then
    echo "Found multiple peer env files, but none describe a remote peer:" >&2
    printf '  %s\n' "${candidates[@]}" >&2
    echo "Leave only the intended peer file in: $RECEIVE_DIR" >&2
    exit 1
  fi

  say_next_steps_for_missing_peer
  exit 1
}

echo "FreeQ macOS tunnel connect"
echo "Repo:       $REPO_ROOT"
echo "Setup dir:  $SETUP_DIR"
echo "Config:     $CONFIG"
echo

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper is for macOS." >&2
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Missing setup profile: $CONFIG_FILE" >&2
  echo "Run the setup script first:" >&2
  echo "  scripts/setup/freeq-setup-macos.sh" >&2
  exit 1
fi

if [ ! -f "$LOCAL_ENV" ]; then
  echo "Missing local identity env: $LOCAL_ENV" >&2
  echo "Run the setup script first:" >&2
  echo "  scripts/setup/freeq-setup-macos.sh" >&2
  exit 1
fi

if [ ! -x "target/release/freeqd" ]; then
  echo "Missing target/release/freeqd." >&2
  echo "Build it first:" >&2
  echo "  cargo build --release -p freeqd" >&2
  exit 1
fi

PEER_ENV="$(find_peer_env)"
echo "Using peer env:"
echo "  $PEER_ENV"
echo

echo "Validating peer env..."
"$SCRIPT_DIR/freeq-validate-peer-env.sh" "$PEER_ENV"
echo

echo "Rendering FreeQ config..."
"$SCRIPT_DIR/freeq-render-config.sh" --peer-env "$PEER_ENV" --output "$CONFIG"
echo

if grep -Eq 'REPLACE|PLACEHOLDER|HOST_OR_IP|ACTUAL_|YOUR_HOST|PEER_HOST|peer-host|<|>' "$CONFIG"; then
  echo "Rendered config still contains a placeholder endpoint:" >&2
  grep -En 'endpoint *=|REPLACE|HOST_OR_IP|ACTUAL_|YOUR_HOST|PEER_HOST|peer-host|<|>' "$CONFIG" >&2 || true
  exit 1
fi

echo "Starting FreeQ daemon."
echo "sudo will ask for this Mac's local admin password if needed."
echo
"$SCRIPT_DIR/freeq-start-macos.sh" --peer-env "$PEER_ENV" "${START_ARGS[@]}"

cat <<EOF

FreeQ connect script finished.

Status:
  curl -s http://127.0.0.1:6789/v1/status

Send this node's peer file to the other node operator if needed:
  $SEND_DIR/<local-node-name>-peer.env

Stop:
  sudo kill "\$(cat ~/.freeq/perf/freeqd.pid)"
EOF
