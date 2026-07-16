#!/usr/bin/env bash
set -euo pipefail

LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
PEER_ENV="${FREEQ_PEER_ENV:-}"
OUTPUT_CONFIG="${FREEQ_CONFIG_OUT:-$HOME/.freeq/perf/freeq.toml}"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

usage() {
  cat <<'EOF'
Render a two-node freeq.toml from local node.env and peer peer.env files.

Example:
  scripts/setup/freeq-render-config.sh

Options:
  --local-env PATH       internal local identity file; normally omit
  --peer-env PATH        peer.env from the other tester; auto-detected from ~/FreeQ if omitted
  --output PATH          output freeq.toml path
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --local-env) LOCAL_ENV="$2"; shift 2 ;;
    --peer-env) PEER_ENV="$2"; shift 2 ;;
    --output) OUTPUT_CONFIG="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

validate_endpoint() {
  local endpoint="$1"
  case "$endpoint" in
    *REPLACE*|*PLACEHOLDER*|*HOST_OR_IP*|*ACTUAL_*|*YOUR_HOST*|*PEER_HOST*|*peer-host*|*"<"*|*">"*)
      echo "Refusing placeholder peer endpoint: $endpoint" >&2
      echo "Use a real reachable host or IP, for example: <peer-host-or-ip>:51820" >&2
      exit 1
      ;;
  esac
  if [[ "$endpoint" != *:* ]]; then
    echo "FREEQ_PUBLIC_ENDPOINT must be HOST:PORT, got: $endpoint" >&2
    exit 1
  fi
  host="${endpoint%:*}"
  port="${endpoint##*:}"
  if [ -z "$host" ] || [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "FREEQ_PUBLIC_ENDPOINT must be HOST:PORT with port 1-65535, got: $endpoint" >&2
    exit 1
  fi
}

find_peer_env() {
  local candidates=()
  local path
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
    echo "Found multiple peer env files in the visible drop folder:" >&2
    printf '  %s\n' "${candidates[@]}" >&2
    echo "Leave only the intended peer.env in: $RECEIVE_DIR" >&2
    exit 1
  fi

  for path in "$HOME"/Downloads/*peer.env "$HOME"/Downloads/*-peer.env; do
    if [ -f "$path" ]; then
      candidates+=("$path")
    fi
  done
  if [ "${#candidates[@]}" -eq 1 ]; then
    printf '%s\n' "${candidates[0]}"
    return 0
  fi
  if [ "${#candidates[@]}" -eq 0 ]; then
    echo "Missing peer env file." >&2
    echo "Put the other tester's peer.env file in this visible folder:" >&2
    echo "  $RECEIVE_DIR" >&2
    echo "Then rerun this command." >&2
    exit 1
  fi

  echo "Found multiple possible peer env files in Downloads:" >&2
  printf '  %s\n' "${candidates[@]}" >&2
  echo "Move the intended file into: $RECEIVE_DIR" >&2
  echo "Or pass the intended one with --peer-env PATH." >&2
  exit 1
}

if [ -z "$PEER_ENV" ]; then
  PEER_ENV="$(find_peer_env)"
  echo "Using peer env: $PEER_ENV"
fi

if [ -z "$LOCAL_ENV" ]; then
  usage
  exit 1
fi

if [ ! -f "$LOCAL_ENV" ]; then
  echo "Missing local env file: $LOCAL_ENV" >&2
  exit 1
fi
if [ ! -f "$PEER_ENV" ]; then
  echo "Missing peer env file: $PEER_ENV" >&2
  exit 1
fi
scripts/setup/freeq-validate-peer-env.sh "$PEER_ENV" >/dev/null

# shellcheck disable=SC1090
. "$LOCAL_ENV"
LOCAL_NODE_NAME="$FREEQ_NODE_NAME"
LOCAL_NODE_ADDRESS="$FREEQ_NODE_ADDRESS"
LOCAL_NODE_LISTEN="$FREEQ_NODE_LISTEN"
LOCAL_IDENTITY_KEY_PATH="$FREEQ_IDENTITY_KEY_PATH"
if [ ! -f "$LOCAL_IDENTITY_KEY_PATH" ]; then
  echo "Missing local identity key: $LOCAL_IDENTITY_KEY_PATH" >&2
  echo "Did you accidentally pass a peer.env as --local-env?" >&2
  exit 1
fi

unset FREEQ_PUBLIC_ENDPOINT
# shellcheck disable=SC1090
. "$PEER_ENV"
PEER_NODE_NAME="$FREEQ_NODE_NAME"
PEER_NODE_ADDRESS="$FREEQ_NODE_ADDRESS"
PEER_PUBLIC_ENDPOINT="${FREEQ_PUBLIC_ENDPOINT:-}"
PEER_PUBLIC_KEY_B64="$FREEQ_PUBLIC_KEY_B64"
PEER_KEM_KEY_B64="$FREEQ_KEM_KEY_B64"
PEER_ALLOWED_IP="${PEER_NODE_ADDRESS%%/*}/32"

if [ -z "$PEER_PUBLIC_ENDPOINT" ]; then
  echo "Missing peer endpoint." >&2
  echo "The peer file does not include FREEQ_PUBLIC_ENDPOINT." >&2
  echo "Ask the other node operator to rerun setup with their reachable UDP endpoint, then resend their peer.env file." >&2
  exit 1
fi
echo "Using peer endpoint from peer env: $PEER_PUBLIC_ENDPOINT"
validate_endpoint "$PEER_PUBLIC_ENDPOINT"

if [ "$LOCAL_NODE_NAME" = "$PEER_NODE_NAME" ]; then
  echo "Local and peer env files both describe node '$LOCAL_NODE_NAME'." >&2
  echo "Use the installer-generated local identity for --local-env and the other tester's peer.env for --peer-env." >&2
  exit 1
fi
if [ "$LOCAL_NODE_ADDRESS" = "$PEER_NODE_ADDRESS" ]; then
  echo "Local and peer env files both use overlay address '$LOCAL_NODE_ADDRESS'." >&2
  echo "Each tester needs a unique overlay address in the test overlay network." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_CONFIG")"
cat > "$OUTPUT_CONFIG" <<EOF
[node]
name = "$LOCAL_NODE_NAME"
listen = "$LOCAL_NODE_LISTEN"
address = "$LOCAL_NODE_ADDRESS"
key_path = "$LOCAL_IDENTITY_KEY_PATH"
algorithm = "ml-kem-768"
sign = "ml-dsa-65"
api_enabled = true
api_addr = "127.0.0.1:6789"

[[peer]]
name = "$PEER_NODE_NAME"
endpoint = "$PEER_PUBLIC_ENDPOINT"
public_key = "$PEER_PUBLIC_KEY_B64"
kem_key = "$PEER_KEM_KEY_B64"
allowed_ips = ["$PEER_ALLOWED_IP"]
key_rotation_secs = 3600
EOF

echo "Rendered FreeQ config:"
echo "  $OUTPUT_CONFIG"
echo
echo "Start freeqd with:"
echo "  sudo target/release/freeqd --config \"$OUTPUT_CONFIG\" --foreground"
