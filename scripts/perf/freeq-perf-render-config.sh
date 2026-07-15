#!/usr/bin/env bash
set -euo pipefail

LOCAL_ENV=""
PEER_ENV=""
PEER_ENDPOINT=""
OUTPUT_CONFIG="${FREEQ_CONFIG_OUT:-$HOME/.freeq/perf/freeq.toml}"

usage() {
  cat <<'EOF'
Render a two-node freeq.toml from local and peer perf node.env files.

Example:
  scripts/perf/freeq-perf-render-config.sh \
    --local-env ~/.freeq/perf/node.env \
    --peer-env ~/Downloads/patrick-node.env \
    --peer-endpoint 203.0.113.10:51820

Options:
  --local-env PATH       local node.env from freeq-perf-identity
  --peer-env PATH        peer node.env from the other tester
  --peer-endpoint HOST:PORT reachable UDP endpoint for the peer
  --output PATH          output freeq.toml path
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --local-env) LOCAL_ENV="$2"; shift 2 ;;
    --peer-env) PEER_ENV="$2"; shift 2 ;;
    --peer-endpoint) PEER_ENDPOINT="$2"; shift 2 ;;
    --output) OUTPUT_CONFIG="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -z "$LOCAL_ENV" ] || [ -z "$PEER_ENV" ] || [ -z "$PEER_ENDPOINT" ]; then
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

# shellcheck disable=SC1090
. "$LOCAL_ENV"
LOCAL_NODE_NAME="$FREEQ_NODE_NAME"
LOCAL_NODE_ADDRESS="$FREEQ_NODE_ADDRESS"
LOCAL_NODE_LISTEN="$FREEQ_NODE_LISTEN"
LOCAL_IDENTITY_KEY_PATH="$FREEQ_IDENTITY_KEY_PATH"

# shellcheck disable=SC1090
. "$PEER_ENV"
PEER_NODE_NAME="$FREEQ_NODE_NAME"
PEER_NODE_ADDRESS="$FREEQ_NODE_ADDRESS"
PEER_PUBLIC_KEY_B64="$FREEQ_PUBLIC_KEY_B64"
PEER_KEM_KEY_B64="$FREEQ_KEM_KEY_B64"
PEER_ALLOWED_IP="${PEER_NODE_ADDRESS%%/*}/32"

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
endpoint = "$PEER_ENDPOINT"
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
