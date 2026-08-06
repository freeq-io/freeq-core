#!/usr/bin/env bash
# Easy leaf path: connect freeqd as gateway_client to AWS freeq-gateway.
# Replaces July-style manual FREEQ_EXTRA_ALLOWED_IPS / relay-key paste.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
CONFIG_OUT="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq-gateway-client.toml}"
GATEWAY_PEER_ENV="${FREEQ_GATEWAY_PEER_ENV:-$HOME/.freeq/perf/aws-gateway-peer.env}"
GATEWAY_PEER_ENV_WAS_DEFAULT=1
RELAY_KEY_FILE="${FREEQ_RELAY_KEY_FILE:-$HOME/.freeq/perf/relay-key.env}"
REMOTE_OVERLAYS=""
CHECK_ONLY=0

usage() {
  cat <<'EOF'
Connect this Mac as a FreeQ leaf (gateway_client) to a public freeq-gateway.

Usage:
  scripts/field/freeq-leaf-connect-gateway-macos.sh \
    --remote-overlay 10.66.0.2/32[,10.66.0.3/32...]

Prerequisites:
  - Local FreeQ setup already run (node.env + identity exist)
  - Gateway peer.env from the field bootstrap (public only). If the default
    runtime copy is missing, this script auto-imports aws-gateway-peer.env from
    the current directory or ~/Downloads.
  - Your public /32 allowed on the gateway security group
  - For leaf-to-leaf relay traffic, both endpoint Macs need the same
    FREEQ_E2E_RELAY_KEY_B64 key. This helper caches that key locally.

Options:
  --gateway-peer-env PATH   gateway public peer.env; default ~/.freeq/perf/aws-gateway-peer.env
  --remote-overlay CIDRS    remote leaf overlay /32s routed via gateway
  --local-env PATH          default ~/.freeq/perf/node.env
  --output PATH             freeq.toml output path
  --relay-key-file PATH     default ~/.freeq/perf/relay-key.env
  --check-only              validate + render only (do not start freeqd)
  --help, -h

Success is not "daemon running". After start, confirm:
  - local API / freeq doctor shows gateway peer session
  - ping remote overlay IP works both ways
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --gateway-peer-env) GATEWAY_PEER_ENV="$2"; GATEWAY_PEER_ENV_WAS_DEFAULT=0; shift 2 ;;
    --remote-overlay) REMOTE_OVERLAYS="$2"; shift 2 ;;
    --local-env) LOCAL_ENV="$2"; shift 2 ;;
    --output) CONFIG_OUT="$2"; shift 2 ;;
    --relay-key-file) RELAY_KEY_FILE="$2"; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$REMOTE_OVERLAYS" ]; then
  usage >&2
  exit 1
fi
cd "$REPO_ROOT"

auto_import_gateway_peer_env() {
  local dest="$1"
  local candidates=()
  local path

  for path in \
    "$PWD/aws-gateway-peer.env" \
    "$PWD/gateway-peer.env" \
    "$HOME/Downloads/aws-gateway-peer.env" \
    "$HOME/Downloads/gateway-peer.env" \
    "$HOME/Downloads"/*aws-gateway-peer.env \
    "$HOME/Downloads"/*gateway-peer.env
  do
    [ -f "$path" ] || continue
    candidates+=("$path")
  done

  if [ "${#candidates[@]}" -eq 0 ]; then
    return 1
  fi

  for path in "${candidates[@]}"; do
    if "$SCRIPT_DIR/../setup/freeq-validate-peer-env.sh" "$path" >/dev/null 2>&1; then
      mkdir -p "$(dirname "$dest")"
      cp "$path" "$dest"
      chmod 0644 "$dest"
      echo "Imported gateway peer.env:"
      echo "  from: $path"
      echo "  to:   $dest"
      return 0
    fi
  done

  echo "Found gateway peer.env candidates, but none validated:" >&2
  printf '  %s\n' "${candidates[@]}" >&2
  return 1
}

if [ ! -f "$GATEWAY_PEER_ENV" ]; then
  if [ "$GATEWAY_PEER_ENV_WAS_DEFAULT" -eq 1 ] && auto_import_gateway_peer_env "$GATEWAY_PEER_ENV"; then
    :
  else
    echo "Missing gateway peer.env: $GATEWAY_PEER_ENV" >&2
    echo "Put aws-gateway-peer.env in the current directory or ~/Downloads, then rerun." >&2
    exit 1
  fi
fi
if [ ! -f "$LOCAL_ENV" ]; then
  echo "Missing local node.env: $LOCAL_ENV" >&2
  echo "Run scripts/setup/freeq-setup-macos.sh first." >&2
  exit 1
fi

"$SCRIPT_DIR/../setup/freeq-validate-peer-env.sh" "$GATEWAY_PEER_ENV"

env_value() {
  local file="$1" key="$2"
  awk -v key="$key" 'index($0, key "=")==1 {
    value=substr($0, length(key)+2)
    if (value ~ /^'\''.*'\''$/) value=substr(value,2,length(value)-2)
    print value; exit
  }' "$file"
}

required_env() {
  local v
  v="$(env_value "$1" "$2")"
  if [ -z "$v" ]; then
    echo "$2 missing in $1" >&2
    exit 1
  fi
  printf '%s\n' "$v"
}

toml_string() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

validate_relay_key() {
  python3 - "$1" <<'PY'
import base64
import sys

value = sys.argv[1].strip()
if not value:
    raise SystemExit("relay key is empty")
try:
    decoded = base64.b64decode(value, validate=True)
except Exception as exc:
    raise SystemExit(f"relay key is not valid base64: {exc}")
if len(decoded) != 32:
    raise SystemExit(f"relay key must decode to 32 bytes, got {len(decoded)}")
PY
}

persist_relay_key() {
  local key="$1"
  mkdir -p "$(dirname "$RELAY_KEY_FILE")"
  umask 077
  printf "FREEQ_E2E_RELAY_KEY_B64='%s'\n" "$key" > "$RELAY_KEY_FILE"
  chmod 600 "$RELAY_KEY_FILE"
}

restore_or_warn_relay_key() {
  local key=""
  if [ -n "${FREEQ_E2E_RELAY_KEY_B64:-}" ]; then
    validate_relay_key "$FREEQ_E2E_RELAY_KEY_B64"
    persist_relay_key "$FREEQ_E2E_RELAY_KEY_B64"
    echo "Persisted relay key to: $RELAY_KEY_FILE"
    return 0
  fi

  if [ -f "$RELAY_KEY_FILE" ]; then
    key="$(env_value "$RELAY_KEY_FILE" FREEQ_E2E_RELAY_KEY_B64)"
    if [ -n "$key" ]; then
      validate_relay_key "$key"
      export FREEQ_E2E_RELAY_KEY_B64="$key"
      echo "Restored relay key from: $RELAY_KEY_FILE"
      return 0
    fi
  fi

  echo "WARN: FREEQ_E2E_RELAY_KEY_B64 is not set and no persisted relay key was found." >&2
  echo "WARN: Leaf-to-leaf traffic through the gateway will fail until both endpoint Macs share the same relay key." >&2
  echo "WARN: Generate or reuse a 32-byte key, then rerun this helper:" >&2
  echo "WARN:   export FREEQ_E2E_RELAY_KEY_B64='<shared-base64-key>'" >&2
}

LOCAL_NAME="$(required_env "$LOCAL_ENV" FREEQ_NODE_NAME)"
LOCAL_ADDR="$(required_env "$LOCAL_ENV" FREEQ_NODE_ADDRESS)"
LOCAL_LISTEN="$(required_env "$LOCAL_ENV" FREEQ_NODE_LISTEN)"
LOCAL_KEY="$(required_env "$LOCAL_ENV" FREEQ_IDENTITY_KEY_PATH)"
[ -f "$LOCAL_KEY" ] || { echo "Missing identity key: $LOCAL_KEY" >&2; exit 1; }

GW_NAME="$(required_env "$GATEWAY_PEER_ENV" FREEQ_NODE_NAME)"
GW_ENDPOINT="$(required_env "$GATEWAY_PEER_ENV" FREEQ_PUBLIC_ENDPOINT)"
GW_PUB="$(required_env "$GATEWAY_PEER_ENV" FREEQ_PUBLIC_KEY_B64)"
GW_KEM="$(required_env "$GATEWAY_PEER_ENV" FREEQ_KEM_KEY_B64)"

restore_or_warn_relay_key

# Build allowed_ips list for gateway peer: remote overlays + gateway overlay host if present
GW_ADDR="$(env_value "$GATEWAY_PEER_ENV" FREEQ_NODE_ADDRESS)"
ALLOWED=()
IFS=',' read -r -a REMOTE_ARR <<< "$REMOTE_OVERLAYS"
for cidr in "${REMOTE_ARR[@]}"; do
  cidr="$(echo "$cidr" | tr -d ' ')"
  [ -n "$cidr" ] || continue
  ALLOWED+=("$cidr")
done
if [ -n "$GW_ADDR" ]; then
  host="${GW_ADDR%%/*}"
  ALLOWED+=("${host}/32")
fi

# Dedup
ALLOWED_UNIQUE="$(printf '%s\n' "${ALLOWED[@]}" | awk 'NF && !seen[$0]++')"
ALLOWED_TOML="$(python3 - <<PY
import json
cidrs = """$ALLOWED_UNIQUE""".strip().splitlines()
print(", ".join(json.dumps(c) for c in cidrs if c))
PY
)"

mkdir -p "$(dirname "$CONFIG_OUT")"
cat > "$CONFIG_OUT" <<EOF
# Generated by freeq-leaf-connect-gateway-macos.sh — gateway_client leaf config
# Gateway never dials this leaf. This node dials outbound only.

[node]
name = $(toml_string "$LOCAL_NAME")
listen = $(toml_string "$LOCAL_LISTEN")
address = $(toml_string "$LOCAL_ADDR")
key_path = $(toml_string "$LOCAL_KEY")
algorithm = "ml-kem-768"
sign = "ml-dsa-65"
api_enabled = true
api_addr = "127.0.0.1:6789"

[[peer]]
name = $(toml_string "$GW_NAME")
mode = "gateway_client"
endpoint = $(toml_string "$GW_ENDPOINT")
public_key = $(toml_string "$GW_PUB")
kem_key = $(toml_string "$GW_KEM")
allowed_ips = [${ALLOWED_TOML}]
key_rotation_secs = 3600
EOF

echo "Rendered gateway-client config: $CONFIG_OUT"
echo "  local=$LOCAL_NAME ($LOCAL_ADDR)"
echo "  gateway=$GW_NAME endpoint=$GW_ENDPOINT"
echo "  routes_via_gateway=$ALLOWED_TOML"

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "check-only: not starting freeqd"
  exit 0
fi

START="$SCRIPT_DIR/../setup/freeq-start-macos.sh"
if [ ! -x "$START" ]; then
  echo "Missing $START" >&2
  exit 1
fi

# Build freeqd if needed (freeq-start-macos also builds, but fail early).
if [ ! -x "$REPO_ROOT/target/release/freeqd" ]; then
  echo "Building freeqd..."
  (cd "$REPO_ROOT" && cargo build --release -p freeqd)
fi

# Extra overlay routes for the remote leaf/leaves (July fragility: manual EXTRA_ALLOWED_IPS).
# freeq-start uses gateway peer.env for primary peer route + these extras.
export FREEQ_EXTRA_ALLOWED_IPS
FREEQ_EXTRA_ALLOWED_IPS="$(printf '%s\n' "${REMOTE_ARR[@]}" | tr '\n' ',' | sed 's/,$//')"

echo "Starting freeqd via freeq-start-macos (gateway_client config, --restart)..."
echo "  config=$CONFIG_OUT"
echo "  gateway_peer_env=$GATEWAY_PEER_ENV"
echo "  extra_allowed_ips=$FREEQ_EXTRA_ALLOWED_IPS"

"$START" \
  --config "$CONFIG_OUT" \
  --local-env "$LOCAL_ENV" \
  --peer-env "$GATEWAY_PEER_ENV" \
  --restart

sleep 2
if curl -fsS --max-time 2 http://127.0.0.1:6789/ >/dev/null 2>&1 \
  || curl -fsS --max-time 2 http://127.0.0.1:6789/status >/dev/null 2>&1 \
  || curl -fsS --max-time 2 http://127.0.0.1:6789/v1/status >/dev/null 2>&1; then
  echo "local_api=reachable"
else
  echo "WARN: local API not reachable yet; check ~/.freeq/perf/freeqd.log" >&2
fi

echo
echo "Success criteria (not just process running):"
echo "  1) ping gateway overlay if assigned"
echo "  2) ping remote leaf overlay IPs: $ALLOWED_TOML"
echo "  3) scripts/perf/freeq-gateway-path-perf.sh --remote-overlay-ip <remote>"
echo
echo "leaf_gateway_client_start_ok=1"
