#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
PEER_ENV="${FREEQ_PEER_ENV:-}"
API_URL="${FREEQ_API:-http://127.0.0.1:6789}"
PING_COUNT="${FREEQ_BIDI_PING_COUNT:-3}"
SSH_USER="${FREEQ_BIDI_SSH_USER:-}"
SSH_PORT="${FREEQ_BIDI_SSH_PORT:-22}"

usage() {
  cat <<'EOF'
Run a quick FreeQ bidirectional smoke test on macOS.

The local direction is tested by pinging the peer/gateway overlay address from
this Mac. The return direction is tested only when --ssh-user is supplied: the
script SSHes to the peer public endpoint and asks that peer to ping this Mac's
overlay address.

Usage:
  scripts/perf/freeq-bidirectional-smoke-macos.sh
  scripts/perf/freeq-bidirectional-smoke-macos.sh --ssh-user ubuntu

Options:
  --peer-env PATH     peer/gateway env file; otherwise auto-detect in ~/FreeQ/02-put-peer-file-here
  --ssh-user USER     SSH user on the peer/gateway for the return-path ping
  --ssh-port PORT     SSH port on the peer/gateway public endpoint, default 22
  --ping-count N      ping count for each direction, default 3
  --help, -h          show this help

Exit codes:
  0  local direction passed and return direction passed or was skipped
  1  local direction failed, return direction failed, or setup was incomplete
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --peer-env) PEER_ENV="$2"; shift 2 ;;
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --ping-count) PING_COUNT="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

cd "$REPO_ROOT"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "FAIL: this helper is for macOS." >&2
  exit 1
fi

if ! [[ "$PING_COUNT" =~ ^[0-9]+$ ]] || [ "$PING_COUNT" -lt 1 ]; then
  echo "FAIL: --ping-count must be a positive integer." >&2
  exit 1
fi

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

find_peer_env() {
  local candidates=()
  local path

  if [ -n "$PEER_ENV" ]; then
    if [ -f "$PEER_ENV" ]; then
      printf '%s\n' "$PEER_ENV"
      return 0
    fi
    echo "FAIL: peer env was specified but does not exist: $PEER_ENV" >&2
    exit 1
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
    echo "FAIL: found multiple peer/gateway env files:" >&2
    printf '  %s\n' "${candidates[@]}" >&2
    echo "Leave only the intended file in: $RECEIVE_DIR" >&2
    exit 1
  fi

  echo "FAIL: missing peer/gateway env file." >&2
  echo "Put it in: $RECEIVE_DIR" >&2
  exit 1
}

status_field() {
  local json="$1"
  local key="$2"
  printf '%s\n' "$json" | sed -n "s/.*\"$key\":[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -1
}

fetch_status() {
  curl -fsS --max-time 2 "$API_URL/v1/status"
}

run_ping() {
  local label="$1"
  local host="$2"
  if ping -c "$PING_COUNT" "$host"; then
    echo "PASS: $label ping to $host"
    return 0
  fi
  echo "FAIL: $label ping to $host" >&2
  return 1
}

PEER_ENV="$(find_peer_env)"
"$REPO_ROOT/scripts/setup/freeq-validate-peer-env.sh" "$PEER_ENV" >/dev/null

if [ ! -f "$LOCAL_ENV" ]; then
  echo "FAIL: missing local identity env: $LOCAL_ENV" >&2
  echo "Run: freeq setup" >&2
  exit 1
fi

LOCAL_NAME="$(env_value "$LOCAL_ENV" FREEQ_NODE_NAME)"
LOCAL_ADDRESS="$(env_value "$LOCAL_ENV" FREEQ_NODE_ADDRESS)"
LOCAL_OVERLAY="${LOCAL_ADDRESS%%/*}"
PEER_NAME="$(env_value "$PEER_ENV" FREEQ_NODE_NAME)"
PEER_ADDRESS="$(env_value "$PEER_ENV" FREEQ_NODE_ADDRESS)"
PEER_OVERLAY="${PEER_ADDRESS%%/*}"
PEER_PUBLIC_ENDPOINT="$(env_value "$PEER_ENV" FREEQ_PUBLIC_ENDPOINT)"
PEER_PUBLIC_HOST="${PEER_PUBLIC_ENDPOINT%:*}"

echo "FreeQ bidirectional smoke test"
echo "  Local node: ${LOCAL_NAME:-unknown} (${LOCAL_ADDRESS:-unknown})"
echo "  Peer node:  ${PEER_NAME:-unknown} (${PEER_ADDRESS:-unknown})"
echo "  Peer endpoint: ${PEER_PUBLIC_ENDPOINT:-unknown}"
echo "  Peer file: $PEER_ENV"
echo

if ! before_status="$(fetch_status 2>/dev/null)"; then
  echo "FAIL: local FreeQ API is not reachable at $API_URL/v1/status" >&2
  echo "Run: freeq gateway" >&2
  exit 1
fi

echo "Local daemon before test:"
echo "  peers: $(status_field "$before_status" peer_count)"
echo "  tunnels: $(status_field "$before_status" tunnel_count)"
echo "  packets: $(status_field "$before_status" packets_ingested)"
echo "  route misses: $(status_field "$before_status" route_misses)"
echo

LOCAL_TO_PEER=0
RETURN_PATH=0

if run_ping "local-to-peer" "$PEER_OVERLAY"; then
  LOCAL_TO_PEER=1
fi

echo
if [ -n "$SSH_USER" ]; then
  echo "Testing return path by SSHing to $SSH_USER@$PEER_PUBLIC_HOST:$SSH_PORT ..."
  if ssh \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o NumberOfPasswordPrompts=0 \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=8 \
    "$SSH_USER@$PEER_PUBLIC_HOST" \
    "ping -c '$PING_COUNT' '$LOCAL_OVERLAY'"; then
    echo "PASS: peer-to-local return ping to $LOCAL_OVERLAY"
    RETURN_PATH=1
  else
    echo "FAIL: peer-to-local return ping to $LOCAL_OVERLAY" >&2
  fi
else
  echo "SKIP: return path was not tested because --ssh-user was not supplied."
  echo "To test the return direction from the peer/gateway, run there:"
  echo "  ping -c $PING_COUNT $LOCAL_OVERLAY"
  RETURN_PATH=1
fi

echo
if after_status="$(fetch_status 2>/dev/null)"; then
  echo "Local daemon after test:"
  echo "  peers: $(status_field "$after_status" peer_count)"
  echo "  tunnels: $(status_field "$after_status" tunnel_count)"
  echo "  packets: $(status_field "$after_status" packets_ingested)"
  echo "  route misses: $(status_field "$after_status" route_misses)"
else
  echo "WARN: local FreeQ API did not respond after test." >&2
fi

echo
if [ "$LOCAL_TO_PEER" -eq 1 ] && [ "$RETURN_PATH" -eq 1 ]; then
  echo "FreeQ bidirectional smoke result: PASS"
  exit 0
fi

echo "FreeQ bidirectional smoke result: FAIL" >&2
exit 1
