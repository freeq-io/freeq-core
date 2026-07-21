#!/usr/bin/env bash
set -euo pipefail

CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
PEER_ENV="${FREEQ_PEER_ENV:-}"
LOG_DIR="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
LOG_FILE="$LOG_DIR/freeqd.log"
PID_FILE="$LOG_DIR/freeqd.pid"
TUN_MTU="${FREEQ_TUN_MTU:-1200}"
CONFIGURE_INTERFACE=1
RESTART=0
SETUP_URL="${FREEQ_SETUP_URL:-http://127.0.0.1:6789/}"
STATUS_URL="${SETUP_URL%/}/v1/status"

usage() {
  cat <<'EOF'
Start freeqd for a macOS two-node perf test and configure the assigned utun.

Options:
  --config PATH          internal generated config path; normally omit
  --local-env PATH       internal local identity file; normally omit
  --peer-env PATH        peer.env from the other tester; auto-detected from ~/FreeQ if omitted
  --no-interface         start daemon but skip ifconfig/route helper
  --restart              stop an existing freeqd pid from this setup before starting

Examples:
  scripts/setup/freeq-start-macos.sh
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --local-env) LOCAL_ENV="$2"; shift 2 ;;
    --peer-env) PEER_ENV="$2"; shift 2 ;;
    --no-interface) CONFIGURE_INTERFACE=0; shift ;;
    --restart) RESTART=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

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

required_env_value() {
  local file="$1"
  local key="$2"
  local value
  value="$(env_value "$file" "$key")"
  if [ -z "$value" ]; then
    echo "$key is missing or blank in: $file" >&2
    exit 1
  fi
  printf '%s\n' "$value"
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
    echo "Found multiple remote peer env files in the visible drop folder:" >&2
    printf '  %s\n' "${remote_candidates[@]}" >&2
    echo "Leave only the intended peer.env in: $RECEIVE_DIR" >&2
    exit 1
  fi

  return 1
}

freeqd_needs_build() {
  if [ ! -x "target/release/freeqd" ]; then
    return 0
  fi
  [ -n "$(find Cargo.toml Cargo.lock daemon crates -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) -newer target/release/freeqd -print -quit 2>/dev/null)" ]
}

ensure_freeqd_built() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Missing cargo. Run the installer first:" >&2
    echo "  scripts/install/freeq-install-macos.sh" >&2
    exit 1
  fi
  if freeqd_needs_build; then
    echo "Building updated freeqd release binary..."
    cargo build --release -p freeqd
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
  if [ "${#candidates[@]}" -gt 0 ] && select_remote_peer_env "${candidates[@]}"; then
    return 0
  fi
  if [ "${#candidates[@]}" -gt 1 ]; then
    echo "Found multiple peer env files in the visible drop folder, but none describe a remote peer:" >&2
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

validate_socket_addr() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress
import sys

value = sys.argv[1]
if value.startswith("["):
    host, sep, port = value[1:].partition("]:")
else:
    host, sep, port = value.rpartition(":")
if not host or not sep or not port.isdigit():
    raise SystemExit(1)
ipaddress.ip_address(host)
port_int = int(port)
if not (1 <= port_int <= 65535):
    raise SystemExit(1)
PY
}

validate_ip_addr() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress
import sys

try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
PY
}

validate_mtu() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 576 ] && [ "$1" -le 1500 ]
}

config_listen_addr() {
  awk -F'"' '
    /^\[node\]/ { in_node = 1; next }
    /^\[/ { in_node = 0 }
    in_node && /^[[:space:]]*listen[[:space:]]*=/ { print $2; exit }
  ' "$CONFIG"
}

validate_pid_value() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]
}

pid_matches_freeqd() {
  local pid="$1"
  local command
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [ -n "$command" ] && [[ "$command" =~ (^|[[:space:]/])freeqd([[:space:]]|$) ]]
}

mkdir -p "$LOG_DIR"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper is for macOS." >&2
  exit 1
fi
if [ ! -f "$CONFIG" ]; then
  echo "Missing config: $CONFIG" >&2
  exit 1
fi
if grep -Eq 'REPLACE|PLACEHOLDER|HOST_OR_IP|ACTUAL_|YOUR_HOST|PEER_HOST|peer-host|<|>' "$CONFIG"; then
  echo "Config still contains a placeholder endpoint:" >&2
  grep -En 'endpoint *=|REPLACE|HOST_OR_IP|ACTUAL_|YOUR_HOST|PEER_HOST|peer-host|<|>' "$CONFIG" >&2 || true
  echo "Rerun scripts/setup/freeq-render-config.sh with a real peer endpoint before starting." >&2
  exit 1
fi
LISTEN_VALUE="$(config_listen_addr)"
if [ -z "$LISTEN_VALUE" ] || ! validate_socket_addr "$LISTEN_VALUE"; then
  echo "Config contains an invalid node.listen value: ${LISTEN_VALUE:-missing}" >&2
  echo "Rerun setup so FreeQ can use the safe default: 0.0.0.0:51820" >&2
  exit 1
fi
if ! validate_mtu "$TUN_MTU"; then
  echo "Invalid FREEQ_TUN_MTU '$TUN_MTU'; expected an integer from 576 through 1500." >&2
  exit 1
fi
ensure_freeqd_built

if [ "$CONFIGURE_INTERFACE" -eq 1 ]; then
  if [ -z "$PEER_ENV" ]; then
    PEER_ENV="$(find_peer_env)"
    echo "Using peer env: $PEER_ENV"
  fi
  if [ ! -f "$LOCAL_ENV" ]; then
    echo "Missing local env: $LOCAL_ENV" >&2
    exit 1
  fi
  if [ ! -f "$PEER_ENV" ]; then
    echo "Missing peer env: $PEER_ENV" >&2
    exit 1
  fi
  scripts/setup/freeq-validate-peer-env.sh "$PEER_ENV" >/dev/null
fi

if [ -f "$PID_FILE" ]; then
  old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$old_pid" ] && ! validate_pid_value "$old_pid"; then
    echo "Ignoring invalid freeqd pid file value: $PID_FILE" >&2
    old_pid=""
  fi
  if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    if ! pid_matches_freeqd "$old_pid"; then
      echo "Refusing to manage pid $old_pid from $PID_FILE because it is not freeqd." >&2
      echo "Remove the stale pid file after verifying the process owner: $PID_FILE" >&2
      exit 1
    fi
    if [ "$RESTART" -eq 1 ]; then
      echo "Checking sudo access..."
      sudo -v
      echo "Stopping existing freeqd pid $old_pid..."
      sudo kill "$old_pid"
      for _ in $(seq 1 20); do
        if ! kill -0 "$old_pid" >/dev/null 2>&1; then
          break
        fi
        sleep 0.25
      done
      if kill -0 "$old_pid" >/dev/null 2>&1; then
        echo "Existing freeqd pid $old_pid did not stop." >&2
        echo "Stop it manually with: sudo kill $old_pid" >&2
        exit 1
      fi
      rm -f "$PID_FILE"
    else
      echo "freeqd already appears to be running as pid $old_pid"
      echo "Stop it with: sudo kill $old_pid"
      exit 1
    fi
  fi
fi

: > "$LOG_FILE"
echo "Checking sudo access..."
sudo -v

echo "Starting freeqd..."
nohup sudo target/release/freeqd --config "$CONFIG" --foreground > "$LOG_FILE" 2>&1 &
pid="$!"
echo "$pid" > "$PID_FILE"
echo "freeqd pid: $pid"
echo "log: $LOG_FILE"

interface=""
for _ in $(seq 1 30); do
  interface="$(python3 - "$LOG_FILE" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
for line in path.read_text(errors="replace").splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    fields = event.get("fields", {})
    if fields.get("message") == "host TUN interface opened" and fields.get("interface"):
        print(fields["interface"])
PY
)"
  if [ -n "$interface" ]; then
    break
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "freeqd exited early. Last log lines:"
    tail -40 "$LOG_FILE"
    exit 1
  fi
  sleep 1
done

if [ -z "$interface" ]; then
  echo "Could not detect utun interface from logs yet."
  echo "Inspect: $LOG_FILE"
  exit 1
fi

echo "Detected interface: $interface"

if [ "$CONFIGURE_INTERFACE" -eq 1 ]; then
  local_address="$(required_env_value "$LOCAL_ENV" FREEQ_NODE_ADDRESS)"
  local_ip="${local_address%%/*}"
  if ! validate_ip_addr "$local_ip"; then
    echo "Invalid local overlay address in $LOCAL_ENV: $local_address" >&2
    exit 1
  fi

  peer_address="$(required_env_value "$PEER_ENV" FREEQ_NODE_ADDRESS)"
  peer_ip="${peer_address%%/*}"
  if ! validate_ip_addr "$peer_ip"; then
    echo "Invalid peer overlay address in $PEER_ENV: $peer_address" >&2
    exit 1
  fi

  echo "Configuring $interface local=$local_ip peer=$peer_ip mtu=$TUN_MTU"
  sudo ifconfig "$interface" "$local_ip" "$peer_ip" up
  sudo ifconfig "$interface" mtu "$TUN_MTU"

  # macOS point-to-point utun interfaces may not route this node's own
  # overlay address locally. Pin it to loopback so local services such as SSH
  # can answer on the overlay IP while the peer host route stays on utun.
  if sudo route -n add -host "$local_ip" 127.0.0.1 >/dev/null 2>&1; then
    echo "Added local overlay route: $local_ip -> 127.0.0.1"
  elif sudo route -n change -host "$local_ip" 127.0.0.1 >/dev/null 2>&1; then
    echo "Updated local overlay route: $local_ip -> 127.0.0.1"
  else
    echo "WARN: could not pin local overlay route for $local_ip to 127.0.0.1" >&2
  fi

  if sudo route -n add -host "$peer_ip" -interface "$interface" >/dev/null 2>&1; then
    echo "Added peer overlay route: $peer_ip -> $interface"
  elif sudo route -n change -host "$peer_ip" -interface "$interface" >/dev/null 2>&1; then
    echo "Updated peer overlay route: $peer_ip -> $interface"
  else
    echo "WARN: could not pin peer overlay route for $peer_ip to $interface" >&2
  fi
fi

api_ready=0
for _ in $(seq 1 15); do
  if curl -fsS "$STATUS_URL" >/dev/null 2>&1; then
    api_ready=1
    break
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "freeqd exited after interface setup. Last log lines:"
    tail -60 "$LOG_FILE"
    exit 1
  fi
  sleep 1
done

if [ "$api_ready" -ne 1 ]; then
  echo "freeqd did not keep the local setup API online at $STATUS_URL." >&2
  echo "Last log lines:" >&2
  tail -60 "$LOG_FILE" >&2
  exit 1
fi

echo ""
echo "FreeQ daemon is running."
echo "Setup page:"
echo "  $SETUP_URL"
echo "Status API:"
echo "  curl -s http://127.0.0.1:6789/v1/status"
echo "Stop:"
echo "  sudo kill $(cat "$PID_FILE")"
open "$SETUP_URL" >/dev/null 2>&1 || true
