#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${FREEQ_PID_FILE:-$HOME/.freeq/perf/freeqd.pid}"
STATE_FILE="${FREEQ_NETWORK_STATE_FILE:-$HOME/.freeq/perf/freeq-network-state.env}"
LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
PEER_ENV="${FREEQ_PEER_ENV:-}"
WIFI_DEVICE="${FREEQ_WIFI_DEVICE:-en0}"
WIFI_SERVICE="${FREEQ_WIFI_SERVICE:-Wi-Fi}"
RENEW_DHCP=0
OVERLAY_IPS=()

usage() {
  cat <<'EOF'
Stop a macOS FreeQ tunnel and remove host routes left by setup.

Options:
  --pid-file PATH       freeqd pid file; default ~/.freeq/perf/freeqd.pid
  --state-file PATH     rollback ledger; default ~/.freeq/perf/freeq-network-state.env
  --local-env PATH      local node.env; default ~/.freeq/perf/node.env
  --peer-env PATH       peer env file whose overlay route should be removed
  --overlay-ip IP       additional overlay host route to remove; may repeat
  --renew-dhcp          ask macOS to renew DHCP on the Wi-Fi device after cleanup
  --wifi-device NAME    Wi-Fi device for --renew-dhcp; default en0
  --help, -h            show this help

Examples:
  scripts/setup/freeq-stop-macos.sh
  scripts/setup/freeq-stop-macos.sh --renew-dhcp
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --pid-file) PID_FILE="$2"; shift 2 ;;
    --state-file) STATE_FILE="$2"; shift 2 ;;
    --local-env) LOCAL_ENV="$2"; shift 2 ;;
    --peer-env) PEER_ENV="$2"; shift 2 ;;
    --overlay-ip) OVERLAY_IPS+=("$2"); shift 2 ;;
    --renew-dhcp) RENEW_DHCP=1; shift ;;
    --wifi-device) WIFI_DEVICE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper is for macOS." >&2
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
    }
    END {
      if (value != "") {
        print value
      }
    }
  ' "$file"
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

overlay_ip_from_env() {
  local file="$1"
  local address ip
  if [ ! -f "$file" ]; then
    return 0
  fi
  address="$(env_value "$file" FREEQ_NODE_ADDRESS)"
  ip="${address%%/*}"
  if [ -n "$ip" ] && validate_ip_addr "$ip"; then
    printf '%s\n' "$ip"
  fi
}

state_value() {
  local key="$1"
  if [ -f "$STATE_FILE" ]; then
    env_value "$STATE_FILE" "$key"
  fi
}

apply_state_defaults() {
  local value
  value="$(state_value FREEQ_PID_FILE)"
  if [ -n "$value" ]; then
    PID_FILE="$value"
  fi
  value="$(state_value FREEQ_WIFI_DEVICE)"
  if [ -n "$value" ]; then
    WIFI_DEVICE="$value"
  fi
  value="$(state_value FREEQ_WIFI_SERVICE)"
  if [ -n "$value" ]; then
    WIFI_SERVICE="$value"
  fi
}

append_overlay_ip_from_env() {
  local file="$1"
  local ip
  ip="$(overlay_ip_from_env "$file")"
  if [ -n "$ip" ]; then
    OVERLAY_IPS+=("$ip")
  fi
}

run_sudo() {
  echo "Checking sudo access for: $*"
  sudo -k
  sudo -v
  sudo "$@"
  local status=$?
  sudo -k || true
  return "$status"
}

stop_freeqd() {
  local pid=""
  if [ ! -f "$PID_FILE" ]; then
    echo "No freeqd pid file found: $PID_FILE"
    return 0
  fi

  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! validate_pid_value "$pid"; then
    echo "Ignoring invalid freeqd pid file value: $PID_FILE" >&2
    rm -f "$PID_FILE"
    return 0
  fi

  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "freeqd pid $pid is not running."
    rm -f "$PID_FILE"
    return 0
  fi

  if ! pid_matches_freeqd "$pid"; then
    echo "Refusing to stop pid $pid from $PID_FILE because it is not freeqd." >&2
    exit 1
  fi

  echo "Stopping freeqd pid $pid..."
  run_sudo kill "$pid"
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  if kill -0 "$pid" >/dev/null 2>&1; then
    echo "freeqd pid $pid did not stop." >&2
    exit 1
  fi
  rm -f "$PID_FILE"
}

remove_overlay_routes() {
  local seen=" "
  local ip
  local local_ip peer_ip added_local added_peer

  if [ -f "$STATE_FILE" ]; then
    local_ip="$(state_value FREEQ_LOCAL_IP)"
    peer_ip="$(state_value FREEQ_PEER_IP)"
    added_local="$(state_value FREEQ_ADDED_LOCAL_ROUTE)"
    added_peer="$(state_value FREEQ_ADDED_PEER_ROUTE)"
    if [ "$added_local" = "1" ] && [ -n "$local_ip" ]; then
      OVERLAY_IPS+=("$local_ip")
    fi
    if [ "$added_peer" = "1" ] && [ -n "$peer_ip" ]; then
      OVERLAY_IPS+=("$peer_ip")
    fi
  else
    echo "No rollback ledger found: $STATE_FILE" >&2
    echo "Falling back to env-derived overlay route cleanup for older FreeQ runs." >&2
    append_overlay_ip_from_env "$LOCAL_ENV"
    if [ -n "$PEER_ENV" ]; then
      append_overlay_ip_from_env "$PEER_ENV"
    fi
  fi

  if [ "${#OVERLAY_IPS[@]}" -eq 0 ]; then
    echo "No overlay routes to remove."
    return 0
  fi

  for ip in "${OVERLAY_IPS[@]}"; do
    if ! validate_ip_addr "$ip"; then
      echo "Skipping invalid overlay IP: $ip" >&2
      continue
    fi
    case "$seen" in
      *" $ip "*) continue ;;
    esac
    seen="${seen}${ip} "
    if run_sudo route -n delete -host "$ip"; then
      echo "Removed overlay host route: $ip"
    else
      echo "Overlay host route was not present: $ip"
    fi
  done
}

renew_dhcp() {
  if [ "$RENEW_DHCP" -ne 1 ]; then
    return 0
  fi
  if [ -f "$STATE_FILE" ]; then
    local mode
    mode="$(state_value FREEQ_WIFI_CONFIG_MODE)"
    if [ "$mode" = "DHCP Configuration" ]; then
      echo "Restoring Wi-Fi service to DHCP mode: $WIFI_SERVICE"
      run_sudo networksetup -setdhcp "$WIFI_SERVICE" || echo "WARN: networksetup DHCP restore failed for $WIFI_SERVICE." >&2
    fi
  fi
  echo "Renewing DHCP on $WIFI_DEVICE..."
  if run_sudo ipconfig set "$WIFI_DEVICE" DHCP; then
    echo "DHCP renewed on $WIFI_DEVICE."
  else
    echo "WARN: DHCP renew failed on $WIFI_DEVICE." >&2
  fi
}

apply_state_defaults
stop_freeqd
remove_overlay_routes
renew_dhcp
if [ -f "$STATE_FILE" ]; then
  rm -f "$STATE_FILE"
fi

echo "FreeQ macOS tunnel cleanup complete."
