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
CONFIGURE_INTERFACE=1

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

usage() {
  cat <<'EOF'
Start freeqd for a macOS two-node perf test and configure the assigned utun.

Options:
  --config PATH          internal generated config path; normally omit
  --local-env PATH       internal local identity file; normally omit
  --peer-env PATH        peer.env from the other tester; auto-detected from ~/FreeQ if omitted
  --no-interface         start daemon but skip ifconfig/route helper

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
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

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
if [ ! -x "target/release/freeqd" ]; then
  echo "Missing target/release/freeqd. Run: cargo build --release -p freeqd" >&2
  exit 1
fi

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
  if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    echo "freeqd already appears to be running as pid $old_pid"
    echo "Stop it with: sudo kill $old_pid"
    exit 1
  fi
fi

: > "$LOG_FILE"
echo "Checking sudo access..."
sudo -v

echo "Starting freeqd..."
sudo target/release/freeqd --config "$CONFIG" --foreground > "$LOG_FILE" 2>&1 &
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
  # shellcheck disable=SC1090
  . "$LOCAL_ENV"
  local_ip="${FREEQ_NODE_ADDRESS%%/*}"

  # shellcheck disable=SC1090
  . "$PEER_ENV"
  peer_ip="${FREEQ_NODE_ADDRESS%%/*}"

  echo "Configuring $interface local=$local_ip peer=$peer_ip"
  sudo ifconfig "$interface" "$local_ip" "$peer_ip" up
  sudo route -n add -host "$peer_ip" -interface "$interface" >/dev/null 2>&1 || true
fi

echo ""
echo "FreeQ daemon is running."
echo "Status API:"
echo "  curl -s http://127.0.0.1:6789/v1/status"
echo "Stop:"
echo "  sudo kill $(cat "$PID_FILE")"
