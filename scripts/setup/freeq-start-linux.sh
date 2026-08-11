#!/usr/bin/env bash
# Start freeqd (or freeq-gateway) on Linux using prebuilt binaries under ~/.freeq.
set -euo pipefail

_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$_src")" && pwd)"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
fi
# shellcheck source=freeq-paths.sh
source "$SCRIPT_DIR/freeq-paths.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOG_DIR="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
LOG_FILE="${FREEQ_LOG_FILE:-$LOG_DIR/freeqd.log}"
PID_FILE="${FREEQ_PID_FILE:-$LOG_DIR/freeqd.pid}"
ROLE="${FREEQ_ROLE:-node}" # node | gateway
RESTART=0
STATUS_URL="${FREEQ_SETUP_URL:-http://127.0.0.1:6789}/v1/status"
GATEWAY_STATUS_URL="${FREEQ_GATEWAY_STATUS_URL:-http://127.0.0.1:6790/healthz}"

usage() {
  cat <<'EOF'
Start FreeQ on Linux (prebuilt binary path).

Options:
  --config PATH          freeq.toml (default ~/.freeq/perf/freeq.toml)
  --role node|gateway    freeqd node (default) or freeq-gateway relay
  --restart              stop existing pid from pidfile first
  --help, -h

Environment:
  FREEQ_BIN_DIR     default ~/.freeq/bin
  FREEQ_ROLE        node|gateway
  FREEQ_USE_SUDO    auto|1|0  (default auto)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --restart) RESTART=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1; }

resolve_bin() {
  local name="$1" c
  for c in \
    "${FREEQ_BIN_DIR:-$HOME/.freeq/bin}/$name" \
    "${FREEQ_INSTALL_DIR:-$HOME/.freeq/dist/current}/bin/$name" \
    "$REPO_ROOT/bin/$name" \
    "$REPO_ROOT/target/release/$name"; do
    if [ -x "$c" ]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  if need "$name"; then
    command -v "$name"
    return 0
  fi
  return 1
}

pid_matches() {
  local pid="$1" name="$2" command
  command="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  [ -n "$command" ] && [[ "$command" == *"$name"* ]]
}

ensure_tun() {
  if [ -e /dev/net/tun ]; then
    return 0
  fi
  if need modprobe; then
    echo "Loading tun kernel module..."
    if [ "$(id -u)" -eq 0 ]; then
      modprobe tun || true
    elif need sudo; then
      sudo modprobe tun || true
    fi
  fi
  if [ ! -e /dev/net/tun ]; then
    echo "WARNING: /dev/net/tun missing; freeqd may fail to create overlay." >&2
  fi
}

ensure_caps() {
  local bin="$1"
  if [ "$ROLE" = "gateway" ]; then
    return 0
  fi
  if ! need setcap || ! need getcap; then
    return 0
  fi
  if getcap "$bin" 2>/dev/null | grep -q 'cap_net_admin'; then
    return 0
  fi
  echo "Granting CAP_NET_ADMIN on $bin (one-time; may ask for sudo password)..."
  if [ "$(id -u)" -eq 0 ]; then
    setcap cap_net_admin,cap_net_bind_service=+ep "$bin" || true
  elif need sudo; then
    sudo setcap cap_net_admin,cap_net_bind_service=+ep "$bin" || true
  fi
}

needs_sudo_for_bin() {
  local bin="$1"
  local mode="${FREEQ_USE_SUDO:-auto}"
  case "$mode" in
    1|always|yes) return 0 ;;
    0|never|no) return 1 ;;
  esac
  if [ "$ROLE" = "gateway" ]; then
    return 1
  fi
  if [ "$(id -u)" -eq 0 ]; then
    return 1
  fi
  if getcap "$bin" 2>/dev/null | grep -q 'cap_net_admin'; then
    return 1
  fi
  return 0
}

mkdir -p "$LOG_DIR"
freeq_ensure_dirs 2>/dev/null || true

if [ ! -f "$CONFIG" ]; then
  echo "Missing config: $CONFIG" >&2
  echo "Run freeq-install-linux.sh first." >&2
  exit 1
fi

if [ "$ROLE" = "gateway" ]; then
  BIN_NAME="freeq-gateway"
  CHECK_URL="$GATEWAY_STATUS_URL"
else
  BIN_NAME="freeqd"
  CHECK_URL="$STATUS_URL"
  ensure_tun
fi

BIN="$(resolve_bin "$BIN_NAME" || true)"
if [ -z "$BIN" ]; then
  echo "Missing $BIN_NAME. Install with scripts/install/freeq-install-linux.sh" >&2
  exit 1
fi

ensure_caps "$BIN"

if [ "$RESTART" -eq 1 ] && [ -f "$PID_FILE" ]; then
  old_pid="$(tr -d '[:space:]' <"$PID_FILE" || true)"
  if [ -n "$old_pid" ] && pid_matches "$old_pid" "$BIN_NAME"; then
    echo "Stopping existing $BIN_NAME pid $old_pid..."
    kill "$old_pid" 2>/dev/null || sudo kill "$old_pid" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
fi

: >"$LOG_FILE"
echo "Starting $BIN_NAME..."
echo "  binary: $BIN"
echo "  config: $CONFIG"
echo "  log:    $LOG_FILE"

if [ "$ROLE" = "gateway" ]; then
  nohup "$BIN" --config "$CONFIG" --status-addr 127.0.0.1:6790 >"$LOG_FILE" 2>&1 &
  pid=$!
elif needs_sudo_for_bin "$BIN"; then
  echo "Starting freeqd with sudo (TUN privileges)..."
  nohup sudo "$BIN" --config "$CONFIG" --foreground >"$LOG_FILE" 2>&1 &
  pid=$!
else
  nohup "$BIN" --config "$CONFIG" --foreground >"$LOG_FILE" 2>&1 &
  pid=$!
fi

echo "$pid" >"$PID_FILE"
echo "$BIN_NAME pid: $pid"

ok=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 1 "$CHECK_URL" >/dev/null 2>&1; then
    ok=1
    break
  fi
  # process died?
  if ! kill -0 "$pid" 2>/dev/null; then
    break
  fi
  sleep 1
done

if [ "$ok" -ne 1 ]; then
  echo "$BIN_NAME did not answer $CHECK_URL yet. Last log lines:" >&2
  tail -40 "$LOG_FILE" 2>/dev/null || true
  exit 1
fi

echo ""
echo "FreeQ Linux start result: PASS"
echo "  Role:   $ROLE"
echo "  Status: $CHECK_URL"
if [ "$ROLE" = "node" ]; then
  echo "  API:    http://127.0.0.1:6789/"
fi
echo "Stop:"
echo "  scripts/setup/freeq-stop-linux.sh"
