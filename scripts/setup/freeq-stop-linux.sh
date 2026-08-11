#!/usr/bin/env bash
# Stop freeqd / freeq-gateway started by freeq-start-linux.sh (pidfile under ~/.freeq).
set -euo pipefail

_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$_src")" && pwd)"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
fi
# shellcheck source=freeq-paths.sh
source "$SCRIPT_DIR/freeq-paths.sh" 2>/dev/null || true

LOG_DIR="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
PID_FILE="${FREEQ_PID_FILE:-$LOG_DIR/freeqd.pid}"

usage() {
  cat <<'EOF'
Stop FreeQ Linux daemon (freeqd or freeq-gateway) using the install pidfile.

  scripts/setup/freeq-stop-linux.sh
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

stopped=0
if [ -f "$PID_FILE" ]; then
  pid="$(tr -d '[:space:]' <"$PID_FILE" || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "Stopping FreeQ pid $pid..."
    if kill "$pid" 2>/dev/null; then
      stopped=1
    elif command -v sudo >/dev/null 2>&1 && sudo kill "$pid" 2>/dev/null; then
      stopped=1
    else
      echo "Could not signal pid $pid" >&2
      exit 1
    fi
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
  fi
  rm -f "$PID_FILE"
fi

# Best-effort cleanup if pidfile missing
for name in freeqd freeq-gateway; do
  if pgrep -x "$name" >/dev/null 2>&1; then
    echo "Also stopping leftover $name processes..."
    pkill -x "$name" 2>/dev/null || sudo pkill -x "$name" 2>/dev/null || true
    stopped=1
  fi
done

if [ "$stopped" -eq 1 ]; then
  echo "FreeQ Linux stop result: PASS"
else
  echo "FreeQ Linux stop result: PASS (nothing running)"
fi
