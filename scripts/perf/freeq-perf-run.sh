#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST=""
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

SSH_USER="${FREEQ_PEER_SSH_USER:-${USER:-}}"
SSH_PORT="${FREEQ_SSH_PORT:-22}"
SSH_PORT="${FREEQ_PEER_SSH_PORT:-$SSH_PORT}"
MODE="direct"
OVERLAY_HOST=""
LABEL="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_ROOT="${FREEQ_PERF_RESULT_ROOT:-perf-results}"
IPERF_SECONDS="${FREEQ_IPERF_SECONDS:-20}"
SCP_MB="${FREEQ_SCP_MB:-32}"
PEER_ENV="${FREEQ_PEER_ENV:-}"

usage() {
  cat <<'EOF'
Run a FreeQ performance A/B test.

Modes:
  direct  Test the normal internet path to --target.
  freeq   Test the FreeQ overlay path to --overlay-host.
  both    Run direct and FreeQ overlay legs.

Examples:
  scripts/perf/freeq-perf-run.sh --mode freeq
  scripts/perf/freeq-perf-run.sh --mode direct

Options:
  --target HOST          direct public/private host or DNS name; defaults to peer endpoint host
  --ssh-user USER        SSH user for direct/overlay SSH checks; defaults to FREEQ_PEER_SSH_USER or current user
  --ssh-port PORT        SSH port for direct mode, default 22
  --overlay-host HOST    FreeQ overlay IP/host for freeq mode; defaults to peer.env overlay IP
  --mode MODE            direct, freeq, or both
  --label LABEL          result directory label
EOF
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
    exit 1
  fi

  echo "Found multiple possible peer env files in Downloads:" >&2
  printf '  %s\n' "${candidates[@]}" >&2
  echo "Move the intended file into: $RECEIVE_DIR" >&2
  echo "Or set FREEQ_PEER_ENV in: $CONFIG_FILE" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) TARGET_HOST="$2"; shift 2 ;;
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --overlay-host) OVERLAY_HOST="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -z "$PEER_ENV" ] && { [ "$MODE" != "direct" ] || [ -z "$TARGET_HOST" ]; }; then
  PEER_ENV="$(find_peer_env)"
fi
if [ -f "$PEER_ENV" ]; then
  unset FREEQ_PUBLIC_ENDPOINT
  # shellcheck disable=SC1090
  . "$PEER_ENV"
  PEER_OVERLAY_HOST="${FREEQ_NODE_ADDRESS%%/*}"
  PEER_PUBLIC_ENDPOINT="${FREEQ_PUBLIC_ENDPOINT:-}"
  if [ -z "$OVERLAY_HOST" ]; then
    OVERLAY_HOST="$PEER_OVERLAY_HOST"
  fi
fi
if [ -z "$TARGET_HOST" ] && [ -n "${PEER_PUBLIC_ENDPOINT:-}" ]; then
  TARGET_HOST="${PEER_PUBLIC_ENDPOINT%:*}"
fi

if [ "$MODE" != "direct" ] && [ "$MODE" != "freeq" ] && [ "$MODE" != "both" ]; then
  echo "--mode must be direct, freeq, or both" >&2
  exit 1
fi
if [ "$MODE" != "freeq" ] && [ -z "$TARGET_HOST" ]; then
  echo "--target is required for direct/both mode unless the peer file includes FREEQ_PUBLIC_ENDPOINT" >&2
  exit 1
fi
if [ "$MODE" != "direct" ] && [ -z "$OVERLAY_HOST" ]; then
  echo "--overlay-host is required for freeq/both mode unless a peer.env file is available in $RECEIVE_DIR" >&2
  exit 1
fi

RESULT_DIR="$RESULT_ROOT/$LABEL"
mkdir -p "$RESULT_DIR"

log() {
  printf '%s\n' "$*" | tee -a "$RESULT_DIR/run.log"
}

run_capture() {
  local name="$1"
  shift
  log ""
  log "== $name =="
  log "$*"
  set +e
  "$@" > "$RESULT_DIR/$name.out" 2> "$RESULT_DIR/$name.err"
  local rc=$?
  set -e
  log "exit_code=$rc"
  return 0
}

time_ssh() {
  local name="$1"
  local host="$2"
  local port="$3"
  local ssh_target="${SSH_USER}@${host}"
  run_capture "$name" python3 -c '
import subprocess, sys, time, statistics
target, port = sys.argv[1], sys.argv[2]
ssh_opts = [
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=8",
]
samples = []
for i in range(5):
    start = time.perf_counter()
    rc = subprocess.call(["ssh", "-p", port, *ssh_opts, target, "true"])
    elapsed = (time.perf_counter() - start) * 1000
    samples.append(elapsed)
    print(f"sample={i+1} rc={rc} ms={elapsed:.1f}")
print(f"avg_ms={statistics.mean(samples):.1f}")
print(f"p95ish_ms={sorted(samples)[-1]:.1f}")
' "$ssh_target" "$port"
}

scp_test() {
  local name="$1"
  local host="$2"
  local port="$3"
  local ssh_target="${SSH_USER}@${host}"
  local payload="$RESULT_DIR/${name}-payload.bin"
  dd if=/dev/zero of="$payload" bs=1048576 count="$SCP_MB" >/dev/null 2>&1
  run_capture "$name" python3 -c '
import subprocess, sys, time
payload, target, port = sys.argv[1], sys.argv[2], sys.argv[3]
ssh_opts = [
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=8",
]
remote = f"{target}:/tmp/freeq-perf-payload.bin"
start = time.perf_counter()
rc = subprocess.call(["scp", "-q", "-P", port, *ssh_opts, payload, remote])
elapsed = time.perf_counter() - start
mb = int(sys.argv[4])
print(f"rc={rc}")
print(f"seconds={elapsed:.3f}")
print(f"mbps={(mb * 8) / elapsed:.2f}")
subprocess.call(["ssh", "-p", port, *ssh_opts, target, "rm -f /tmp/freeq-perf-payload.bin"])
' "$payload" "$ssh_target" "$port" "$SCP_MB"
}

iperf_test() {
  local name="$1"
  local host="$2"
  if ! command -v iperf3 >/dev/null 2>&1; then
    log "Skipping $name: iperf3 not installed"
    return 0
  fi
  run_capture "$name" iperf3 -J -t "$IPERF_SECONDS" -c "$host"
}

run_leg() {
  local prefix="$1"
  local host="$2"
  local ssh_port="$3"
  log ""
  log "##########################################################"
  log "Running $prefix leg against $host"
  log "##########################################################"
  run_capture "${prefix}-ping" ping -c 10 "$host"
  time_ssh "${prefix}-ssh-latency" "$host" "$ssh_port"
  scp_test "${prefix}-scp-upload" "$host" "$ssh_port"
  iperf_test "${prefix}-iperf3-tcp" "$host"
}

{
  echo "schema_version=freeq.perf_run.v1"
  echo "label=$LABEL"
  echo "mode=$MODE"
  echo "target_host=$TARGET_HOST"
  echo "overlay_host=$OVERLAY_HOST"
  echo "ssh_user=$SSH_USER"
  echo "ssh_port=$SSH_PORT"
  echo "iperf_seconds=$IPERF_SECONDS"
  echo "scp_mb=$SCP_MB"
  echo "started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$RESULT_DIR/run.env"

if [ "$MODE" = "direct" ] || [ "$MODE" = "both" ]; then
  run_leg "direct" "$TARGET_HOST" "$SSH_PORT"
fi
if [ "$MODE" = "freeq" ] || [ "$MODE" = "both" ]; then
  run_leg "freeq" "$OVERLAY_HOST" "22"
fi

{
  echo "# FreeQ Perf Run"
  echo ""
  echo "- Label: $LABEL"
  echo "- Mode: $MODE"
  echo "- Direct target: ${TARGET_HOST:-n/a}"
  echo "- FreeQ overlay target: ${OVERLAY_HOST:-n/a}"
  echo "- SSH user: $SSH_USER"
  echo "- Direct SSH port: $SSH_PORT"
  echo "- Result dir: $RESULT_DIR"
  echo ""
  echo "Raw command output files are stored alongside this summary."
} > "$RESULT_DIR/summary.md"

log ""
log "Perf run complete: $RESULT_DIR"
