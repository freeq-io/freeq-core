#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

SSH_USER="${FREEQ_PERF_SSH_USER:-${FREEQ_PEER_SSH_USER:-}}"
DIRECT_SSH_PORT="${FREEQ_PERF_DIRECT_SSH_PORT:-${FREEQ_PEER_SSH_PORT:-${FREEQ_SSH_PORT:-22}}}"
TARGET_HOST="${FREEQ_PERF_TARGET_HOST:-}"
OVERLAY_HOST="${FREEQ_PERF_OVERLAY_HOST:-}"
BLOB_MB="${FREEQ_PERF_BLOB_MB:-256}"
LABEL="${FREEQ_PERF_LABEL:-blob-ab-$(date -u +%Y%m%dT%H%M%SZ)}"
PEER_ENV="${FREEQ_PEER_ENV:-}"

usage() {
  cat <<'EOF'
Run a same-direction blob transfer A/B test:

  direct: normal SSH/SCP to the peer public endpoint
  freeq:  SSH/SCP to the peer overlay address through FreeQ

Run this on the node that can initiate both connections.

Example:
  scripts/perf/freeq-blob-ab-test-macos.sh \
    --ssh-user peeruser \
    --direct-ssh-port 65022 \
    --mb 512

Options:
  --ssh-user USER          SSH account on the peer machine
  --direct-ssh-port PORT   public/direct SSH port for the peer
  --target HOST            public/direct peer host; defaults to peer.env endpoint host
  --overlay-host HOST      FreeQ overlay peer host; defaults to peer.env overlay address
  --peer-env PATH          peer env file; otherwise uses the visible drop folder
  --mb SIZE                blob size in MiB, default 256
  --label LABEL            result label
  --help, -h               show this help

Notes:
  - This writes a temporary blob locally and uploads it to /tmp on the peer.
  - The peer must allow SSH for the selected direct port and overlay port 22.
  - Results are written under perf-results/<label>.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ssh-user)
      SSH_USER="$2"
      shift 2
      ;;
    --direct-ssh-port)
      DIRECT_SSH_PORT="$2"
      shift 2
      ;;
    --target)
      TARGET_HOST="$2"
      shift 2
      ;;
    --overlay-host)
      OVERLAY_HOST="$2"
      shift 2
      ;;
    --peer-env)
      PEER_ENV="$2"
      shift 2
      ;;
    --mb)
      BLOB_MB="$2"
      shift 2
      ;;
    --label)
      LABEL="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

cd "$REPO_ROOT"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper is for macOS." >&2
  exit 1
fi

if [ -z "$SSH_USER" ]; then
  echo "--ssh-user is required unless FREEQ_PERF_SSH_USER is set." >&2
  exit 1
fi

if ! [[ "$BLOB_MB" =~ ^[0-9]+$ ]] || [ "$BLOB_MB" -lt 1 ]; then
  echo "--mb must be a positive integer." >&2
  exit 1
fi

echo "FreeQ blob A/B test"
echo "Repo:       $REPO_ROOT"
echo "Setup dir:  $SETUP_DIR"
echo "Blob size:  ${BLOB_MB} MiB"
echo "SSH user:   $SSH_USER"
echo

if ! curl -fsS http://127.0.0.1:6789/v1/status >/dev/null 2>&1; then
  echo "Warning: local FreeQ status API is not responding at http://127.0.0.1:6789/v1/status"
  echo "The direct leg can still run, but the FreeQ leg likely needs the daemon started first."
  echo
fi

RUN_ARGS=(
  --mode both
  --ssh-user "$SSH_USER"
  --ssh-port "$DIRECT_SSH_PORT"
  --label "$LABEL"
)
if [ -n "$TARGET_HOST" ]; then
  RUN_ARGS+=(--target "$TARGET_HOST")
fi
if [ -n "$OVERLAY_HOST" ]; then
  RUN_ARGS+=(--overlay-host "$OVERLAY_HOST")
fi

FREEQ_SCP_MB="$BLOB_MB" \
FREEQ_PEER_ENV="$PEER_ENV" \
  scripts/perf/freeq-perf-run.sh "${RUN_ARGS[@]}"

echo
echo "Bundle results with:"
echo "  scripts/perf/freeq-perf-bundle-results.sh \"$LABEL\""
