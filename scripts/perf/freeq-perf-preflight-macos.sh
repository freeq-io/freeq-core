#!/usr/bin/env bash
set -euo pipefail

REMOTE_SSH="${FREEQ_REMOTE_SSH:-}"
REMOTE_SSH_PORT="${FREEQ_REMOTE_SSH_PORT:-22}"
REMOTE_UDP="${FREEQ_REMOTE_UDP:-}"
LOG_DIR="${FREEQ_LOG_DIR:-${FREEQ_PERF_LOG_DIR:-${FREEQ_SETUP_DIR:-$HOME/FreeQ}/04-logs}}"
SSH_NONINTERACTIVE_OPTS=(
  -o BatchMode=yes
  -o PreferredAuthentications=publickey
  -o PasswordAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o NumberOfPasswordPrompts=0
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=8
)
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/preflight-$(date -u +%Y%m%dT%H%M%SZ).log"

usage() {
  cat <<'EOF'
Run macOS preflight checks for a FreeQ setup.

Environment:
  FREEQ_REMOTE_SSH=user@host       optional non-interactive SSH key target to test
  FREEQ_REMOTE_SSH_PORT=PORT       optional SSH port, default 22
  FREEQ_REMOTE_UDP=host:port       optional UDP target to probe best-effort
  FREEQ_LOG_DIR=PATH               default ~/FreeQ/04-logs

Examples:
  FREEQ_REMOTE_SSH=user@example.com scripts/perf/freeq-perf-preflight-macos.sh
  FREEQ_REMOTE_UDP=example.com:51820 scripts/perf/freeq-perf-preflight-macos.sh
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

log() {
  printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

pass() {
  log "PASS: $*"
}

warn() {
  log "WARN: $*"
}

fail() {
  log "FAIL: $*"
}

need() {
  command -v "$1" >/dev/null 2>&1
}

check_cmd() {
  local cmd="$1"
  local hint="$2"
  if need "$cmd"; then
    pass "$cmd found: $(command -v "$cmd")"
  else
    fail "$cmd missing. $hint"
    FAILED=$((FAILED + 1))
  fi
}

find_cargo() {
  if need cargo; then
    candidate="$(command -v cargo)"
    if [ -x "$candidate" ] && "$candidate" --version >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  fi
  if [ -x "$HOME/.rustup/toolchains/stable-x86_64-apple-darwin/bin/cargo" ]; then
    echo "$HOME/.rustup/toolchains/stable-x86_64-apple-darwin/bin/cargo"
    return 0
  fi
  return 1
}

FAILED=0

log "== FreeQ macOS setup preflight =="
log "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Log: $LOG_FILE"
log ""

if [ "$(uname -s)" = "Darwin" ]; then
  pass "macOS detected"
else
  fail "This helper is for macOS. Detected: $(uname -s)"
  FAILED=$((FAILED + 1))
fi

check_cmd git "Install Xcode command line tools: xcode-select --install"
CARGO_BIN="$(find_cargo || true)"
if [ -n "$CARGO_BIN" ]; then
  pass "cargo found: $CARGO_BIN"
else
  fail "cargo missing. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  FAILED=$((FAILED + 1))
fi
check_cmd ssh "SSH should be included with macOS."
check_cmd curl "curl should be included with macOS."

if need brew; then
  pass "Homebrew found: $(command -v brew)"
  for pkg in iperf3 jq; do
    if brew list "$pkg" >/dev/null 2>&1; then
      pass "Homebrew package installed: $pkg"
    else
      warn "Homebrew package missing: $pkg. Install with: brew install $pkg"
    fi
  done
else
  warn "Homebrew missing. Install with: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
  warn "After Homebrew is installed, optional benchmark tools can be installed with: brew install iperf3 jq"
fi

if [ -n "$REMOTE_SSH" ]; then
  log ""
  log "Testing SSH reachability to $REMOTE_SSH on port $REMOTE_SSH_PORT..."
  if ssh -p "$REMOTE_SSH_PORT" "${SSH_NONINTERACTIVE_OPTS[@]}" "$REMOTE_SSH" 'echo freeq-ssh-ok'; then
    pass "SSH reached $REMOTE_SSH on port $REMOTE_SSH_PORT"
  else
    warn "SSH test failed. Check host, username, Remote Login, firewall, port forwarding, and key-based auth."
  fi
fi

if [ -n "$REMOTE_UDP" ]; then
  host="${REMOTE_UDP%:*}"
  port="${REMOTE_UDP##*:}"
  log ""
  log "Best-effort UDP probe to $host:$port..."
  if need nc; then
    if nc -u -z -w 2 "$host" "$port" >/dev/null 2>&1; then
      pass "UDP probe did not report failure"
    else
      warn "UDP probe did not confirm reachability. UDP probes are often inconclusive behind NAT."
    fi
  else
    warn "nc not available; skipping UDP probe."
  fi
fi

log ""
if [ "$FAILED" -eq 0 ]; then
  pass "Preflight complete"
  exit 0
fi

fail "Preflight found $FAILED required issue(s). Fix those and rerun."
exit 1
