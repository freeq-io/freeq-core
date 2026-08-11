#!/usr/bin/env bash
# Check FreeQ Linux setup health without starting, stopping, enabling, or
# disabling anything, and without requiring sudo. Read-only, matches the
# spirit of scripts/setup/freeq-doctor-macos.sh but checks the
# deploy/ansible/roles/freeqd install shape (systemd unit, /etc/freeq,
# a dedicated freeq user) instead of the macOS workstation peer-exchange
# folder, because that's what actually installs FreeQ on Linux today.
#
# If /etc/freeq is only readable by root or the freeq group (the role's
# default 0750 root:freeq), some checks may report "cannot verify" rather
# than pass/fail — that means run this as root or a freeq group member for
# a complete answer, not that anything is broken.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OS_NAME="${FREEQ_DOCTOR_OS:-$(uname -s)}"
SERVICE_NAME="${FREEQ_SERVICE_NAME:-freeqd}"
CONFIG_DIR="${FREEQ_CONFIG_DIR:-/etc/freeq}"
CONFIG="${FREEQ_CONFIG:-$CONFIG_DIR/freeq.toml}"
NOT_CONFIGURED_MARKER="${FREEQ_NOT_CONFIGURED_MARKER:-$CONFIG_DIR/NOT-CONFIGURED.txt}"
API="${FREEQ_API:-http://127.0.0.1:6789}"
TUN_PATH="${FREEQ_TUN_PATH:-/dev/net/tun}"
BIN_DIR="${FREEQ_BIN_DIR:-/usr/local/bin}"
SOURCE_BIN_DIR="${FREEQ_SOURCE_BIN_DIR:-$REPO_ROOT/target/release}"

fail_count=0

usage() {
  cat <<'EOF'
Check FreeQ Linux setup health. Read-only; never starts, stops, enables, or
disables freeqd, and does not require sudo (though some checks need root or
freeq-group membership to read /etc/freeq).

Usage:
  scripts/setup/freeq-doctor-linux.sh

Environment overrides:
  FREEQ_SERVICE_NAME   default freeqd
  FREEQ_CONFIG_DIR     default /etc/freeq
  FREEQ_CONFIG         default /etc/freeq/freeq.toml
  FREEQ_API            default http://127.0.0.1:6789
  FREEQ_TUN_PATH       default /dev/net/tun
  FREEQ_BIN_DIR        default /usr/local/bin
  FREEQ_SOURCE_BIN_DIR default target/release in this checkout
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  local check="$1"
  local next="$2"
  printf 'FAIL: %s\n' "$check"
  printf '  Next: %s\n' "$next"
  fail_count=$((fail_count + 1))
}

info() {
  printf 'INFO: %s\n' "$1"
}

need() {
  command -v "$1" >/dev/null 2>&1
}

find_binary() {
  local name="$1"
  if [ -x "$BIN_DIR/$name" ]; then
    printf '%s\n' "$BIN_DIR/$name"
    return 0
  fi
  if [ -x "$SOURCE_BIN_DIR/$name" ]; then
    printf '%s\n' "$SOURCE_BIN_DIR/$name"
    return 0
  fi
  return 1
}

echo "FreeQ Linux doctor"
echo "  Service: $SERVICE_NAME"
echo "  Config: $CONFIG"
echo

if [ "$OS_NAME" = "Linux" ]; then
  pass "Operating system is Linux"
else
  fail "Operating system is not Linux" "use freeq-doctor-macos.sh or the platform-specific FreeQ doctor for this machine"
fi

if need systemctl; then
  pass "Dependency available: systemctl"
else
  fail "systemd is not present" "the freeqd role and unit require a systemd host; non-systemd Linux is not supported yet"
fi

if [ -e "$TUN_PATH" ]; then
  pass "TUN device present: $TUN_PATH"
else
  fail "TUN device missing: $TUN_PATH" "load the tun kernel module: sudo modprobe tun"
fi

if getent passwd freeq >/dev/null 2>&1; then
  pass "Service account exists: freeq"
else
  info "Service account 'freeq' does not exist yet; this is expected before the freeqd role has run"
fi

missing_bins=()
for bin in freeq freeqd freeq-perf-identity; do
  if ! find_binary "$bin" >/dev/null; then
    missing_bins+=("$bin")
  fi
done
if [ "${#missing_bins[@]}" -eq 0 ]; then
  pass "Binaries present: freeq, freeqd, freeq-perf-identity"
else
  fail "Binaries missing: ${missing_bins[*]}" "install the freeq package, or run cargo build --release -p freeqd -p freeq -p freeq-perf-identity"
fi

if need systemctl && systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
  pass "systemd unit installed: $SERVICE_NAME"

  enabled_state="$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || true)"
  active_state="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"

  if [ -r "$CONFIG" ]; then
    if [ "$active_state" = "active" ]; then
      pass "freeqd is configured and running (enabled: ${enabled_state:-unknown})"
    else
      fail "freeqd is configured but not running (active: ${active_state:-unknown})" "check: sudo journalctl -u $SERVICE_NAME -n 50"
    fi
  elif [ -e "$CONFIG" ]; then
    info "Cannot verify $CONFIG (not readable by this user); rerun as root or a freeq-group member for a complete check"
  else
    if [ -f "$NOT_CONFIGURED_MARKER" ] || { [ "$enabled_state" != "enabled" ] && [ "$active_state" != "active" ]; }; then
      info "freeqd is installed but not yet configured (disabled, no $CONFIG) — this is the expected state for a freshly built or imported appliance"
      info "Next: an operator runs deploy/ansible/playbooks/site.yml against this host with a real node name, address, and peers"
    else
      fail "freeqd is enabled/active but $CONFIG is missing" "check: sudo journalctl -u $SERVICE_NAME -n 50"
    fi
  fi
else
  info "systemd unit '$SERVICE_NAME' is not installed yet; this is expected before the freeqd role has run"
fi

if need curl; then
  status_body="$(curl -fsS --max-time 2 "$API/v1/status" 2>/dev/null || true)"
  if [ -n "$status_body" ]; then
    pass "Local API reachable: $API/v1/status"
  else
    info "Local API not reachable at $API/v1/status (expected if freeqd is not running yet)"
  fi
else
  info "curl not installed; skipping local API reachability check"
fi

echo
if [ "$fail_count" -eq 0 ]; then
  echo "FreeQ doctor result: PASS"
  echo "Next: if freeqd shows as not yet configured above, an operator activates this node with deploy/ansible (see docs/linux-rhel-appliance.md)"
else
  echo "FreeQ doctor result: FAIL ($fail_count issue(s))"
  echo "Fix the listed item(s), then rerun this doctor."
  exit 1
fi
