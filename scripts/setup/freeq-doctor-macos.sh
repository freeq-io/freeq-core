#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OS_NAME="${FREEQ_DOCTOR_OS:-$(uname -s)}"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"
LOCAL_ENV="${FREEQ_LOCAL_ENV:-$HOME/.freeq/perf/node.env}"
PEER_ENV="${FREEQ_PEER_ENV:-}"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
BIN_DIR="${FREEQ_BIN_DIR:-$REPO_ROOT/target/release}"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
SEND_DIR="$SETUP_DIR/01-send-this-file"

fail_count=0
selected_peer_env=""

usage() {
  cat <<'EOF'
Check FreeQ macOS setup health without starting FreeQ or using sudo.

Usage:
  scripts/setup/freeq-doctor-macos.sh

Environment overrides:
  FREEQ_SETUP_DIR      default ~/FreeQ
  FREEQ_SETUP_CONFIG   default ~/FreeQ/freeq-setup.conf
  FREEQ_LOCAL_ENV      default ~/.freeq/perf/node.env
  FREEQ_PEER_ENV       explicit peer.env, otherwise auto-detect in ~/FreeQ
  FREEQ_CONFIG         default ~/.freeq/perf/freeq.toml
  FREEQ_BIN_DIR        default target/release in this checkout
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

local_node_name() {
  if [ -f "$LOCAL_ENV" ]; then
    env_value "$LOCAL_ENV" FREEQ_NODE_NAME
  fi
}

local_node_address() {
  if [ -f "$LOCAL_ENV" ]; then
    env_value "$LOCAL_ENV" FREEQ_NODE_ADDRESS
  fi
}

select_peer_env() {
  if [ -n "$PEER_ENV" ]; then
    if [ -f "$PEER_ENV" ]; then
      printf '%s\n' "$PEER_ENV"
      return 0
    fi
    return 1
  fi

  local candidates=()
  local remote_candidates=()
  local path peer_name peer_address
  local local_name local_address
  local_name="$(local_node_name)"
  local_address="$(local_node_address)"

  for path in "$RECEIVE_DIR"/*.env; do
    if [ -f "$path" ]; then
      candidates+=("$path")
    fi
  done

  if [ "${#candidates[@]}" -gt 0 ]; then
    for path in "${candidates[@]}"; do
      peer_name="$(env_value "$path" FREEQ_NODE_NAME)"
      peer_address="$(env_value "$path" FREEQ_NODE_ADDRESS)"
      if { [ -n "$local_name" ] && [ "$peer_name" = "$local_name" ]; } || \
         { [ -n "$local_address" ] && [ "$peer_address" = "$local_address" ]; }; then
        continue
      fi
      remote_candidates+=("$path")
    done
  fi

  if [ "${#remote_candidates[@]}" -eq 1 ]; then
    printf '%s\n' "${remote_candidates[0]}"
    return 0
  fi
  if [ "${#remote_candidates[@]}" -gt 1 ]; then
    printf 'AMBIGUOUS\n'
    printf '%s\n' "${remote_candidates[@]}"
    return 2
  fi
  if [ "${#candidates[@]}" -gt 1 ]; then
    printf 'LOCAL_ONLY_MULTIPLE\n'
    printf '%s\n' "${candidates[@]}"
    return 3
  fi
  return 1
}

check_file_nonempty() {
  local label="$1"
  local path="$2"
  local next="$3"
  if [ -s "$path" ]; then
    pass "$label: $path"
  else
    fail "$label missing or empty: $path" "$next"
  fi
}

check_dependency() {
  local command_name="$1"
  local next="$2"
  if need "$command_name"; then
    pass "Dependency available: $command_name"
  else
    fail "Dependency missing: $command_name" "$next"
  fi
}

check_local_env() {
  if [ ! -f "$LOCAL_ENV" ]; then
    fail "Local node env missing: $LOCAL_ENV" "run freeq setup"
    return
  fi

  local missing=()
  local key
  for key in FREEQ_NODE_NAME FREEQ_NODE_ADDRESS FREEQ_NODE_LISTEN FREEQ_IDENTITY_KEY_PATH FREEQ_PUBLIC_KEY_B64 FREEQ_KEM_KEY_B64; do
    if [ -z "$(env_value "$LOCAL_ENV" "$key")" ]; then
      missing+=("$key")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    fail "Local node env is incomplete: ${missing[*]}" "run freeq setup again"
    return
  fi

  local identity_key
  identity_key="$(env_value "$LOCAL_ENV" FREEQ_IDENTITY_KEY_PATH)"
  if [ ! -f "$identity_key" ]; then
    fail "Local identity key missing: $identity_key" "run freeq setup again"
    return
  fi

  pass "Local node env is ready: $LOCAL_ENV"
}

check_peer_env() {
  local selection
  local status
  set +e
  selection="$(select_peer_env)"
  status=$?
  set -e

  case "$status" in
    0)
      selected_peer_env="$selection"
      pass "Received peer env found: $selected_peer_env"
      if "$SCRIPT_DIR/freeq-validate-peer-env.sh" "$selected_peer_env" >/dev/null; then
        pass "Peer env validation passed"
      else
        fail "Peer env validation failed: $selected_peer_env" "ask the other node operator to rerun setup and resend peer.env"
      fi
      ;;
    1)
      fail "Received peer env missing" "place exactly one remote peer.env in $RECEIVE_DIR"
      ;;
    2)
      fail "Received peer env is ambiguous" "leave only the intended remote peer.env in $RECEIVE_DIR"
      printf '%s\n' "$selection" | sed 's/^/  Candidate: /'
      ;;
    3)
      fail "Peer drop folder contains only local-node peer files" "place the remote node or gateway peer.env in $RECEIVE_DIR"
      ;;
    *)
      fail "Unable to inspect peer env" "check $RECEIVE_DIR and rerun this doctor"
      ;;
  esac
}

check_binaries() {
  local missing=()
  local bin
  for bin in freeq freeqd freeq-perf-identity; do
    if [ ! -x "$BIN_DIR/$bin" ]; then
      missing+=("$BIN_DIR/$bin")
    fi
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    pass "Release binaries are built in $BIN_DIR"
  else
    fail "Release binaries missing: ${missing[*]}" "run cargo build --release -p freeqd -p freeq -p freeq-perf-identity"
  fi
}

echo "FreeQ macOS doctor"
echo "  Setup folder: $SETUP_DIR"
echo "  Peer drop folder: $RECEIVE_DIR"
echo "  Local node env: $LOCAL_ENV"
echo "  Rendered config: $CONFIG"
echo

if [ "$OS_NAME" = "Darwin" ]; then
  pass "Operating system is macOS"
else
  fail "Operating system is not macOS" "use the Linux or platform-specific FreeQ doctor for this machine"
fi

check_dependency git "install Apple command line tools with xcode-select --install"
check_dependency python3 "install Python 3, then rerun freeq setup"

if need cargo; then
  pass "Dependency available: cargo"
else
  info "Cargo is not installed; it is required only for source builds, not for an already installed FreeQ binary."
fi

if need brew; then
  pass "Dependency available: brew"
else
  info "Homebrew is not installed; setup can continue, but benchmark tools are easier with brew."
fi

if [ -d "$SETUP_DIR" ]; then
  pass "Visible setup folder exists: $SETUP_DIR"
else
  fail "Visible setup folder missing: $SETUP_DIR" "run freeq setup"
fi

if [ -d "$SEND_DIR" ]; then
  pass "Send folder exists: $SEND_DIR"
else
  fail "Send folder missing: $SEND_DIR" "run freeq setup"
fi

if [ -d "$RECEIVE_DIR" ]; then
  pass "Peer drop folder exists: $RECEIVE_DIR"
else
  fail "Peer drop folder missing: $RECEIVE_DIR" "run freeq setup"
fi

check_file_nonempty "Setup profile config" "$CONFIG_FILE" "run freeq setup"
check_local_env
check_peer_env
check_binaries
check_file_nonempty "Rendered freeq.toml" "$CONFIG" "run freeq gateway after adding the intended peer.env"

echo
if [ "$fail_count" -eq 0 ]; then
  echo "FreeQ doctor result: PASS"
  echo "Next: run freeq status or freeq gateway status"
else
  echo "FreeQ doctor result: FAIL ($fail_count issue(s))"
  echo "Fix the listed item(s), then rerun this doctor."
  exit 1
fi
