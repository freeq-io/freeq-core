#!/usr/bin/env bash
set -euo pipefail

default_node_name() {
  hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed 's/^-*//;s/-*$//'
}

default_overlay_address() {
  local name="$1"
  local checksum
  checksum="$(printf '%s' "$name" | cksum | awk '{print $1}')"
  printf '10.66.0.%s/24\n' "$((checksum % 200 + 20))"
}

quote_shell() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/freeq-core}"
BRANCH="${FREEQ_BRANCH:-main}"
DEFAULT_NODE_NAME="$(default_node_name)"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG_FILE="${FREEQ_SETUP_CONFIG:-$SETUP_DIR/freeq-setup.conf}"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

NODE_NAME="${FREEQ_NODE_NAME:-${DEFAULT_NODE_NAME:-freeq-mac}}"
OVERLAY_ADDRESS="${FREEQ_OVERLAY_ADDRESS:-$(default_overlay_address "$NODE_NAME")}"
LISTEN_ADDR="${FREEQ_LISTEN_ADDR:-0.0.0.0:51820}"
PEER_ENDPOINT="${FREEQ_PEER_ENDPOINT:-}"
PEER_SSH_USER="${FREEQ_PEER_SSH_USER:-}"
PEER_SSH_PORT="${FREEQ_PEER_SSH_PORT:-22}"
PERF_DIR="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
SEND_DIR="$SETUP_DIR/01-send-this-file"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
RESULTS_DIR="$SETUP_DIR/03-perf-results"
LOG_DIR="$SETUP_DIR/04-logs"

usage() {
  cat <<'EOF'
Install/build FreeQ Core on macOS and prepare setup identity files.

Environment overrides:
  FREEQ_REPO_URL       default https://github.com/freeq-io/freeq-core.git
  FREEQ_INSTALL_DIR    default ~/freeq-core
  FREEQ_BRANCH         default main
  FREEQ_NODE_NAME      default sanitized local hostname
  FREEQ_OVERLAY_ADDRESS default generated from local hostname
  FREEQ_LISTEN_ADDR    default 0.0.0.0:51820
  FREEQ_SETUP_DIR      default ~/FreeQ
  FREEQ_SETUP_CONFIG   default ~/FreeQ/freeq-setup.conf
  FREEQ_ASSUME_DEFAULTS=1 skips interactive prompts

Example:
  bash scripts/setup/freeq-setup-macos.sh
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

need() {
  command -v "$1" >/dev/null 2>&1
}

existing_identity_matches() {
  if [ ! -f "$PERF_DIR/node.env" ]; then
    return 1
  fi
  # shellcheck disable=SC1090
  . "$PERF_DIR/node.env"
  [ "${FREEQ_NODE_NAME:-}" = "$NODE_NAME" ] && [ "${FREEQ_NODE_ADDRESS:-}" = "$OVERLAY_ADDRESS" ] && [ -f "${FREEQ_IDENTITY_KEY_PATH:-}" ]
}

write_peer_env_from_node_env() {
  awk '/^FREEQ_NODE_NAME=|^FREEQ_NODE_ADDRESS=|^FREEQ_NODE_LISTEN=|^FREEQ_PUBLIC_KEY_B64=|^FREEQ_KEM_KEY_B64=/' \
    "$PERF_DIR/node.env" > "$PERF_DIR/peer.env"
}

backup_perf_identity() {
  local timestamp
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local backup_dir="$PERF_DIR/backups/$timestamp"
  mkdir -p "$backup_dir"
  for file in identity.key node.env peer.env node-exchange.json peer-snippet.toml freeq.toml; do
    if [ -e "$PERF_DIR/$file" ]; then
      mv "$PERF_DIR/$file" "$backup_dir/$file"
    fi
  done
  echo "Backed up existing setup identity/config files to:"
  echo "  $backup_dir"
}

prompt_value() {
  local label="$1"
  local current="$2"
  local answer
  if [ "${FREEQ_ASSUME_DEFAULTS:-}" = "1" ] || [ ! -t 0 ]; then
    printf '%s\n' "$current"
    return 0
  fi
  printf '%s [%s]: ' "$label" "$current" >&2
  IFS= read -r answer || answer=""
  if [ -n "$answer" ]; then
    printf '%s\n' "$answer"
  else
    printf '%s\n' "$current"
  fi
}

run_guided_setup() {
  if [ "${FREEQ_ASSUME_DEFAULTS:-}" = "1" ] || [ ! -t 0 ]; then
    return 0
  fi
  echo "FreeQ setup will use local defaults. Press Return to accept a value."
  NODE_NAME="$(prompt_value "Local node name" "$NODE_NAME")"
  OVERLAY_ADDRESS="$(prompt_value "Local overlay address" "$OVERLAY_ADDRESS")"
  LISTEN_ADDR="$(prompt_value "Local listen address" "$LISTEN_ADDR")"
  PEER_ENDPOINT="$(prompt_value "Peer reachable UDP endpoint, or leave blank for later" "$PEER_ENDPOINT")"
  PEER_SSH_USER="$(prompt_value "Peer SSH user for optional benchmarks, or leave blank" "$PEER_SSH_USER")"
  if [ -n "$PEER_SSH_USER" ]; then
    PEER_SSH_PORT="$(prompt_value "Peer SSH port for optional benchmarks" "$PEER_SSH_PORT")"
  fi
  echo
}

write_config() {
  mkdir -p "$SETUP_DIR"
  cat > "$CONFIG_FILE" <<EOF
# FreeQ setup profile.
# Edit this visible file for machine-specific setup values.

FREEQ_NODE_NAME=$(quote_shell "$NODE_NAME")
FREEQ_OVERLAY_ADDRESS=$(quote_shell "$OVERLAY_ADDRESS")
FREEQ_LISTEN_ADDR=$(quote_shell "$LISTEN_ADDR")

# Fill this in before rendering config, or pass --peer-endpoint HOST:PORT.
# Example: FREEQ_PEER_ENDPOINT='<peer-host-or-ip>:51820'
FREEQ_PEER_ENDPOINT=$(quote_shell "$PEER_ENDPOINT")
FREEQ_PEER_SSH_USER=$(quote_shell "$PEER_SSH_USER")
FREEQ_PEER_SSH_PORT=$(quote_shell "$PEER_SSH_PORT")
EOF
}

write_visible_readme() {
  cat > "$SETUP_DIR/README.txt" <<EOF
FreeQ Setup

This visible folder is the only folder you need to use.

1. Send this file to the other tester:
   $SEND_DIR/$NODE_NAME-peer.env

2. When the other tester sends you their peer.env file, put it here:
   $RECEIVE_DIR

3. Ask the other tester for their reachable UDP host or IP, put it in:
   $CONFIG_FILE

4. Then run:
   cd "$INSTALL_DIR"
   scripts/setup/freeq-render-config.sh
   scripts/setup/freeq-start-macos.sh

5. Performance result bundles will be written here:
   $RESULTS_DIR

Do not send identity.key.
Do not use Finder to open hidden .freeq folders.
EOF
}

publish_visible_exchange() {
  mkdir -p "$SEND_DIR" "$RECEIVE_DIR" "$RESULTS_DIR" "$LOG_DIR"
  write_config
  cp "$PERF_DIR/peer.env" "$SEND_DIR/$NODE_NAME-peer.env"
  cat > "$RECEIVE_DIR/PUT-PEER-FILE-HERE.txt" <<EOF
Put the other tester's peer.env file in this folder.

After there is exactly one .env file in this folder, the setup scripts will
find it automatically. You should not need to type this file path.
EOF
  write_visible_readme
}

count_received_peer_envs() {
  local count=0
  local path
  for path in "$RECEIVE_DIR"/*.env; do
    if [ -f "$path" ]; then
      count=$((count + 1))
    fi
  done
  printf '%s\n' "$count"
}

offer_configure_and_start() {
  if [ "${FREEQ_ASSUME_DEFAULTS:-}" = "1" ] || [ ! -t 0 ]; then
    return 0
  fi
  local peer_count
  peer_count="$(count_received_peer_envs)"
  if [ "$peer_count" -eq 0 ] || [ -z "$PEER_ENDPOINT" ]; then
    return 0
  fi
  if [ "$peer_count" -gt 1 ]; then
    echo "Multiple peer .env files are in $RECEIVE_DIR; leave only one before starting."
    return 0
  fi

  local answer
  printf 'Peer file and endpoint are present. Render config and start FreeQ now? [y/N]: ' >&2
  IFS= read -r answer || answer=""
  case "$answer" in
    y|Y|yes|YES)
      scripts/setup/freeq-render-config.sh
      scripts/setup/freeq-start-macos.sh
      ;;
  esac
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

run_guided_setup

echo "== FreeQ macOS setup =="
echo "Repo: $REPO_URL"
echo "Install dir: $INSTALL_DIR"
echo "Visible setup folder: $SETUP_DIR"
echo "Profile config: $CONFIG_FILE"
echo "Node: $NODE_NAME ($OVERLAY_ADDRESS)"
echo

if ! need git; then
  echo "git is required. Install Xcode command line tools first:"
  echo "  xcode-select --install"
  exit 1
fi

CARGO_BIN="$(find_cargo || true)"
if [ -z "$CARGO_BIN" ]; then
  echo "Rust/cargo is required. Recommended install:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "Then open a new terminal and rerun this script."
  exit 1
fi

if need brew; then
  for pkg in iperf3 jq; do
    if ! brew list "$pkg" >/dev/null 2>&1; then
      echo "Installing Homebrew package: $pkg"
      brew install "$pkg"
    fi
  done
else
  echo "Homebrew not found. iperf3/jq will not be auto-installed."
  echo "Install Homebrew later if direct throughput tests need iperf3."
fi

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing checkout..."
  git -C "$INSTALL_DIR" fetch --all --prune
  git -C "$INSTALL_DIR" checkout "$BRANCH"
  git -C "$INSTALL_DIR" pull --ff-only
else
  echo "Cloning FreeQ Core..."
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

echo "Running local preflight checks..."
scripts/perf/freeq-perf-preflight-macos.sh || {
  echo
  echo "Preflight found an issue. You can inspect the visible log folder:"
  echo "  $LOG_DIR"
  echo "fix the listed item, and rerun this installer."
  exit 1
}

echo "Building FreeQ release binaries..."
"$CARGO_BIN" build --release -p freeqd -p freeq -p freeq-perf-identity

mkdir -p "$PERF_DIR"

if existing_identity_matches; then
  echo "Existing matching setup identity found; preserving:"
  echo "  $PERF_DIR/node.env"
  write_peer_env_from_node_env
  echo "Refreshed public exchange file:"
  echo "  $PERF_DIR/peer.env"
else
  if [ -e "$PERF_DIR/identity.key" ] || [ -e "$PERF_DIR/node.env" ] || [ -e "$PERF_DIR/peer.env" ] || [ -e "$PERF_DIR/node-exchange.json" ] || [ -e "$PERF_DIR/peer-snippet.toml" ]; then
    backup_perf_identity
  fi
  echo "Generating local setup identity bundle..."
  target/release/freeq-perf-identity \
    --node-name "$NODE_NAME" \
    --overlay-address "$OVERLAY_ADDRESS" \
    --listen "$LISTEN_ADDR" \
    --output-dir "$PERF_DIR"
fi
publish_visible_exchange

cat > "$PERF_DIR/install-summary.txt" <<EOF
FreeQ setup complete.

Repo: $INSTALL_DIR
Visible setup folder: $SETUP_DIR
Profile config: $CONFIG_FILE
Node name: $NODE_NAME
Overlay address: $OVERLAY_ADDRESS
Listen: $LISTEN_ADDR

Send this file to the other tester over a trusted channel:
  $SEND_DIR/$NODE_NAME-peer.env

Keep this file local:
  internal node.env generated by the installer

Never send this private key:
  identity.key

Useful commands:
  cd "$INSTALL_DIR"
  scripts/perf/freeq-perf-preflight-macos.sh
  scripts/setup/freeq-render-config.sh --help
  scripts/setup/freeq-start-macos.sh --help
  scripts/perf/freeq-perf-run.sh --help
  scripts/perf/freeq-perf-bundle-results.sh

Next steps:
  1. Send the other tester:
     $SEND_DIR/$NODE_NAME-peer.env
  2. Put the other tester's peer.env file in:
     $RECEIVE_DIR
  3. Set FREEQ_PEER_ENDPOINT in:
     $CONFIG_FILE
  4. Render and start:
     cd "$INSTALL_DIR"
     scripts/setup/freeq-render-config.sh
     scripts/setup/freeq-start-macos.sh
  5. Run the overlay leg:
     scripts/perf/freeq-perf-run.sh \\
       --mode freeq \\
       --label "$NODE_NAME-to-peer-freeq"
  6. Bundle results:
     scripts/perf/freeq-perf-bundle-results.sh "$NODE_NAME-to-peer"
EOF

echo
cat "$PERF_DIR/install-summary.txt"
echo
echo "A visible setup folder is ready at:"
echo "  $SETUP_DIR"
echo
echo "Send this visible file:"
echo "  $SEND_DIR/$NODE_NAME-peer.env"
open "$SETUP_DIR" >/dev/null 2>&1 || true
offer_configure_and_start
