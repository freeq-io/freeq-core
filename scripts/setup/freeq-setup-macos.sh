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

is_valid_socket_addr() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress
import sys

value = sys.argv[1]
if value.startswith("["):
    host, sep, port = value[1:].partition("]:")
else:
    host, sep, port = value.rpartition(":")
if not host or not sep or not port.isdigit():
    raise SystemExit(1)
ipaddress.ip_address(host)
port_int = int(port)
if not (1 <= port_int <= 65535):
    raise SystemExit(1)
PY
}

normalize_listen_addr() {
  if is_valid_socket_addr "$LISTEN_ADDR"; then
    return 0
  fi
  echo "Invalid local listen address: $LISTEN_ADDR"
  echo "Using safe local bind default instead: 0.0.0.0:51820"
  LISTEN_ADDR="0.0.0.0:51820"
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
PUBLIC_ENDPOINT="${FREEQ_PUBLIC_ENDPOINT:-}"
PEER_SSH_USER="${FREEQ_PEER_SSH_USER:-}"
PEER_SSH_PORT="${FREEQ_PEER_SSH_PORT:-22}"
PERF_DIR="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
SEND_DIR="$SETUP_DIR/01-send-this-file"
RECEIVE_DIR="$SETUP_DIR/02-put-peer-file-here"
RESULTS_DIR="$SETUP_DIR/03-perf-results"
LOG_DIR="$SETUP_DIR/04-logs"
DRY_RUN=0

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
  FREEQ_PUBLIC_ENDPOINT reachable HOST:PORT this Mac shares in its peer file
  FREEQ_SETUP_DIR      default ~/FreeQ
  FREEQ_SETUP_CONFIG   default ~/FreeQ/freeq-setup.conf
  FREEQ_ASSUME_DEFAULTS=1 skips interactive prompts

Example:
  bash scripts/setup/freeq-setup-macos.sh

Options:
  --dry-run            print planned setup values without installing or writing files
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-no}"
  local answer
  if [ "${FREEQ_ASSUME_DEFAULTS:-}" = "1" ] || [ ! -t 0 ]; then
    return 1
  fi
  if [ "$default" = "yes" ]; then
    printf '%s [Y/n]: ' "$prompt" >&2
  else
    printf '%s [y/N]: ' "$prompt" >&2
  fi
  IFS= read -r answer || answer=""
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    n|N|no|NO) return 1 ;;
    "") [ "$default" = "yes" ] ;;
    *) return 1 ;;
  esac
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
  awk '/^FREEQ_NODE_NAME=|^FREEQ_NODE_ADDRESS=|^FREEQ_NODE_LISTEN=|^FREEQ_PUBLIC_ENDPOINT=|^FREEQ_PUBLIC_KEY_B64=|^FREEQ_KEM_KEY_B64=/' \
    "$PERF_DIR/node.env" > "$PERF_DIR/peer.env"
}

refresh_existing_identity_files() {
  # shellcheck disable=SC1090
  . "$PERF_DIR/node.env"
  local identity_key_path="${FREEQ_IDENTITY_KEY_PATH:-}"
  local public_key_b64="${FREEQ_PUBLIC_KEY_B64:-}"
  local kem_key_b64="${FREEQ_KEM_KEY_B64:-}"
  cat > "$PERF_DIR/node.env" <<EOF
# Local node file. Keep this on this Mac; send peer.env instead.
FREEQ_NODE_NAME=$(quote_shell "$NODE_NAME")
FREEQ_NODE_ADDRESS=$(quote_shell "$OVERLAY_ADDRESS")
FREEQ_NODE_LISTEN=$(quote_shell "$LISTEN_ADDR")
FREEQ_PUBLIC_ENDPOINT=$(quote_shell "$PUBLIC_ENDPOINT")
FREEQ_IDENTITY_KEY_PATH=$(quote_shell "$identity_key_path")
FREEQ_PUBLIC_KEY_B64=$(quote_shell "$public_key_b64")
FREEQ_KEM_KEY_B64=$(quote_shell "$kem_key_b64")
EOF
  write_peer_env_from_node_env
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
  PUBLIC_ENDPOINT="$(prompt_value "This Mac's reachable UDP endpoint to share, or leave blank" "$PUBLIC_ENDPOINT")"
  PEER_SSH_USER="$(prompt_value "Peer SSH user for optional benchmarks, or leave blank" "$PEER_SSH_USER")"
  if [ -n "$PEER_SSH_USER" ]; then
    PEER_SSH_PORT="$(prompt_value "Peer SSH port for optional benchmarks" "$PEER_SSH_PORT")"
  fi
  echo
}

maybe_warn_missing_public_endpoint() {
  if [ -n "$PUBLIC_ENDPOINT" ] || [ "${FREEQ_ASSUME_DEFAULTS:-}" = "1" ]; then
    return 0
  fi
  echo "FREEQ_PUBLIC_ENDPOINT is blank."
  echo "The other tester will need this Mac's reachable UDP endpoint before they can render their config."
  echo "Set it in:"
  echo "  $CONFIG_FILE"
}

write_config() {
  mkdir -p "$SETUP_DIR"
  cat > "$CONFIG_FILE" <<EOF
# FreeQ setup profile.
# Edit this visible file for machine-specific setup values.

FREEQ_NODE_NAME=$(quote_shell "$NODE_NAME")
FREEQ_OVERLAY_ADDRESS=$(quote_shell "$OVERLAY_ADDRESS")
FREEQ_LISTEN_ADDR=$(quote_shell "$LISTEN_ADDR")

# This Mac's reachable UDP endpoint to include in the peer file you send.
# Example: FREEQ_PUBLIC_ENDPOINT='<this-mac-host-or-ip>:51820'
FREEQ_PUBLIC_ENDPOINT=$(quote_shell "$PUBLIC_ENDPOINT")

FREEQ_PEER_SSH_USER=$(quote_shell "$PEER_SSH_USER")
FREEQ_PEER_SSH_PORT=$(quote_shell "$PEER_SSH_PORT")
EOF
}

write_visible_readme() {
  cat > "$SETUP_DIR/README.txt" <<EOF
FreeQ Setup

FreeQ is managed from this local setup page:

  http://127.0.0.1:6789/

Use that page to create or join a 15-minute invite.

Fallback compatibility files are kept here only for older two-node test scripts:

  Send fallback peer file:
    $SEND_DIR/$NODE_NAME-peer.env

  Receive fallback peer files:
    $RECEIVE_DIR

Performance result bundles will be written here:
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
  if [ "$peer_count" -eq 0 ]; then
    return 0
  fi
  if [ "$peer_count" -gt 1 ]; then
    echo "Multiple peer .env files are in $RECEIVE_DIR; leave only one before starting."
    return 0
  fi

  local answer
  printf 'Peer file is present. Render config and start FreeQ now? [y/N]: ' >&2
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

install_xcode_tools() {
  echo "Command to install Apple command line tools:"
  echo "  xcode-select --install"
  if ask_yes_no "Open the Apple command line tools installer now?"; then
    xcode-select --install || true
    echo "After the Apple installer finishes, rerun this setup script."
  fi
}

install_rust() {
  echo "Command to install Rust:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  if ask_yes_no "Run the Rust installer now?"; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    if [ -f "$HOME/.cargo/env" ]; then
      # shellcheck disable=SC1090
      . "$HOME/.cargo/env"
    fi
  fi
}

install_homebrew() {
  echo "Command to install Homebrew:"
  echo '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
  if ask_yes_no "Run the Homebrew installer now?"; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if [ -x /opt/homebrew/bin/brew ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -x /usr/local/bin/brew ]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
}

ensure_homebrew_packages() {
  if ! need brew; then
    echo "Homebrew is not installed."
    echo "Homebrew is optional for setup, but recommended for iperf3/jq benchmark tooling."
    install_homebrew
  fi

  if need brew; then
    for pkg in iperf3 jq; do
      if brew list "$pkg" >/dev/null 2>&1; then
        echo "Homebrew package installed: $pkg"
      else
        echo "Missing optional Homebrew package: $pkg"
        echo "Command to install it:"
        echo "  brew install $pkg"
        if ask_yes_no "Install $pkg now?"; then
          brew install "$pkg"
        fi
      fi
    done
  else
    echo "Skipping optional Homebrew packages. You can install them later with:"
    echo '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    echo "  brew install iperf3 jq"
  fi
}

run_guided_setup
normalize_listen_addr

echo "== FreeQ macOS setup =="
echo "Repo: $REPO_URL"
echo "Install dir: $INSTALL_DIR"
echo "Visible setup folder: $SETUP_DIR"
echo "Profile config: $CONFIG_FILE"
echo "Node: $NODE_NAME ($OVERLAY_ADDRESS)"
echo

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
Dry run only. No files were written and no commands were run.

Planned values:
  Node name: $NODE_NAME
  Overlay address: $OVERLAY_ADDRESS
  Listen address: $LISTEN_ADDR
  Public endpoint to share: ${PUBLIC_ENDPOINT:-not set}
  Install dir: $INSTALL_DIR
  Visible setup folder: $SETUP_DIR
  Profile config: $CONFIG_FILE
  Internal identity folder: $PERF_DIR
  Send folder: $SEND_DIR
  Peer drop folder: $RECEIVE_DIR

Setup would:
  1. Check/install dependencies.
  2. Clone or update FreeQ Core.
  3. Build release binaries.
  4. Generate local identity files.
  5. Publish the peer.env file into the visible setup folder.
EOF
  exit 0
fi

if ! need git; then
  echo "git is required. Install Xcode command line tools first:"
  echo "  xcode-select --install"
  install_xcode_tools
  if ! need git; then
    exit 1
  fi
fi

CARGO_BIN="$(find_cargo || true)"
if [ -z "$CARGO_BIN" ]; then
  echo "Rust/cargo is required. Recommended install:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  install_rust
  CARGO_BIN="$(find_cargo || true)"
  if [ -z "$CARGO_BIN" ]; then
    echo "Then open a new terminal and rerun this setup script."
    exit 1
  fi
fi

ensure_homebrew_packages

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
  refresh_existing_identity_files
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
    --public-endpoint "$PUBLIC_ENDPOINT" \
    --output-dir "$PERF_DIR"
fi
publish_visible_exchange
maybe_warn_missing_public_endpoint

cat > "$PERF_DIR/install-summary.txt" <<EOF
FreeQ setup complete.

Repo: $INSTALL_DIR
Visible setup folder: $SETUP_DIR
Profile config: $CONFIG_FILE
Node name: $NODE_NAME
Overlay address: $OVERLAY_ADDRESS
Listen: $LISTEN_ADDR
Public endpoint shared in peer file: ${PUBLIC_ENDPOINT:-not set}

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
  scripts/setup/freeq-connect-macos.sh --restart
  scripts/setup/freeq-stop-macos.sh --renew-dhcp
  scripts/perf/freeq-perf-run.sh --help
  scripts/perf/freeq-perf-bundle-results.sh

Next steps:
  1. Keep this installer window open until it reports PASS or FAIL.
  2. Use the local setup page when it opens:
     http://127.0.0.1:6789/
  3. Create or join a 15-minute invite from that page.
  4. To roll FreeQ back and resume normal networking:
     cd "$INSTALL_DIR"
     scripts/setup/freeq-stop-macos.sh --renew-dhcp

Fallback compatibility files are available here:
  Send fallback peer file:
    $SEND_DIR/$NODE_NAME-peer.env
  Receive fallback peer files:
    $RECEIVE_DIR
EOF

echo
cat "$PERF_DIR/install-summary.txt"
echo
echo "A visible setup folder is ready at:"
echo "  $SETUP_DIR"
echo
echo "After FreeQ starts, use the local setup page:"
echo "  http://127.0.0.1:6789/"
open "$SETUP_DIR" >/dev/null 2>&1 || true
offer_configure_and_start
