#!/usr/bin/env bash
set -euo pipefail

default_node_name() {
  hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed 's/^-*//;s/-*$//'
}

REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/freeq-core}"
BRANCH="${FREEQ_BRANCH:-main}"
DEFAULT_NODE_NAME="$(default_node_name)"
NODE_NAME="${FREEQ_NODE_NAME:-${DEFAULT_NODE_NAME:-freeq-mac}}"
OVERLAY_ADDRESS="${FREEQ_OVERLAY_ADDRESS:-10.66.0.2/24}"
LISTEN_ADDR="${FREEQ_LISTEN_ADDR:-0.0.0.0:51820}"

usage() {
  cat <<'EOF'
Install/build FreeQ Core on macOS and prepare perf-test identity files.

Environment overrides:
  FREEQ_REPO_URL       default https://github.com/freeq-io/freeq-core.git
  FREEQ_INSTALL_DIR    default ~/freeq-core
  FREEQ_BRANCH         default main
  FREEQ_NODE_NAME      default sanitized local hostname
  FREEQ_OVERLAY_ADDRESS default 10.66.0.2/24
  FREEQ_LISTEN_ADDR    default 0.0.0.0:51820

Example:
  FREEQ_NODE_NAME=florida-mac \
  bash scripts/perf/freeq-perf-install-macos.sh
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
  echo "Backed up existing perf identity/config files to:"
  echo "  $backup_dir"
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

echo "== FreeQ macOS perf install =="
echo "Repo: $REPO_URL"
echo "Install dir: $INSTALL_DIR"
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
  echo "Preflight found an issue. You can still inspect the log under ~/.freeq/perf,"
  echo "fix the listed item, and rerun this installer."
  exit 1
}

echo "Building FreeQ release binaries..."
"$CARGO_BIN" build --release -p freeqd -p freeq -p freeq-perf-identity

PERF_DIR="$HOME/.freeq/perf"
mkdir -p "$PERF_DIR"

if existing_identity_matches; then
  echo "Existing matching perf identity found; preserving:"
  echo "  $PERF_DIR/node.env"
  if [ ! -f "$PERF_DIR/peer.env" ]; then
    write_peer_env_from_node_env
    echo "Created public exchange file:"
    echo "  $PERF_DIR/peer.env"
  fi
else
  if [ -e "$PERF_DIR/identity.key" ] || [ -e "$PERF_DIR/node.env" ] || [ -e "$PERF_DIR/peer.env" ] || [ -e "$PERF_DIR/node-exchange.json" ] || [ -e "$PERF_DIR/peer-snippet.toml" ]; then
    backup_perf_identity
  fi
  echo "Generating local perf identity bundle..."
  target/release/freeq-perf-identity \
    --node-name "$NODE_NAME" \
    --overlay-address "$OVERLAY_ADDRESS" \
    --listen "$LISTEN_ADDR" \
    --output-dir "$PERF_DIR"
fi

cat > "$PERF_DIR/install-summary.txt" <<EOF
FreeQ perf install complete.

Repo: $INSTALL_DIR
Node name: $NODE_NAME
Overlay address: $OVERLAY_ADDRESS
Listen: $LISTEN_ADDR

Send this file to the other tester over a trusted channel:
  $PERF_DIR/peer.env

Keep this file local:
  $PERF_DIR/node.env

Never send this private key:
  $PERF_DIR/identity.key

Useful commands:
  cd "$INSTALL_DIR"
  scripts/perf/freeq-perf-preflight-macos.sh
  scripts/perf/freeq-perf-render-config.sh --help
  scripts/perf/freeq-perf-start-macos.sh --help
  scripts/perf/freeq-perf-run.sh --help
  scripts/perf/freeq-perf-bundle-results.sh

David next steps:
  1. Send Patrick:
     $PERF_DIR/peer.env
  2. Save Patrick's peer.env as:
     $HOME/Downloads/patrick-peer.env
  3. Ask Patrick for his reachable UDP host/IP and run:
     cd "$INSTALL_DIR"
     scripts/perf/freeq-perf-render-config.sh \\
       --local-env "$PERF_DIR/node.env" \\
       --peer-env "$HOME/Downloads/patrick-peer.env" \\
       --peer-endpoint ACTUAL_PATRICK_HOST_OR_IP:51820
  4. Start FreeQ:
     scripts/perf/freeq-perf-start-macos.sh --peer-env "$HOME/Downloads/patrick-peer.env"
  5. Run the overlay leg:
     scripts/perf/freeq-perf-run.sh \\
       --mode freeq \\
       --overlay-host 10.66.0.1 \\
       --ssh-user patrickmccormick \\
       --label david-to-patrick-freeq
  6. Bundle results:
     scripts/perf/freeq-perf-bundle-results.sh david-to-patrick
EOF

echo
cat "$PERF_DIR/install-summary.txt"
