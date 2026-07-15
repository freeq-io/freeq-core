#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/freeq-core}"
BRANCH="${FREEQ_BRANCH:-main}"
NODE_NAME="${FREEQ_NODE_NAME:-florida-mac}"
OVERLAY_ADDRESS="${FREEQ_OVERLAY_ADDRESS:-10.66.0.2/24}"
LISTEN_ADDR="${FREEQ_LISTEN_ADDR:-0.0.0.0:51820}"
REMOTE_SSH="${FREEQ_REMOTE_SSH:-}"
REMOTE_SSH_PORT="${FREEQ_REMOTE_SSH_PORT:-22}"

usage() {
  cat <<'EOF'
Install/build FreeQ Core on macOS and prepare perf-test identity files.

Environment overrides:
  FREEQ_REPO_URL       default https://github.com/freeq-io/freeq-core.git
  FREEQ_INSTALL_DIR    default ~/freeq-core
  FREEQ_BRANCH         default main
  FREEQ_NODE_NAME      default florida-mac
  FREEQ_OVERLAY_ADDRESS default 10.66.0.2/24
  FREEQ_LISTEN_ADDR    default 0.0.0.0:51820
  FREEQ_REMOTE_SSH     optional user@host for Patrick's Mac direct SSH check
  FREEQ_REMOTE_SSH_PORT optional SSH port for Patrick's Mac, default 22

Example:
  FREEQ_REMOTE_SSH=patrickmccormick@203.0.113.10 \
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
FREEQ_REMOTE_SSH="$REMOTE_SSH" FREEQ_REMOTE_SSH_PORT="$REMOTE_SSH_PORT" scripts/perf/freeq-perf-preflight-macos.sh || {
  echo
  echo "Preflight found an issue. You can still inspect the log under ~/.freeq/perf,"
  echo "fix the listed item, and rerun this installer."
  exit 1
}

echo "Building FreeQ release binaries..."
"$CARGO_BIN" build --release -p freeqd -p freeq -p freeq-perf-identity

PERF_DIR="$HOME/.freeq/perf"
mkdir -p "$PERF_DIR"

echo "Generating local perf identity bundle..."
target/release/freeq-perf-identity \
  --node-name "$NODE_NAME" \
  --overlay-address "$OVERLAY_ADDRESS" \
  --listen "$LISTEN_ADDR" \
  --output-dir "$PERF_DIR"

cat > "$PERF_DIR/install-summary.txt" <<EOF
FreeQ perf install complete.

Repo: $INSTALL_DIR
Node name: $NODE_NAME
Overlay address: $OVERLAY_ADDRESS
Listen: $LISTEN_ADDR

Send this file to Patrick over a trusted channel:
  $PERF_DIR/node.env

Useful commands:
  cd "$INSTALL_DIR"
  scripts/perf/freeq-perf-preflight-macos.sh
  scripts/perf/freeq-perf-render-config.sh --help
  scripts/perf/freeq-perf-start-macos.sh --help
  scripts/perf/freeq-perf-run.sh --help
  scripts/perf/freeq-perf-bundle-results.sh

David next steps:
  1. Send Patrick this file:
     $PERF_DIR/node.env
  2. Save Patrick's node.env as:
     $HOME/Downloads/patrick-node.env
  3. Ask Patrick for his reachable host/IP and run:
     cd "$INSTALL_DIR"
     scripts/perf/freeq-perf-render-config.sh \\
       --local-env "$PERF_DIR/node.env" \\
       --peer-env "$HOME/Downloads/patrick-node.env" \\
       --peer-endpoint PATRICK_HOST_OR_IP:51820
  4. Start FreeQ:
     scripts/perf/freeq-perf-start-macos.sh --peer-env "$HOME/Downloads/patrick-node.env"
  5. Run the overlay leg:
     scripts/perf/freeq-perf-run.sh \\
       --mode freeq \\
       --overlay-host 10.66.0.1 \\
       --ssh-user patrickmccormick \\
       --label david-to-patrick-freeq
  6. Bundle results:
     scripts/perf/freeq-perf-bundle-results.sh david-to-patrick
EOF

if [ -n "$REMOTE_SSH" ]; then
  echo "Testing SSH reachability to $REMOTE_SSH on port $REMOTE_SSH_PORT..."
  if ssh -p "$REMOTE_SSH_PORT" -o BatchMode=no -o ConnectTimeout=8 "$REMOTE_SSH" 'echo freeq-ssh-ok'; then
    echo "SSH check succeeded."
  else
    echo "SSH check failed. This is not fatal; verify hostname, user, firewall, and Remote Login."
  fi
fi

echo
cat "$PERF_DIR/install-summary.txt"
