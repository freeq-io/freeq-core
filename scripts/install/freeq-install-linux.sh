#!/usr/bin/env bash
# FreeQ Linux installer — downloads prebuilt GitHub release binaries (like macOS).
# Primary path for Ubuntu/Debian-class servers (e.g. freeq.local).
set -euo pipefail

_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$_src")" >/dev/null 2>&1 && pwd -P || true)"
else
  SCRIPT_DIR=""
fi

REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
BRANCH="${FREEQ_BRANCH:-main}"
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/.freeq/dist/current}"
BIN_DIR="${FREEQ_BIN_DIR:-$HOME/.freeq/bin}"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOG_FILE="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}/freeqd.log"
SETUP_URL="${FREEQ_SETUP_URL:-http://127.0.0.1:6789/}"
GATEWAY_STATUS_URL="${FREEQ_GATEWAY_STATUS_URL:-http://127.0.0.1:6790/healthz}"
VERSION="${FREEQ_VERSION:-latest}"
FROM_SOURCE="${FREEQ_FROM_SOURCE:-0}"
ROLE="${FREEQ_ROLE:-node}" # node | gateway
DRY_RUN=0
ROLLBACK=0
PREFLIGHT=0
UPDATE_STATUS="not checked"
RELEASE_TAG=""

usage() {
  cat <<'EOF'
FreeQ Linux installer.

Downloads prebuilt FreeQ binaries from GitHub Releases (no Rust/cargo required),
creates local identity under ~/.freeq/, starts freeqd (or freeq-gateway), and
prints one result. Re-run any time to update.

Options:
  --dry-run         show plan only; no download/start
  --preflight       read-only host inspection (legacy alpha checks)
  --rollback        stop FreeQ started by this installer
  --role node|gateway  freeqd node (default) or accept-only freeq-gateway
  --version TAG     release tag or latest (default latest)
  --from-source     git clone + cargo build (developers)
  --help, -h

Environment:
  FREEQ_VERSION, FREEQ_ROLE, FREEQ_BIN_DIR, FREEQ_FROM_SOURCE
  FREEQ_NODE_NAME, FREEQ_OVERLAY_ADDRESS, FREEQ_LISTEN_ADDR
  FREEQ_PUBLIC_ENDPOINT   e.g. freeq.local:51820 for gateway public endpoint

Examples:
  # Ubuntu server node (leaf or LAN peer)
  curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh | bash

  # Accept-only gateway on freeq.local
  curl -fsSL …/freeq-install-linux.sh | FREEQ_ROLE=gateway FREEQ_PUBLIC_ENDPOINT=freeq.local:51820 bash
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --preflight) PREFLIGHT=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
    --role) ROLE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --from-source) FROM_SOURCE=1; shift ;;
    --help|-h) usage; exit 0 ;;
    --apply)
      # Back-compat with old preflight flag: treat as real install.
      shift
      ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

say() { printf '%s\n' "$*"; }

fail() {
  say ""
  say "FreeQ install result: FAILED"
  say "$*"
  if [ -f "$LOG_FILE" ]; then
    say ""
    say "Last FreeQ log lines:"
    tail -30 "$LOG_FILE" || true
  fi
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1; }

resolve_bin() {
  local name="$1"
  if [ -x "${BIN_DIR}/${name}" ]; then
    printf '%s\n' "${BIN_DIR}/${name}"
    return 0
  fi
  if [ -x "${INSTALL_DIR}/bin/${name}" ]; then
    printf '%s\n' "${INSTALL_DIR}/bin/${name}"
    return 0
  fi
  if need "$name"; then
    command -v "$name"
    return 0
  fi
  return 1
}

run_preflight() {
  local OS_RELEASE_FILE="${FREEQ_LINUX_OS_RELEASE:-/etc/os-release}"
  local TUN_PATH="${FREEQ_LINUX_TUN_PATH:-/dev/net/tun}"
  local OS_ID="unknown" OS_LIKE="" DISTRO_FAMILY="unknown"
  if [ -r "$OS_RELEASE_FILE" ]; then
    OS_ID="$(awk -F= '$1 == "ID" {gsub(/^"|"$/, "", $2); print $2; exit}' "$OS_RELEASE_FILE")"
    OS_LIKE="$(awk -F= '$1 == "ID_LIKE" {gsub(/^"|"$/, "", $2); print $2; exit}' "$OS_RELEASE_FILE")"
    OS_ID="${OS_ID:-unknown}"
  fi
  case "$OS_ID" in
    ubuntu|debian|linuxmint|elementary|pop) DISTRO_FAMILY="debian" ;;
    fedora|rhel|centos|rocky|almalinux|ol|amzn) DISTRO_FAMILY="rhel" ;;
    alpine) DISTRO_FAMILY="alpine" ;;
    arch|manjaro|endeavouros) DISTRO_FAMILY="arch" ;;
    *)
      case " $OS_LIKE " in
        *" debian "*|*" ubuntu "*) DISTRO_FAMILY="debian" ;;
        *" fedora "*|*" rhel "*) DISTRO_FAMILY="rhel" ;;
        *" arch "*) DISTRO_FAMILY="arch" ;;
      esac
      ;;
  esac
  say "FreeQ Linux preflight"
  say "  Distribution ID: $OS_ID"
  say "  Distribution family: $DISTRO_FAMILY"
  say "  Architecture: $(uname -m)"
  say "  /dev/net/tun: $([ -e "$TUN_PATH" ] && echo present || echo missing)"
  say "  curl: $(need curl && echo present || echo missing)"
  say "  tar: $(need tar && echo present || echo missing)"
  say "  systemctl: $(need systemctl && echo present || echo missing)"
  say ""
  say "Preflight result: PASS (inspection only; use installer without --preflight to install)"
}

print_plan() {
  cat <<EOF
FreeQ Linux installer

What this does:
  1. Downloads prebuilt FreeQ binaries for this CPU from GitHub Releases.
  2. Installs under ~/.freeq/dist and links ~/.freeq/bin.
  3. Creates local identity under ~/.freeq/perf.
  4. Starts freeqd (role=node) or freeq-gateway (role=gateway).
  5. Checks local status HTTP.

Role:    $ROLE
Version: $VERSION
Bin dir: $BIN_DIR
State:   ~/.freeq/

No cargo/rustc required for the normal path.
EOF
}

install_from_release() {
  local fetch tmp
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/freeq-fetch-release.sh" ]; then
    fetch="$SCRIPT_DIR/freeq-fetch-release.sh"
  elif [ -f "$INSTALL_DIR/scripts/install/freeq-fetch-release.sh" ]; then
    fetch="$INSTALL_DIR/scripts/install/freeq-fetch-release.sh"
  else
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/freeq-bootstrap.XXXXXX")"
    curl -fsSL "https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-platform.sh" \
      -o "$tmp/freeq-platform.sh"
    curl -fsSL "https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-fetch-release.sh" \
      -o "$tmp/freeq-fetch-release.sh"
    chmod +x "$tmp/freeq-platform.sh" "$tmp/freeq-fetch-release.sh"
    fetch="$tmp/freeq-fetch-release.sh"
  fi

  FREEQ_VERSION="$VERSION" \
  FREEQ_BIN_DIR="$BIN_DIR" \
  FREEQ_INSTALL_DIR="${FREEQ_DIST_ROOT:-$HOME/.freeq/dist}" \
    bash "$fetch"

  INSTALL_DIR="${HOME}/.freeq/dist/current"
  [ -d "$INSTALL_DIR" ] || fail "Release extract did not create $INSTALL_DIR"
  if [ -f "$INSTALL_DIR/RELEASE_TAG" ]; then
    RELEASE_TAG="$(tr -d '[:space:]' <"$INSTALL_DIR/RELEASE_TAG")"
  fi
  UPDATE_STATUS="release ${RELEASE_TAG:-$VERSION}"
  # Ensure Linux start/stop helpers exist even if the release tarball is older
  # than this installer (scripts are small; always refresh from main).
  refresh_linux_helpers
}

# Pull critical helper scripts from public main so install works against older
# release tarballs that only contained macOS helpers.
refresh_linux_helpers() {
  local base="${FREEQ_SCRIPTS_BASE:-https://raw.githubusercontent.com/freeq-io/freeq-core/main}"
  local rel
  say "Refreshing Linux helper scripts from main..."
  for rel in \
    scripts/setup/freeq-paths.sh \
    scripts/setup/freeq-render-config.sh \
    scripts/setup/freeq-validate-peer-env.sh \
    scripts/setup/freeq-start-linux.sh \
    scripts/setup/freeq-stop-linux.sh \
    scripts/setup/freeq-pair.sh \
    scripts/setup/freeq-doctor-linux.sh \
    scripts/install/freeq-platform.sh \
    scripts/install/freeq-fetch-release.sh \
    scripts/install/freeq-install-linux.sh; do
    mkdir -p "$INSTALL_DIR/$(dirname "$rel")"
    if curl -fsSL "$base/$rel" -o "$INSTALL_DIR/$rel"; then
      chmod +x "$INSTALL_DIR/$rel" 2>/dev/null || true
    else
      say "  warn: could not refresh $rel"
    fi
  done
}

install_from_source() {
  local src="${FREEQ_SOURCE_DIR:-$HOME/freeq-core}"
  need git || fail "git is required for --from-source"
  need cargo || fail "cargo is required for --from-source"
  if [ -d "$src/.git" ]; then
    git -C "$src" fetch --all --prune
    git -C "$src" checkout "$BRANCH"
    git -C "$src" pull --ff-only
  else
    git clone --branch "$BRANCH" "$REPO_URL" "$src"
  fi
  (cd "$src" && cargo build --release -p freeq -p freeqd -p freeq-gateway -p freeq-perf-identity)
  mkdir -p "$BIN_DIR" "$HOME/.freeq/dist/current/bin" "$HOME/.freeq/dist/current/scripts"
  for b in freeq freeqd freeq-gateway freeq-perf-identity; do
    cp "$src/target/release/$b" "$BIN_DIR/$b"
    cp "$src/target/release/$b" "$HOME/.freeq/dist/current/bin/$b"
    chmod 755 "$BIN_DIR/$b" "$HOME/.freeq/dist/current/bin/$b"
  done
  # Prefer scripts from source tree as install dir for render/start
  INSTALL_DIR="$src"
  ln -sfn "$src" "$HOME/.freeq/dist/current" 2>/dev/null || true
  UPDATE_STATUS="source build"
}

generate_identity_if_needed() {
  local id_bin perf_dir node_name overlay listen host
  perf_dir="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
  mkdir -p "$perf_dir" "$BIN_DIR"

  if [ -f "$perf_dir/node.env" ] && [ -f "$perf_dir/identity.key" ]; then
    say "Existing identity preserved: $perf_dir/node.env"
    return 0
  fi

  id_bin="$(resolve_bin freeq-perf-identity || true)"
  [ -n "$id_bin" ] || fail "freeq-perf-identity not found after install."

  host="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo freeq-linux)"
  node_name="${FREEQ_NODE_NAME:-$host}"
  overlay="${FREEQ_OVERLAY_ADDRESS:-10.66.0.$(( (RANDOM % 200) + 20 ))/32}"
  listen="${FREEQ_LISTEN_ADDR:-0.0.0.0:51820}"

  say "Generating local identity..."
  "$id_bin" \
    --node-name "$node_name" \
    --overlay-address "$overlay" \
    --listen "$listen" \
    --public-endpoint "${FREEQ_PUBLIC_ENDPOINT:-}" \
    --output-dir "$perf_dir"
}

check_status() {
  local url="$1" status="" _i
  for _i in $(seq 1 25); do
    status="$(curl -fsS --max-time 2 "$url" 2>/dev/null || true)"
    if [ -n "$status" ]; then
      say "$status"
      return 0
    fi
    sleep 1
  done
  return 1
}

# --- main ---

if [ "$PREFLIGHT" -eq 1 ]; then
  run_preflight
  exit 0
fi

print_plan

if [ "$DRY_RUN" -eq 1 ]; then
  say ""
  say "Dry run only. Nothing was installed or started."
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/freeq-platform.sh" ]; then
    # shellcheck source=freeq-platform.sh
    source "$SCRIPT_DIR/freeq-platform.sh"
    say "Detected target: $(freeq_target_triple 2>/dev/null || echo unknown)"
  fi
  exit 0
fi

if [ "$(uname -s)" != "Linux" ]; then
  fail "This installer is for Linux. Use freeq-install-macos.sh on macOS."
fi

need curl || fail "curl is required"
need tar || fail "tar is required"

if [ "$ROLLBACK" -eq 1 ]; then
  if [ -d "$HOME/.freeq/dist/current" ]; then
    INSTALL_DIR="$HOME/.freeq/dist/current"
  fi
  if [ -x "$INSTALL_DIR/scripts/setup/freeq-stop-linux.sh" ]; then
    "$INSTALL_DIR/scripts/setup/freeq-stop-linux.sh"
  elif [ -x "$BIN_DIR/../dist/current/scripts/setup/freeq-stop-linux.sh" ]; then
    "$BIN_DIR/../dist/current/scripts/setup/freeq-stop-linux.sh"
  else
    pkill -x freeqd 2>/dev/null || true
    pkill -x freeq-gateway 2>/dev/null || true
  fi
  say "FreeQ rollback result: PASS"
  exit 0
fi

say ""
if [ "$FROM_SOURCE" = "1" ]; then
  say "Install mode: source build"
  install_from_source
else
  say "Install mode: prebuilt GitHub release binaries"
  install_from_release
fi

export FREEQ_INSTALL_DIR="$INSTALL_DIR"
export FREEQ_BIN_DIR="$BIN_DIR"
export PATH="${BIN_DIR}:${PATH}"
export FREEQ_ROLE="$ROLE"

cd "$INSTALL_DIR"

generate_identity_if_needed

say ""
say "Rendering listen-only config..."
if [ -x "$INSTALL_DIR/scripts/setup/freeq-render-config.sh" ]; then
  (cd "$INSTALL_DIR" && scripts/setup/freeq-render-config.sh --listen-only --output "$CONFIG" >/dev/null)
else
  fail "Missing freeq-render-config.sh in $INSTALL_DIR"
fi

say ""
say "Starting FreeQ (role=$ROLE)..."
if [ ! -x "$INSTALL_DIR/scripts/setup/freeq-start-linux.sh" ]; then
  fail "Missing freeq-start-linux.sh — re-download a newer release or pull main scripts."
fi

FREEQ_BIN_DIR="$BIN_DIR" FREEQ_INSTALL_DIR="$INSTALL_DIR" FREEQ_ROLE="$ROLE" FREEQ_CONFIG="$CONFIG" \
  "$INSTALL_DIR/scripts/setup/freeq-start-linux.sh" --restart --role "$ROLE" --config "$CONFIG"

say ""
say "Checking FreeQ..."
if [ "$ROLE" = "gateway" ]; then
  check_status "$GATEWAY_STATUS_URL" || fail "Gateway status check failed at $GATEWAY_STATUS_URL"
else
  check_status "${SETUP_URL%/}/v1/status" || fail "Node status check failed"
fi

say ""
say "FreeQ install result: PASS"
say "FreeQ is installed and running on this Linux host."
say "Update status: $UPDATE_STATUS"
say "Role: $ROLE"
say "State folder: ~/.freeq/"
say "Binaries: $BIN_DIR"
say ""
say "Add to PATH:"
say "  export PATH=\"$BIN_DIR:\$PATH\""
say ""
if [ "$ROLE" = "gateway" ]; then
  say "Gateway status: $GATEWAY_STATUS_URL"
  say "Publish peer material from: ~/.freeq/perf/peer.env"
  say "Leaves join with: freeq pair gateway --gateway-endpoint HOST:51820 --gateway-peer-env …"
else
  say "API: $SETUP_URL"
  say "Connect:"
  say "  freeq pair host --code SECRET --port 8791 --auto-start"
  say "  freeq pair join-host --url http://THIS_HOST:8791 --code SECRET --auto-start"
  say "  freeq pair gateway --gateway-endpoint IP:51820 --gateway-peer-env URL_OR_PATH \\"
  say "    --remote-overlay OTHER/32 --auto-start"
fi
say ""
say "Stop:"
say "  $INSTALL_DIR/scripts/setup/freeq-stop-linux.sh"
say ""
say "You are done."
