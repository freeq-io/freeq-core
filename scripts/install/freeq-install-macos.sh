#!/usr/bin/env bash
# FreeQ macOS installer — downloads prebuilt GitHub release binaries (fast path).
# Optional source build remains available via FREEQ_FROM_SOURCE=1.
set -euo pipefail

# When installed via `curl | bash`, BASH_SOURCE is unset; bootstrap has no local scripts.
_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$_src")" >/dev/null 2>&1 && pwd -P || true)"
else
  SCRIPT_DIR=""
fi
REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
BRANCH="${FREEQ_BRANCH:-main}"
# Binary dist lives under ~/.freeq/dist by default (no full git clone).
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/.freeq/dist/current}"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
BIN_DIR="${FREEQ_BIN_DIR:-$HOME/.freeq/bin}"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOG_FILE="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}/freeqd.log"
SETUP_URL="${FREEQ_SETUP_URL:-http://127.0.0.1:6789/}"
VERSION="${FREEQ_VERSION:-latest}"
FROM_SOURCE="${FREEQ_FROM_SOURCE:-0}"
DRY_RUN=0
ROLLBACK=0
UPDATE_STATUS="not checked"
RELEASE_TAG=""

usage() {
  cat <<'EOF'
FreeQ macOS installer.

Downloads prebuilt FreeQ binaries from GitHub Releases (no Rust/cargo required),
creates local identity under ~/.freeq/, starts the node, and prints one result.

Re-run any time to update to the latest (or FREEQ_VERSION) release.

Options:
  --dry-run      show what would happen without installing or starting
  --rollback     stop FreeQ and return this Mac to normal networking
  --from-source  clone git + cargo build (slow; developers only)
  --version TAG  install a specific release tag (default: latest)
  --help, -h     show this help

Environment:
  FREEQ_VERSION       release tag or "latest" (default latest)
  FREEQ_FROM_SOURCE   set to 1 to force git+cargo install
  FREEQ_BIN_DIR       binary symlink dir (default ~/.freeq/bin)
  FREEQ_INSTALL_DIR   install/extract root override
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
    --from-source) FROM_SOURCE=1; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

say() {
  printf '%s\n' "$*"
}

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

need() {
  command -v "$1" >/dev/null 2>&1
}

repo_root_from_script() {
  local maybe_root
  if [ -z "$SCRIPT_DIR" ]; then
    return 0
  fi
  maybe_root="$(cd "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd -P || true)"
  if [ -n "$maybe_root" ] && [ -f "$maybe_root/Cargo.toml" ] && [ -d "$maybe_root/scripts/setup" ]; then
    printf '%s\n' "$maybe_root"
  fi
}

resolve_bin() {
  local name="$1"
  if [ -n "${FREEQ_BIN_DIR:-}" ] && [ -x "${FREEQ_BIN_DIR}/${name}" ]; then
    printf '%s\n' "${FREEQ_BIN_DIR}/${name}"
    return 0
  fi
  if [ -x "${BIN_DIR}/${name}" ]; then
    printf '%s\n' "${BIN_DIR}/${name}"
    return 0
  fi
  if [ -n "${INSTALL_DIR:-}" ] && [ -x "${INSTALL_DIR}/bin/${name}" ]; then
    printf '%s\n' "${INSTALL_DIR}/bin/${name}"
    return 0
  fi
  if [ -x "${INSTALL_DIR}/target/release/${name}" ]; then
    printf '%s\n' "${INSTALL_DIR}/target/release/${name}"
    return 0
  fi
  if need "$name"; then
    command -v "$name"
    return 0
  fi
  return 1
}

print_plan() {
  cat <<EOF
FreeQ macOS installer

What this does:
  1. Downloads prebuilt FreeQ binaries for this Mac from GitHub Releases.
  2. Installs them under ~/.freeq/dist and links ~/.freeq/bin.
  3. Creates this Mac's local node identity under ~/.freeq/.
  4. Starts FreeQ in local listen mode and checks the local API.
  5. Does NOT require ~/FreeQ drop folders for pairing (legacy paths optional).

No Rust/cargo install is required for the normal path.

After install, connect without human peer-file trading:
  freeq pair host --code SECRET --port 8791 --auto-start
  freeq pair join-host --url http://HOST:8791 --code SECRET --auto-start
  freeq pair gateway --gateway-endpoint IP:51820 \\
    --gateway-peer-env PATH_OR_URL --remote-overlay OTHER/32 --auto-start

Version:
  $VERSION

Binaries:
  $BIN_DIR

State folder:
  ~/.freeq/   (identity, peers/received, pair/, perf/, dist/)

Local setup page:
  $SETUP_URL

FreeQ may ask for this Mac's local admin password so it can open the network
interface. It never asks for another person's password.
EOF
}

print_rollback_plan() {
  cat <<EOF
FreeQ macOS rollback

What this does:
  1. Stops only the validated FreeQ daemon.
  2. Removes FreeQ-owned overlay host routes.
  3. Restores Wi-Fi DHCP mode when FreeQ recorded it before start.
  4. Renews Wi-Fi DHCP so normal networking can resume.

Install / scripts:
  $INSTALL_DIR
EOF
}

check_status() {
  local status=""
  local _attempt
  for _attempt in $(seq 1 20); do
    status="$(curl -fsS --max-time 2 http://127.0.0.1:6789/v1/status 2>/dev/null || true)"
    if [ -n "$status" ]; then
      say "$status"
      return 0
    fi
    sleep 1
  done
  return 1
}

run_rollback() {
  local stop
  stop="$(resolve_bin freeq || true)"
  if [ -n "$stop" ]; then
    # freeq stop runs freeq-stop-macos.sh when package root is findable
    if FREEQ_INSTALL_DIR="$INSTALL_DIR" "$stop" stop; then
      return 0
    fi
  fi
  if [ -x "$INSTALL_DIR/scripts/setup/freeq-stop-macos.sh" ]; then
    cd "$INSTALL_DIR"
    scripts/setup/freeq-stop-macos.sh --renew-dhcp
    return 0
  fi
  fail "FreeQ rollback helper is missing. Rerun the installer without --rollback first."
}

install_from_release() {
  local fetch
  # Prefer fetch script next to this installer (curl-bootstrap or package).
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/freeq-fetch-release.sh" ]; then
    fetch="$SCRIPT_DIR/freeq-fetch-release.sh"
  elif [ -f "$INSTALL_DIR/scripts/install/freeq-fetch-release.sh" ]; then
    fetch="$INSTALL_DIR/scripts/install/freeq-fetch-release.sh"
  else
    # Bootstrap: download fetch + platform helpers into a temp dir, then run.
    local tmp
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
  if [ ! -d "$INSTALL_DIR" ]; then
    fail "Release extract did not create $INSTALL_DIR"
  fi
  if [ -f "$INSTALL_DIR/RELEASE_TAG" ]; then
    RELEASE_TAG="$(tr -d '[:space:]' <"$INSTALL_DIR/RELEASE_TAG")"
  fi
  UPDATE_STATUS="release ${RELEASE_TAG:-$VERSION}"
}

install_from_source() {
  local local_root
  local_root="$(repo_root_from_script)"
  if [ -n "$local_root" ] && [ -z "${FREEQ_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$local_root"
    UPDATE_STATUS="local checkout"
  elif [ -d "${FREEQ_SOURCE_DIR:-$HOME/freeq-core}/.git" ]; then
    INSTALL_DIR="${FREEQ_SOURCE_DIR:-$HOME/freeq-core}"
    say "Updating FreeQ source..."
    git -C "$INSTALL_DIR" fetch --all --prune
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" pull --ff-only
    UPDATE_STATUS="source updated"
  else
    INSTALL_DIR="${FREEQ_SOURCE_DIR:-$HOME/freeq-core}"
    say "Cloning FreeQ source..."
    need git || fail "git is required for --from-source"
    git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    UPDATE_STATUS="source cloned"
  fi
  cd "$INSTALL_DIR"
  FREEQ_ASSUME_DEFAULTS=1 \
  FREEQ_INSTALL_DIR="$INSTALL_DIR" \
  FREEQ_SETUP_DIR="$SETUP_DIR" \
  FREEQ_FROM_SOURCE=1 \
    scripts/setup/freeq-setup-macos.sh
}

generate_identity_if_needed() {
  local id_bin perf_dir node_name overlay listen
  perf_dir="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}"
  mkdir -p "$perf_dir" "$SETUP_DIR" "$BIN_DIR"

  if [ -f "$perf_dir/node.env" ] && [ -f "$perf_dir/identity.key" ]; then
    say "Existing identity preserved: $perf_dir/node.env"
    return 0
  fi

  id_bin="$(resolve_bin freeq-perf-identity || true)"
  if [ -z "$id_bin" ]; then
    fail "freeq-perf-identity not found after install."
  fi

  node_name="${FREEQ_NODE_NAME:-$(scutil --get ComputerName 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr ' ' '-' || echo freeq-mac)}"
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

if [ "$(uname -s)" != "Darwin" ]; then
  fail "This installer is for macOS. Linux binary install is coming next (preflight only today)."
fi

if [ "$ROLLBACK" -eq 1 ]; then
  print_rollback_plan
else
  print_plan
fi

if [ "$DRY_RUN" -eq 1 ]; then
  say ""
  say "Dry run only. Nothing was installed or started."
  # Still show resolved platform for dry-run clarity when helpers exist.
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/freeq-platform.sh" ]; then
    # shellcheck source=freeq-platform.sh
    source "$SCRIPT_DIR/freeq-platform.sh"
    say "Detected target: $(freeq_target_triple 2>/dev/null || echo unknown)"
  fi
  say "Local setup page:"
  say "  $SETUP_URL"
  exit 0
fi

if ! need curl; then
  fail "curl is required but was not found on this Mac."
fi

if [ "$ROLLBACK" -eq 1 ]; then
  # Best-effort resolve install dir for scripts
  if [ -d "$HOME/.freeq/dist/current" ]; then
    INSTALL_DIR="$HOME/.freeq/dist/current"
  fi
  say ""
  say "Rolling FreeQ back..."
  if ! run_rollback; then
    fail "FreeQ rollback did not complete."
  fi
  say ""
  say "FreeQ rollback result: PASS"
  say "FreeQ is stopped and normal networking rollback was requested."
  exit 0
fi

say ""
if [ "$FROM_SOURCE" = "1" ]; then
  say "Install mode: source build (FREEQ_FROM_SOURCE / --from-source)"
  install_from_source
else
  say "Install mode: prebuilt GitHub release binaries"
  install_from_release
fi

export FREEQ_INSTALL_DIR="$INSTALL_DIR"
export FREEQ_BIN_DIR="$BIN_DIR"
export PATH="${BIN_DIR}:${PATH}"

cd "$INSTALL_DIR"

# Binary path: identity + start without requiring cargo
if [ "$FROM_SOURCE" != "1" ]; then
  generate_identity_if_needed
fi

say ""
say "Starting FreeQ..."
if [ -x "$INSTALL_DIR/scripts/setup/freeq-render-config.sh" ]; then
  "$INSTALL_DIR/scripts/setup/freeq-render-config.sh" --listen-only --output "$CONFIG" >/dev/null
else
  fail "Missing freeq-render-config.sh in $INSTALL_DIR"
fi

FREEQ_BIN_DIR="$BIN_DIR" FREEQ_INSTALL_DIR="$INSTALL_DIR" \
  "$INSTALL_DIR/scripts/setup/freeq-start-macos.sh" --restart --no-interface --config "$CONFIG"

say ""
say "Checking FreeQ..."
if ! check_status; then
  fail "FreeQ started, but the local status check did not respond yet."
fi

open "$SETUP_URL" >/dev/null 2>&1 || true

# Ensure freeq CLI is preferred from bin dir
if [ -x "$BIN_DIR/freeq" ]; then
  say ""
  say "CLI: $BIN_DIR/freeq"
fi

say ""
say "FreeQ install result: PASS"
say "FreeQ is installed and running on this Mac."
say "Update status: $UPDATE_STATUS"
say "State folder: ~/.freeq/"
say "Binaries: $BIN_DIR"
say "Setup page:"
say "  $SETUP_URL"
say ""
say "Add to PATH if needed:"
say "  export PATH=\"$BIN_DIR:\$PATH\""
say ""
say "Connect (automatic peer exchange — no folder drop):"
say "  freeq pair show"
say "  freeq pair host --code SECRET --port 8791 --auto-start"
say "  freeq pair join-host --url http://OTHER_IP:8791 --code SECRET --auto-start"
say "  freeq pair gateway --gateway-endpoint IP:51820 --gateway-peer-env URL_OR_PATH \\"
say "    --remote-overlay 10.66.0.2/32 --auto-start"
say ""
say "Rollback:"
say "  freeq stop"
say ""
say "You are done."
