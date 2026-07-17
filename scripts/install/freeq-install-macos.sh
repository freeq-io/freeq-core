#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
BRANCH="${FREEQ_BRANCH:-main}"
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/freeq-core}"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOG_FILE="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}/freeqd.log"
DRY_RUN=0

usage() {
  cat <<'EOF'
FreeQ macOS installer.

This installer prepares FreeQ, starts the local node, and prints one result.

Options:
  --dry-run     show what would happen without installing or starting
  --help, -h    show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
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
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P || true)"
  local maybe_root
  maybe_root="$(cd "$script_dir/../.." >/dev/null 2>&1 && pwd -P || true)"
  if [ -n "$maybe_root" ] && [ -f "$maybe_root/Cargo.toml" ] && [ -d "$maybe_root/scripts/setup" ]; then
    printf '%s\n' "$maybe_root"
  fi
}

prepare_repo() {
  local local_root
  local_root="$(repo_root_from_script)"
  if [ -n "$local_root" ]; then
    INSTALL_DIR="$local_root"
    return 0
  fi

  if [ -d "$INSTALL_DIR/.git" ]; then
    say "Updating FreeQ..."
    git -C "$INSTALL_DIR" fetch --all --prune
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" pull --ff-only
    return 0
  fi

  say "Downloading FreeQ..."
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
}

print_plan() {
  cat <<EOF
FreeQ macOS installer

What this does:
  1. Downloads or updates FreeQ.
  2. Builds FreeQ.
  3. Creates this Mac's local node identity.
  4. Starts FreeQ in local listen mode.
  5. Checks that the local FreeQ status API responds.

Install folder:
  $INSTALL_DIR

Visible setup folder:
  $SETUP_DIR

FreeQ may ask for this Mac's local admin password so it can open the network
interface. It never asks for another person's password.
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

if [ "$(uname -s)" != "Darwin" ]; then
  fail "This installer is for macOS. Linux support is being added separately."
fi

LOCAL_REPO_ROOT="$(repo_root_from_script)"
if [ -n "$LOCAL_REPO_ROOT" ] && [ -z "${FREEQ_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$LOCAL_REPO_ROOT"
fi

print_plan

if [ "$DRY_RUN" -eq 1 ]; then
  say ""
  say "Dry run only. Nothing was installed or started."
  exit 0
fi

if ! need git; then
  say ""
  say "Git is required. macOS can install it with:"
  say "  xcode-select --install"
  xcode-select --install >/dev/null 2>&1 || true
  fail "After the Apple installer finishes, run the FreeQ installer again."
fi

if ! need curl; then
  fail "curl is required but was not found on this Mac."
fi

prepare_repo
cd "$INSTALL_DIR"

say ""
say "Installing FreeQ..."
FREEQ_ASSUME_DEFAULTS=1 \
FREEQ_INSTALL_DIR="$INSTALL_DIR" \
FREEQ_SETUP_DIR="$SETUP_DIR" \
  scripts/setup/freeq-setup-macos.sh

say ""
say "Starting FreeQ..."
scripts/setup/freeq-render-config.sh --listen-only --output "$CONFIG" >/dev/null
scripts/setup/freeq-start-macos.sh --restart --no-interface --config "$CONFIG"

say ""
say "Checking FreeQ..."
if ! check_status; then
  fail "FreeQ started, but the local status check did not respond yet."
fi

say ""
say "FreeQ install result: PASS"
say "FreeQ is installed and running on this Mac."
say ""
say "You are done."
