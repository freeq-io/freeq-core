#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${FREEQ_REPO_URL:-https://github.com/freeq-io/freeq-core.git}"
BRANCH="${FREEQ_BRANCH:-main}"
INSTALL_DIR="${FREEQ_INSTALL_DIR:-$HOME/freeq-core}"
SETUP_DIR="${FREEQ_SETUP_DIR:-$HOME/FreeQ}"
CONFIG="${FREEQ_CONFIG:-$HOME/.freeq/perf/freeq.toml}"
LOG_FILE="${FREEQ_PERF_DIR:-$HOME/.freeq/perf}/freeqd.log"
SETUP_URL="${FREEQ_SETUP_URL:-http://127.0.0.1:6789/}"
DRY_RUN=0
ROLLBACK=0
UPDATE_STATUS="not checked"
CURRENT_REV=""
UPDATED_REV=""

usage() {
  cat <<'EOF'
FreeQ macOS installer.

This installer prepares or updates FreeQ, starts the local node, and prints one result.
Rerun the same command any time to update local docs, scripts, and binaries.

Options:
  --dry-run      show what would happen without installing or starting
  --rollback     stop FreeQ and return this Mac to normal networking
  --help, -h     show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
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

git_rev() {
  git -C "$1" rev-parse --short HEAD 2>/dev/null || true
}

prepare_repo() {
  local local_root
  local_root="$(repo_root_from_script)"
  if [ -n "$local_root" ]; then
    INSTALL_DIR="$local_root"
    UPDATE_STATUS="running from local checkout"
    CURRENT_REV="$(git_rev "$INSTALL_DIR")"
    UPDATED_REV="$CURRENT_REV"
    return 0
  fi

  if [ -d "$INSTALL_DIR/.git" ]; then
    say "Updating FreeQ..."
    CURRENT_REV="$(git_rev "$INSTALL_DIR")"
    git -C "$INSTALL_DIR" fetch --all --prune
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" pull --ff-only
    UPDATED_REV="$(git_rev "$INSTALL_DIR")"
    if [ -n "$CURRENT_REV" ] && [ "$CURRENT_REV" = "$UPDATED_REV" ]; then
      UPDATE_STATUS="already current"
    else
      UPDATE_STATUS="updated"
    fi
    return 0
  fi

  say "Downloading FreeQ..."
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  UPDATED_REV="$(git_rev "$INSTALL_DIR")"
  UPDATE_STATUS="installed"
}

print_plan() {
  cat <<EOF
FreeQ macOS installer

What this does:
  1. Downloads or updates FreeQ docs, scripts, and source.
  2. Reports whether an update was applied.
  3. Builds FreeQ.
  4. Creates this Mac's local node identity.
  5. Starts FreeQ in local listen mode.
  6. Opens the local FreeQ setup page and checks that FreeQ responds.

Install folder:
  $INSTALL_DIR

Visible setup folder:
  $SETUP_DIR

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

Install folder:
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
  if [ ! -x "$INSTALL_DIR/scripts/setup/freeq-stop-macos.sh" ]; then
    fail "FreeQ rollback helper is missing. Rerun the installer without --rollback to update FreeQ first."
  fi
  cd "$INSTALL_DIR"
  scripts/setup/freeq-stop-macos.sh --renew-dhcp
}

if [ "$(uname -s)" != "Darwin" ]; then
  fail "This installer is for macOS. Linux support is being added separately."
fi

LOCAL_REPO_ROOT="$(repo_root_from_script)"
if [ -n "$LOCAL_REPO_ROOT" ] && [ -z "${FREEQ_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$LOCAL_REPO_ROOT"
fi

if [ "$ROLLBACK" -eq 1 ]; then
  print_rollback_plan
else
  print_plan
fi

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

if [ "$ROLLBACK" -eq 1 ]; then
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
say "FreeQ update status: $UPDATE_STATUS"
if [ -n "$CURRENT_REV" ] || [ -n "$UPDATED_REV" ]; then
  say "Revision before: ${CURRENT_REV:-none}"
  say "Revision now:    ${UPDATED_REV:-unknown}"
fi

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

open "$SETUP_URL" >/dev/null 2>&1 || true

say ""
say "FreeQ install result: PASS"
say "FreeQ is installed and running on this Mac."
say "Update status: $UPDATE_STATUS"
say "Setup page:"
say "  $SETUP_URL"
say "Rollback command:"
say "  freeq stop"
say ""
say "You are done."
