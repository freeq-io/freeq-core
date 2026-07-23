#!/usr/bin/env bash
set -euo pipefail

OS_RELEASE_FILE="${FREEQ_LINUX_OS_RELEASE:-/etc/os-release}"
TUN_PATH="${FREEQ_LINUX_TUN_PATH:-/dev/net/tun}"

usage() {
  cat <<'EOF'
FreeQ Linux install preflight (alpha)

This command is read-only. It inspects the host and prints planned next steps.
Linux installation is planned/stubbed and is not supported yet.

Options:
  --dry-run      explicit read-only inspection (the default)
  --apply        refuse; live installation is not implemented
  --help, -h     show this help
EOF
}

MODE="inspect"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) MODE="inspect"; shift ;;
    --apply) MODE="refuse"; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ "$MODE" = "refuse" ]; then
  echo "Linux installation --apply is not implemented pending main-engineer review."
  echo "No changes were made. No privileged or networking commands were run."
  exit 2
fi

has_command() {
  command -v "$1" >/dev/null 2>&1
}

command_state() {
  if has_command "$1"; then
    printf 'present'
  else
    printf 'missing'
  fi
}

OS_ID="unknown"
OS_LIKE=""
if [ -r "$OS_RELEASE_FILE" ]; then
  OS_ID="$(awk -F= '$1 == "ID" {gsub(/^"|"$/, "", $2); print $2; exit}' "$OS_RELEASE_FILE")"
  OS_LIKE="$(awk -F= '$1 == "ID_LIKE" {gsub(/^"|"$/, "", $2); print $2; exit}' "$OS_RELEASE_FILE")"
  OS_ID="${OS_ID:-unknown}"
fi

DISTRO_FAMILY="unknown"
case "$OS_ID" in
  ubuntu|debian|linuxmint|elementary|pop)
    DISTRO_FAMILY="debian"
    ;;
  fedora|rhel|centos|rocky|almalinux|ol|amzn)
    DISTRO_FAMILY="rhel"
    ;;
  alpine)
    DISTRO_FAMILY="alpine"
    ;;
  arch|manjaro|endeavouros)
    DISTRO_FAMILY="arch"
    ;;
  *)
    case " $OS_LIKE " in
      *" debian "*|*" ubuntu "*) DISTRO_FAMILY="debian" ;;
      *" fedora "*|*" rhel "*|*" centos "*) DISTRO_FAMILY="rhel" ;;
      *" arch "*) DISTRO_FAMILY="arch" ;;
    esac
    ;;
esac

ARCH="$(uname -m)"
KERNEL="$(uname -s)"

printf '%s\n' "FreeQ Linux install preflight (alpha)"
printf '%s\n' "  Mode: read-only inspection"
printf '%s\n' "  Linux install status: planned/stubbed (not supported)"
printf '%s\n' "  Kernel: $KERNEL"
printf '%s\n' "  Architecture: $ARCH"
printf '%s\n' "  Distribution ID: $OS_ID"
printf '%s\n' "  Distribution family: $DISTRO_FAMILY"
printf '%s\n' ""

printf '%s\n' "Detected prerequisites:"
printf '  %-16s %s\n' "cargo" "$(command_state cargo)"
printf '  %-16s %s\n' "rustc" "$(command_state rustc)"
printf '  %-16s %s\n' "iproute2/ip" "$(command_state ip)"
printf '  %-16s %s\n' "systemd" "$(command_state systemctl)"
printf '  %-16s %s\n' "Homebrew" "$(command_state brew)"
printf '  %-16s %s\n' "apt-get" "$(command_state apt-get)"
printf '  %-16s %s\n' "dnf" "$(command_state dnf)"
printf '  %-16s %s\n' "yum" "$(command_state yum)"
printf '  %-16s %s\n' "pacman" "$(command_state pacman)"
printf '  %-16s %s\n' "apk" "$(command_state apk)"
if [ -e "$TUN_PATH" ]; then
  TUN_STATE="present"
else
  TUN_STATE="missing"
fi
printf '  %-16s %s\n' "/dev/net/tun" "$TUN_STATE"
printf '%s\n' ""

printf '%s\n' "Planned next steps (not executed):"
printf '%s\n' "  1. Main engineer selects and reviews the Linux package/service path."
printf '%s\n' "  2. Main engineer implements and tests rollback for the target network stack."
printf '%s\n' "  3. A signed package and real-host acceptance matrix are added."
printf '%s\n' ""
printf '%s\n' "No packages were installed. No services were changed. No host networking was changed."
printf '%s\n' "Preflight result: PASS (inspection only)"
