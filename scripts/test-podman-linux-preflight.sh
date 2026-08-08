#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${FREEQ_PODMAN_IMAGE:-docker.io/library/ubuntu:24.04}"
CONTAINER_WORKDIR="/work/freeq-core"

usage() {
  cat <<'EOF'
FreeQ Podman Linux preflight

Runs the read-only Linux installer preflight inside a container image.
This is useful for distro-family checks; it does not boot a full VM or
exercise real host networking.

Examples:
  scripts/test-podman-linux-preflight.sh
  FREEQ_PODMAN_IMAGE=registry.access.redhat.com/ubi9/ubi scripts/test-podman-linux-preflight.sh
  FREEQ_PODMAN_IMAGE=registry.access.redhat.com/ubi10/ubi scripts/test-podman-linux-preflight.sh

Notes:
  - RHEL installer ISO files are VM media, not Podman container images.
  - Use UBI/RHEL container images for container preflight.
  - Use a VM for full RHEL host, kernel, systemd, TUN, and routing tests.
EOF
}

case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    echo "Unknown argument: $1" >&2
    usage >&2
    exit 1
    ;;
esac

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required for this test." >&2
  exit 1
fi

echo "FreeQ Podman Linux preflight"
echo "  image: $IMAGE"
echo "  repo:  $ROOT"
echo

podman run --rm \
  --volume "$ROOT:$CONTAINER_WORKDIR:ro" \
  --workdir "$CONTAINER_WORKDIR" \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    echo "== container =="
    uname -a
    cat /etc/os-release || true
    echo
    echo "== FreeQ Linux installer preflight =="
    scripts/install/freeq-install-linux.sh --dry-run
  '
