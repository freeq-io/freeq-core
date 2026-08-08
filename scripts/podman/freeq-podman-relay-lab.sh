#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UBI_IMAGE="${FREEQ_PODMAN_UBI_IMAGE:-registry.access.redhat.com/ubi9/ubi:latest}"
RUST_IMAGE="${FREEQ_PODMAN_RUST_IMAGE:-docker.io/library/rust:1.88-bookworm}"
CONTAINER_WORKDIR="/work/freeq-core"

usage() {
  cat <<'EOF'
FreeQ Podman relay lab

Runs local container checks so relay work can be validated before asking a
remote person to help with a field test.

Usage:
  scripts/podman/freeq-podman-relay-lab.sh [--preflight] [--relay-runtime] [--all]

Options:
  --preflight       Run Linux installer preflight in a UBI/RHEL-family image.
  --relay-runtime   Run the in-memory gateway relay runtime test in a Rust image.
  --all             Run preflight and relay-runtime tiers.
  --help, -h        Show this help.

Environment:
  FREEQ_PODMAN_UBI_IMAGE     UBI/RHEL-family image for preflight.
  FREEQ_PODMAN_RUST_IMAGE    Rust image for relay runtime tests.

Notes:
  - This lab does not require David's machine.
  - The relay-runtime tier proves gateway forwarding semantics without TUN.
  - Full kernel TUN/routing acceptance remains a separate privileged Linux lab.
EOF
}

run_preflight=false
run_relay_runtime=false

if [ "$#" -eq 0 ]; then
  run_preflight=true
  run_relay_runtime=true
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --preflight)
      run_preflight=true
      shift
      ;;
    --relay-runtime)
      run_relay_runtime=true
      shift
      ;;
    --all)
      run_preflight=true
      run_relay_runtime=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required for this lab." >&2
  exit 1
fi

echo "FreeQ Podman relay lab"
echo "  repo:       $ROOT"
echo "  UBI image:  $UBI_IMAGE"
echo "  Rust image: $RUST_IMAGE"
echo

if [ "$run_preflight" = true ]; then
  echo "== tier 1: Linux installer preflight =="
  podman run --rm \
    --volume "$ROOT:$CONTAINER_WORKDIR:ro" \
    --workdir "$CONTAINER_WORKDIR" \
    "$UBI_IMAGE" \
    bash -lc 'set -euo pipefail; scripts/install/freeq-install-linux.sh --dry-run'
  echo
fi

if [ "$run_relay_runtime" = true ]; then
  echo "== tier 2: gateway relay runtime semantics =="
  podman run --rm \
    --volume "$ROOT:$CONTAINER_WORKDIR:Z" \
    --workdir "$CONTAINER_WORKDIR" \
    -e CARGO_HOME=/work/freeq-core/target/podman-cargo-home \
    -e CARGO_TARGET_DIR=/work/freeq-core/target/podman-target \
    "$RUST_IMAGE" \
    bash -c '
      set -euo pipefail
      export PATH="/usr/local/cargo/bin:$PATH"
      rustc --version
      cargo --version
      cargo test -p freeqd dataplane_runtime_relays_packet_between_gateway_peers -- --nocapture
    '
  echo
fi

echo "FreeQ Podman relay lab complete."
