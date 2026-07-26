# FreeQ Podman Relay Lab

Status: supported local development harness

The Podman relay lab lets one developer exercise the Linux and relay-regression
path before asking a remote field-test partner to help.

This exists because a real FreeQ relay must work for nodes that cannot accept
inbound traffic. Starlink residential, hotel Wi-Fi, LTE, airport Wi-Fi, coffee
shops, and CGNAT networks are exactly why the relay lane exists.

## What This Lab Proves

The lab has two tiers.

Tier 1 runs the Linux installer preflight inside a UBI/RHEL-family container.
It checks distro detection and confirms the current Linux installer path remains
read-only until the Linux host installer is fully supported.

Tier 2 runs the in-memory gateway relay runtime test inside a Linux Rust
container. It proves the important relay rule:

```text
Patrick leaf --outbound only--> gateway relay <--outbound only-- David leaf
```

The gateway must forward between authenticated active sessions. It must not
dial back into a CGNAT leaf.

## What This Lab Does Not Prove Yet

Podman on macOS is not the same thing as a full Linux host acceptance test.
This lab does not yet prove:

- privileged `/dev/net/tun` operation
- Linux route mutation and rollback
- NetworkManager, systemd-networkd, netplan, or distro DHCP behavior
- real multi-container packet forwarding through kernel TUN interfaces

Those belong in the next privileged Linux lab tier.

## Run The Lab

From the `freeq-core` repo:

```bash
scripts/podman/freeq-podman-relay-lab.sh --all
```

Run only the Linux installer preflight:

```bash
scripts/podman/freeq-podman-relay-lab.sh --preflight
```

Run only the relay runtime proof:

```bash
scripts/podman/freeq-podman-relay-lab.sh --relay-runtime
```

The default images are:

```text
FREEQ_PODMAN_UBI_IMAGE=registry.access.redhat.com/ubi9/ubi:latest
FREEQ_PODMAN_RUST_IMAGE=docker.io/library/rust:1.88-bookworm
```

Override them if needed:

```bash
FREEQ_PODMAN_RUST_IMAGE=docker.io/library/rust:1.88-bookworm \
  scripts/podman/freeq-podman-relay-lab.sh --relay-runtime
```

## Acceptance Rule

Do not ask a remote field-test partner to rerun gateway tests until this local
lab passes and the privileged Linux lab either passes or has a clearly scoped
known limitation.

David-style field testing should be reserved for final validation:

```text
Spain unknown network -> AWS gateway <- Florida Starlink/CGNAT
```

The local lab is where relay semantics and Linux support should break first.
