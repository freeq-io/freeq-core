# FreeQ Ansible Deployment Layer

This directory contains a first-party Ansible layer for provisioning and
managing `freeqd` on Linux hosts, especially RHEL-style environments where
systemd, TUN interfaces, and host-level network tuning matter.

This layer is intentionally host-focused:

- install or refresh the `freeqd` binary
- template `/etc/freeq/freeq.toml`
- install and manage a hardened systemd unit
- create service users and directories
- optionally build the local binary before deployment
- health-check the local REST API after startup

It does not try to become the long-term network control plane. That belongs in
`freeq-cloud` or a custom management layer.

## Layout

```text
deploy/ansible/
├── ansible.cfg
├── inventories/
│   └── example/
│       └── hosts.yml
├── playbooks/
│   └── site.yml
└── roles/
    └── freeqd/
        ├── defaults/main.yml
        ├── handlers/main.yml
        ├── tasks/main.yml
        └── templates/
            ├── freeq.toml.j2
            └── freeqd.service.j2
```

## Expectations

- Controller runs Ansible from this repository checkout.
- Target hosts run Linux with systemd.
- A release build of `freeqd` exists locally, or you enable local build.
- Current daemon startup is still limited by the unfinished authenticated
  session key negotiation path, so the service is expected to run in the
  current degraded/status-serving mode until that path is completed.

## Quick Start

Build the daemon locally:

```bash
cargo build --release -p freeqd
```

Change into the Ansible directory so `ansible.cfg` is picked up automatically:

```bash
cd deploy/ansible
```

Edit the example inventory in
[inventories/example/hosts.yml](/Users/patrickmccormick/Documents/FreeQ/freeq-core/deploy/ansible/inventories/example/hosts.yml)
with real hosts, node addresses, and peer keys.

Dry-run:

```bash
ansible-playbook playbooks/site.yml --check
```

Deploy:

```bash
ansible-playbook playbooks/site.yml
```

Build locally as part of the play:

```bash
ansible-playbook playbooks/site.yml -e freeq_build_local_binary=true
```

## macOS Local Validation

For local MacBook validation, use the dedicated loopback playbook instead of
the Linux/systemd deployment role:

```bash
cd deploy/ansible
ansible-playbook -i inventories/local/hosts.yml playbooks/macos-local-test.yml
```

This playbook:

- builds the local Rust workspace components needed by `freeqd`
- runs the crypto security regression tests
- runs the daemon loopback dataplane test that emulates node-to-node traffic
  over real local QUIC sockets
- renders a temporary single-node config under `/private/tmp`
- starts `freeqd` in the foreground long enough to verify `/v1/status`

If Homebrew Ansible fails before running tasks with `Local RPC server did not
start`, the installed Ansible controller is unhealthy. The FreeQ commands can
still be validated directly:

```bash
cargo build -p freeqd -p freeq -p freeq-auth -p freeq-transport -p freeq-tunnel
cargo test -p freeq-crypto --test security_audits
cargo test -p freeqd --bin freeqd tests::dataplane_runtime_forwards_packet_over_real_quic_transport -- --nocapture
```

## Important Variables

- `freeq_binary_src`: local path to the `freeqd` binary copied to the target
- `freeq_build_local_binary`: build `freeqd` locally before copying it
- `freeq_node_name`: node name written into `freeq.toml`
- `freeq_node_address`: required overlay address/prefix
- `freeq_peers`: list of peer dictionaries matching the daemon config schema
- `freeq_api_enabled`: whether the local REST API is enabled
- `freeq_manage_sysctl`: whether to apply the optional sysctl profile
- `freeq_sysctl`: sysctl map applied when `freeq_manage_sysctl` is true

## Security / Ops Notes

- The service runs as a dedicated `freeq` user by default.
- systemd grants `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`.
- The role creates `/etc/freeq`, `/var/lib/freeq`, and `/var/log/freeq`.
- The health check calls `GET /v1/status` on the local API after restart.
- Peer public keys and KEM keys stay in inventory or a vaulted variable file,
  not in the role itself.
