# Linux Install Code Mill Brief

Status: read-only alpha preflight and static-readiness scaffold only.

This brief defines a safe SLM/code-mill slice for Linux installation work. It
does not establish Linux workstation or gateway installation as working.

## Current Inventory

- The macOS setup, gateway, status, and stop flow is the active field-tested
  path.
- `deploy/ansible/` contains Linux deployment scaffolding for the `freeqd`
  role, including a hardened service template and configuration defaults.
- `scripts/test-linux-deploy.sh` validates the Ansible role contract statically
  and optionally runs an Ansible syntax check when Ansible is installed.
- Linux workstation installation is planned/stubbed; there is no validated
  end-user Linux installer in this repository.
- `scripts/install/freeq-install-linux.sh` is a read-only alpha preflight. It
  reports host facts and planned next steps, but it does not install packages,
  change services, or change host networking.
- `scripts/test-linux-install-flow.sh` validates the preflight's shell syntax,
  static command guardrails, fake-host inspection path, and explicit `--apply`
  refusal.
- Linux gateway installation is planned/stubbed; Ansible scaffolding is not a
  substitute for a supported package, service, or rollback workflow.

## Read-Only Distro Matrix

This matrix is fixture coverage for the alpha preflight only. It is not a
support statement, package implementation, or gateway installation path.

| Fixture | Reported ID | Normalized family | Status |
| --- | --- | --- | --- |
| Ubuntu/Debian-like | `ubuntu` | `debian` | planned/stubbed, read-only |
| Fedora/RHEL-like | `fedora` | `rhel` | planned/stubbed, read-only |
| Alpine | `alpine` | `alpine` | planned/stubbed, read-only |
| Arch | `arch` | `arch` | planned/stubbed, read-only |
| Unknown/minimal | `unknown` | `unknown` | planned/stubbed, read-only |

The fixtures live under `scripts/fixtures/linux-os-release/` and are consumed
by `scripts/test-linux-install-flow.sh`. A real Linux host still receives only
inspection output; `--apply` remains refused.

## Alpha Command Contract

Future Linux implementations should align with the existing user vocabulary:

```text
freeq setup
freeq gateway status
freeq gateway
freeq status
freeq stop
```

Package lifecycle remains separate from the FreeQ lifecycle. The intended
package-manager shape is:

```text
brew install freeq
brew upgrade freeq
brew uninstall freeq
```

Native Linux packages, containers, and cloud images may add platform-specific
installation wrappers later, but they should preserve the same FreeQ commands.

## SLM-Appropriate Slices

An SLM/code-mill run may prepare only low-risk, reviewable artifacts:

1. Inventory current Linux files, package formats, service assumptions, and
   documented gaps.
2. Maintain a distro matrix for Debian/Ubuntu, Fedora/RHEL-family, Arch,
   Alpine, and Homebrew-on-Linux without claiming support.
3. Draft a dry-run-only Linux installer contract that reports detected host
   facts and planned dependencies without installing or changing anything.
4. Draft a read-only Linux doctor/status checklist that inspects files and
   capabilities without changing routes, services, DNS, DHCP, or TUN state.
5. Add static tests using fixtures or fake command paths. Tests must not invoke
   `sudo`, `systemctl`, `ip route`, NetworkManager mutation, or a real TUN
   device.
6. Keep user and operator documentation synchronized across Core and Cloud.

Every generated script must default to inspection or dry-run behavior. Any
future apply mode requires main-engineer implementation and security review.

## Main-Engineer-Only Boundaries

The SLM/code mill must not edit or generate changes to:

- Rust source, Cargo manifests, daemon behavior, crypto, or API semantics.
- TUN/dataplane code, packet handling, or tunnel lifecycle behavior.
- Route, firewall, DNS, DHCP, NetworkManager, netplan, or adapter mutation.
- `sudo` flows, privilege escalation, capability grants, or host networking.
- systemd unit behavior, enable/start/stop actions, service installation, or
  boot-time behavior.
- Rollback ledger semantics or any claim that normal networking is restored.

The main engineer owns the eventual implementation, security review, and real
Linux acceptance testing on representative workstation and gateway hosts.

## Acceptance For This Run

- Only Markdown, the read-only Linux preflight, and static test scaffolding are
  changed.
- No Rust, Cargo, daemon, TUN, route, systemd, or privileged-networking files
  are modified.
- Documentation says explicitly that Linux install is not yet working.
- The Linux preflight defaults to read-only inspection and does not claim that
  it installed FreeQ.
- `--apply` refuses with a main-engineer review message and makes no changes.
- The existing `scripts/test-linux-deploy.sh` remains the static Ansible
  contract check.
- The command vocabulary remains compatible with `freeq setup`,
  `freeq gateway status`, `freeq gateway`, `freeq status`, and `freeq stop`.

## Open Questions

- Is Homebrew-on-Linux the first supported workstation path, or should a
  signed `.deb` be the first Linux user-facing package?
- Which Linux gateway environments are release targets: systemd hosts only,
  containers, or both?
- Which network manager and DHCP implementations must the main-engineer-owned
  rollback design support in the first Linux alpha?
- What real-host acceptance matrix is required before Linux moves from
  planned/stubbed to supported?
