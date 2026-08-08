# Linux Support Acceptance

<!-- FREEQ_LINUX_SUPPORT_STATUS: preflight -->

Current status: **preflight available; Linux installation and rollback are not
supported yet**.

This document is the release gate for changing the public Linux status. A
fixture-driven shell test is useful for preventing regressions, but it is not
evidence that FreeQ works on a real Linux host. The status marker above may be
changed to `supported` only in the same change that includes the completed
evidence below and passes the public-status harness.

## Required Evidence

| Area | Required host or artifact | Acceptance evidence | Status |
| --- | --- | --- | --- |
| Debian-family workstation | Clean supported Ubuntu LTS and Debian stable hosts | Install, setup, gateway status, gateway connect, status, stop, and package uninstall logs | Not run |
| Fedora/RHEL-family workstation | Clean Fedora and one RHEL-compatible host | Install, setup, gateway status, gateway connect, status, stop, and package uninstall logs | Not run |
| Linux gateway | At least one real systemd server host | Non-interactive install, boot start, health/status, gateway operation, upgrade, stop, and uninstall logs | Not run |
| Homebrew-on-Linux workstation | Clean Linux host with Homebrew | Tap install, upgrade, uninstall, formula test, and the full FreeQ lifecycle | Not run |
| Rollback | Each supported network stack used above | `freeq stop` stops only FreeQ-owned processes, removes only FreeQ-owned state, restores normal networking, and reports failures clearly | Not run |
| Captive or restricted network | At least one field or equivalent controlled test | Gateway path works and rollback leaves ordinary network access usable | Not run |
| Documentation and package | Release artifacts and public docs | Versioned package, checksum/signature policy, upgrade path, uninstall path, and matching user instructions | Not run |

## Lifecycle Contract

Every supported Linux workstation and gateway must make these commands
available, with platform-specific service details documented separately:

```text
freeq setup
freeq gateway status
freeq gateway
freeq status
freeq stop
```

`freeq stop` is the acceptance boundary. It must restore the network state that
FreeQ recorded before startup, remove only state owned by FreeQ, stop only the
FreeQ daemon it started, and leave enough diagnostics to resolve a failed
rollback. A successful daemon stop alone is not sufficient.

## Test Boundaries

The repository can run these checks without Linux, `sudo`, `systemctl`, package
managers, or live networking:

- shell syntax and static command guardrails
- fake `/etc/os-release` distro classification
- installer read-only behavior and explicit `--apply` refusal
- public documentation status-language checks
- static Ansible role contract checks

Those checks do not prove that Linux is supported. The real-host matrix above
must be completed by the main engineer and recorded with reproducible command
output before changing the status marker.

## Release Procedure

1. Implement the Linux package and service path under main-engineer ownership.
2. Implement and security-review Linux route, TUN, privilege, and rollback
   behavior.
3. Run the real-host matrix on clean machines and retain the logs, versions,
   distro details, and network-manager details.
4. Add or update package tests and non-mutating CI checks.
5. Update user-facing docs and website source together.
6. Change `FREEQ_LINUX_SUPPORT_STATUS` to `supported` only after all rows pass.
7. Run the full repository checks and review the resulting public claims.

Until then, use the read-only preflight:

```bash
scripts/install/freeq-install-linux.sh
```

It reports host facts and planned work. It does not install packages, change
services, mutate routes, touch DHCP, or configure a TUN device.
