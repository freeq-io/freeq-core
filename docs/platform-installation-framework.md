# FreeQ Platform Installation Framework

## Decision

FreeQ should use one command contract across platforms, with platform-specific
installers underneath it.

The user-facing lifecycle should stay consistent:

```bash
freeq setup
freeq gateway
freeq gateway status
freeq stop
freeq status
freeq doctor
```

Package managers own install, update, and uninstall:

```bash
brew install freeq
brew upgrade freeq
brew uninstall freeq
```

Equivalent package-manager commands should be added per platform without
changing the FreeQ command vocabulary.

## Guiding Principles

- One CLI contract across all endpoint and gateway platforms.
- One rollback contract: stopping FreeQ restores normal networking.
- Package managers own package lifecycle; FreeQ does not self-update package
  manager installs.
- Gateway installs must be non-interactive and service-friendly.
- Workstation installs may be interactive, but rollback must be reliable.
- Cloud installs should use infrastructure and container workflows, not
  workstation package managers.
- Platform support can be stubbed early, but each stub must name the intended
  package format, service manager, networking API, and acceptance tests.

## Platform Matrix

| Target | Primary installer | Service model | Status |
| --- | --- | --- | --- |
| macOS workstation | Homebrew formula | Script-started alpha, launchd later | Active |
| Linux workstation | Homebrew formula first, native packages later | systemd user/system service later | Planned |
| Linux gateway/server | `.deb`/`.rpm` plus container images | systemd | Stub |
| macOS gateway/field relay | Homebrew for lab use, `.pkg` if enterprise managed | launchd | Stub |
| Windows workstation | MSI plus winget | Windows Service | Stub |
| Windows gateway/server | MSI plus enterprise deployment | Windows Service | Stub |
| Containers | OCI image | container runtime or Kubernetes | Stub |
| Cloud managed gateway | image, Terraform, or orchestration bundle | cloud init/systemd/container | Stub |
| Enterprise fleet | MDM/Jamf/Intune/SCCM wrapping native packages | platform service manager | Stub |

## Workstation Path

Homebrew is the best first workstation installer for supported macOS and Linux
targets because many early users already understand:

```bash
brew install freeq
brew upgrade freeq
brew uninstall freeq
```

During alpha:

```bash
brew install freeq-io/tap/freeq
```

Later:

```bash
brew install freeq
```

The workstation flow remains:

```bash
freeq setup
freeq gateway
freeq gateway status
freeq stop
freeq status
```

Workstation rollback must handle captive Wi-Fi, DHCP renewal, stale routes,
daemon cleanup, and clear PASS/FAIL reporting.

## Gateway Path

Homebrew is viable for lab gateways, developer gateways, and early Linux gateway
testing. It is not the final answer for every production gateway.

Production gateways need non-interactive, service-native installation:

- Linux gateways should support `.deb` and `.rpm` packages with systemd units.
- Cloud gateways should support machine images, cloud-init, Terraform, or
  container deployment.
- Container gateways should make required privileges explicit, especially TUN
  device access, route mutation, and host networking.
- Enterprise gateways should support MDM, Intune, SCCM, Jamf, or deployment
  tooling by wrapping signed native packages.

The gateway command contract should remain recognizable:

```bash
freeq gateway
freeq gateway status
freeq status
freeq doctor
freeq stop
```

Gateway service commands can be added later, but should stay consistent:

```bash
freeq service install
freeq service start
freeq service stop
freeq service status
```

## Windows Path

Windows should be stubbed now and implemented intentionally.

Recommended path:

- MSI for signed enterprise install and uninstall.
- winget for public package-manager install.
- Windows Service for long-running daemon mode.
- PowerShell-backed rollback and diagnostics.
- Windows networking APIs for routes, adapters, DNS, and DHCP state.
- WSL Homebrew may be useful for development, but it should not be treated as
  the real Windows endpoint networking implementation.

Target lifecycle:

```powershell
winget install FreeQ.FreeQ
freeq setup
freeq gateway
freeq stop
freeq status
freeq doctor
winget upgrade FreeQ.FreeQ
```

Windows acceptance tests must verify that `freeq stop` removes FreeQ-owned
routes, stops the FreeQ service, and restores normal networking without
requiring Device Manager or manual adapter cleanup.

## Linux Native Package Path

Linux native packages should be added after the Homebrew Linux path proves the
CLI and rollback contract.

Recommended package order:

1. `.deb` for Debian and Ubuntu gateways/workstations.
2. `.rpm` for Fedora, RHEL, Rocky, AlmaLinux, and Amazon Linux.
3. Nix package for reproducible environments.
4. `apk` only if Alpine gateways become important.

Linux implementation must detect and support the host's network manager path:

- `iproute2` for route inspection and mutation.
- NetworkManager where present.
- systemd-networkd where present.
- netplan where present.
- distro-specific DHCP renewal only through controlled platform helpers.

The package should install systemd units only when the selected install mode
requires service operation.

## Container And Cloud Path

Containers are appropriate for relay, rendezvous, scanner, cloud agent, and
gateway deployments where the host privileges are explicit.

Containers are not a replacement for the workstation endpoint installer.

Container acceptance criteria:

- Image has pinned FreeQ version metadata.
- Required Linux capabilities are documented.
- TUN device requirements are documented.
- Host networking requirements are documented.
- Logs are structured.
- Health checks are present.
- Upgrade and rollback are documented.

Cloud-managed gateway acceptance criteria:

- Install is non-interactive.
- Enrollment material can be injected securely.
- Service starts on boot.
- Logs and health are observable.
- Rollback removes FreeQ-owned routes and service state.
- Reprovisioning produces a predictable result.

## Repo Ownership

FreeQ Core owns:

- The `freeq` CLI contract.
- Daemon packaging hooks.
- Platform rollback helpers.
- Local setup and gateway commands.
- Formula/package scripts that ship endpoint binaries.
- Tests that prove setup, gateway, stop, status, and doctor behavior.

FreeQ Cloud owns:

- Gateway and relay deployment patterns.
- Managed enrollment workflows.
- Cloud image and container deployment guidance.
- Enterprise rollout runbooks.
- Customer-facing operational guidance for managed gateways.
- Cross-repo release coordination.

Both repos should use this framework so customer instructions do not fork into
different product stories.

## Platform Stub Template

Every new platform lane should add a short design note with:

- Target users.
- Package format.
- Install command.
- Update command.
- Uninstall command.
- Service manager.
- Network state capture method.
- Route mutation method.
- DHCP or network refresh method.
- Rollback command.
- Diagnostics command.
- Automated acceptance tests.
- Manual field test checklist.

## Acceptance Criteria

A platform is considered supported only when:

- Install works from a clean machine.
- Update replaces binaries, scripts, docs, and service definitions correctly.
- Uninstall removes package-owned files.
- `freeq setup` is documented and tested.
- `freeq gateway` is documented and tested when relevant.
- `freeq stop` restores normal networking.
- `freeq status` reports useful state.
- `freeq doctor` gives PASS/FAIL results with one next action per failure.
- The service manager path is documented.
- Manual privileged cleanup is not part of normal user instructions.

## Recommended Sequence

1. Finish Homebrew tap for macOS and Linux workstation alpha.
2. Add `freeq doctor`.
3. Add Linux rollback helpers behind the same `freeq stop` command.
4. Add Linux gateway `.deb` package and systemd unit.
5. Add Linux gateway `.rpm` package and systemd unit.
6. Add OCI images for gateway, relay, and cloud components.
7. Add Windows design stub and test harness.
8. Add signed Windows MSI and winget package.
9. Add enterprise packaging wrappers after the native package paths stabilize.
