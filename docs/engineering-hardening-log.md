# FreeQ Engineering Hardening Log

This document records concrete implementation issues that were found during
build-out, the fixes applied in this repository, and the gaps that still
remain. It is written for engineers who want a compact map of what changed and
what still needs work.

## Scope

This log focuses on high-signal implementation problems that commonly show up
in fast-moving or AI-assisted code generation work:

- placeholder or incomplete cryptography
- transport sizing mistakes
- packet parsing and framing mistakes
- status surfaces that look real but are still stubbed
- runtime paths that exist only in tests or comments
- startup behavior that implies more completeness than actually exists

## Fixed

### 1. Placeholder bulk crypto was replaced with real AEAD implementations

Problem:

- Bulk packet encryption was not yet backed by real AES-256-GCM and
  ChaCha20-Poly1305 implementations.

Fix:

- Added working encrypt/decrypt paths in
  `crates/freeq-crypto/src/bulk.rs`
- Added round-trip tests for both algorithms

Files:

- `crates/freeq-crypto/src/bulk.rs`

### 2. Hybrid key derivation was hardened

Problem:

- Session key derivation needed explicit domain separation and cleaner handling
  of combined classical/post-quantum material.

Fix:

- Hardened KDF combination logic
- Improved session key derivation flow

Files:

- `crates/freeq-crypto/src/kdf.rs`

### 3. KEM fallback behavior was tightened

Problem:

- Hybrid KEM behavior needed safer selection/fallback handling.

Fix:

- Adjusted KEM handling to use constant-time-oriented fallback/selection logic

Files:

- `crates/freeq-crypto/src/kem.rs`

### 4. Test key material became explicit and erasable

Problem:

- Tunnel and benchmark paths needed a defined key container instead of ad hoc
  byte handling.

Fix:

- Added `FreeQKeyPair` with zeroization support and test-key generation

Files:

- `crates/freeq-crypto/src/types.rs`

### 5. Packet parsing was moved onto validated header parsing

Problem:

- Packet handling needed a real IPv4 parser instead of assuming aligned,
  already-valid input.

Fix:

- Added validated IPv4 header parsing
- Added tests for unaligned subslices

Files:

- `crates/freeq-tunnel/src/packet.rs`

### 6. Tunnel write path became a real pipeline

Problem:

- Tunnel packet handling existed more as a conceptual path than a reversible,
  testable pipeline.

Fix:

- Added `TunnelInterface` processing for:
  - MTU validation
  - IPv4 length validation
  - AEAD encryption
  - transport envelope construction
  - QUIC frame chunking
- Added reverse receive path for:
  - transport envelope parsing
  - AEAD decryption
  - plaintext validation

Files:

- `crates/freeq-tunnel/src/pipeline.rs`

### 7. AEAD associated data was corrected to be protocol-stable

Problem:

- Packet AEAD AAD was initially bound to the local interface name, which broke
  interoperability between peers with different host interface names.

Fix:

- Replaced interface-name-dependent AAD with a stable protocol context:
  `freeq-tunnel/v1`

Files:

- `crates/freeq-tunnel/src/pipeline.rs`

### 8. Transport framing became explicit and reversible

Problem:

- Encrypted packets were chunked, but the framing story was not explicit enough
  for real reassembly and receive-side validation.

Fix:

- Added transport frame headers with:
  - packet id
  - chunk index
  - chunk count
- Added `FrameReassembler`
- Added decode/round-trip tests

Files:

- `crates/freeq-transport/src/frame.rs`

### 9. QUIC datagram sizing was corrected conservatively

Problem:

- Using a 1200-byte application datagram target was too close to the actual
  QUIC transport boundary once framing overhead was included.

Fix:

- Reduced `SECURE_QUIC_MTU` to a conservative 1024-byte application payload cap
- Updated tests to reflect real framing overhead instead of one-frame
  assumptions

Files:

- `crates/freeq-transport/src/frame.rs`
- `crates/freeq-tunnel/src/pipeline.rs`
- `crates/freeq-tunnel/src/service.rs`

### 10. Service-level error accounting became explicit

Problem:

- Route misses and tunnel failures were not fully categorized for status and
  metrics.

Fix:

- Added counters for:
  - route misses
  - malformed packet errors
  - crypto errors
  - transport errors

Files:

- `crates/freeq-tunnel/src/service.rs`

### 11. API status and metrics stopped returning stubbed runtime data

Problem:

- The REST API exposed status-like surfaces that were not yet backed by shared
  daemon state.

Fix:

- Added shared `ApiState`
- Added runtime snapshot and error counters
- Wired `/v1/status`, `/v1/metrics`, and `/v1/tunnels` to shared state

Files:

- `crates/freeq-api/src/state.rs`
- `crates/freeq-api/src/handlers/status.rs`
- `crates/freeq-api/src/handlers/metrics.rs`
- `crates/freeq-api/src/handlers/tunnels.rs`
- `crates/freeq-api/src/models.rs`
- `crates/freeq-api/src/router.rs`
- `crates/freeq-api/src/server.rs`

### 12. Daemon startup now reflects real tunnel/API state

Problem:

- `freeqd` startup behavior described more runtime completeness than the daemon
  actually had.

Fix:

- Added tunnel service initialization
- Added API state initialization from real service counters
- Reduced startup blockers to remaining unimplemented subsystems only

Files:

- `daemon/src/main.rs`

### 13. A real transport-side dataplane loop now exists

Problem:

- The daemon had QUIC components and tunnel components, but not a verified
  end-to-end runtime path between them.

Fix:

- Added transport accept loop
- Added transport egress loop
- Added connection receive loop
- Added end-to-end QUIC dataplane test using real local sockets

Files:

- `daemon/src/main.rs`

### 14. Host TUN adapter layer was added

Problem:

- TUN was still effectively a placeholder at the OS boundary.

Fix:

- Added real macOS `utun` open/read/write support
- Exported `TunInterface` from `freeq-tunnel`
- Added daemon packet-I/O bridge abstraction so host TUN and in-memory test I/O
  share the same orchestration pattern

Files:

- `crates/freeq-tunnel/src/iface.rs`
- `crates/freeq-tunnel/src/lib.rs`
- `daemon/src/main.rs`

### 15. Soak/perf tooling became real and observable

Problem:

- Performance and reconnection behavior needed a repeatable harness rather than
  ad hoc local checks.

Fix:

- Added `tools/freeq-soak-test`
- Added chaos-mode reconnect/drop simulation
- Added CPU utilization reporting to perf output
- Added helper scripts for hooks and throughput testing

Files:

- `tools/freeq-soak-test/src/main.rs`
- `tools/freeq-soak-test/Cargo.toml`
- `scripts/bench-throughput.sh`
- `scripts/install-hooks.sh`
- `scripts/git-pre-commit.sh`

### 16. Host orchestration layer was added explicitly

Problem:

- Repo-level deployment assumptions were implicit.

Fix:

- Added an Ansible deployment layer for:
  - binary rollout
  - templated `freeq.toml`
  - systemd unit installation
  - service user creation
  - optional sysctl tuning
  - local API health checks

Files:

- `deploy/ansible/`

### 17. Linux TUN support was added to the host interface layer

Problem:

- The OS adapter layer only supported macOS `utun`, which blocked Linux-first
  deployment and testing paths.

Fix:

- Added Linux `/dev/net/tun` open/read/write support
- Kept Linux on the same nonblocking `AsyncFd` runtime pattern as macOS
- Added Linux-specific interface name handling and ignored host-open test hooks

Files:

- `crates/freeq-tunnel/src/iface.rs`

### 18. Application-layer cloaking was tightened

Problem:

- The responder mapped malformed or bad-signature init messages to explicit
  handshake failures even though unauthenticated traffic should be silent.
- The daemon recorded unauthenticated inbound probes as transport failures,
  which polluted telemetry and made scans look like operational errors.

Fix:

- Mapped malformed init messages, unknown fingerprints, and bad initiator
  signatures to `AuthError::Cloaked`
- Dropped cloaked inbound probes without API error records or warning logs
- Added regression coverage for malformed and tampered initiator messages

Files:

- `crates/freeq-auth/src/handshake.rs`
- `daemon/src/main.rs`

### 19. Invite pairing codes became independent of bundle nonce material

Problem:

- Invite bundles included a public nonce, and the displayed pairing code was
  derived from the first eight nonce characters.
- Anyone with the bundle could reconstruct the out-of-band pairing code, which
  weakened the intended two-channel invite flow.

Fix:

- Generate the displayed pairing code from independent random bytes
- Keep the bundle nonce public, but use it only as pairing-hash context
- Added regression coverage proving the code is uppercase hex, omitted from the
  bundle text, and not equal to the old nonce-derived value

Files:

- `crates/freeq-api/src/handlers/peers.rs`
- `crates/freeq-api/Cargo.toml`

### 20. Public status responses no longer expose raw daemon error detail

Problem:

- `/v1/status` returned the raw last daemon error string, which could include
  local paths, endpoint addresses, or other operational detail better kept in
  local logs.

Fix:

- Keep raw error detail in internal runtime snapshots for diagnostics
- Return only a bounded class summary through the public status handler
- Added tests for path and endpoint redaction

Files:

- `crates/freeq-api/src/handlers/status.rs`

### 21. Existing identity key permissions are checked before load

Problem:

- Newly generated identity keys were chmodded to `0600`, but existing key files
  were loaded without checking whether group or world permissions had drifted.

Fix:

- Added Unix permission validation before loading existing identity keys
- Fail closed when any group/world read, write, or execute bit is present
- Added a regression test for group-readable key rejection

Files:

- `daemon/src/main.rs`

### 22. Local API bind validation now fails closed by default

Problem:

- The local REST API was documented as loopback-only, but config validation only
  checked that `node.api_addr` was a syntactically valid socket address.
- A non-loopback bind such as `0.0.0.0:6789` could expose unauthenticated
  management routes outside the local machine.

Fix:

- Added `node.allow_unsafe_api_bind`, defaulting to `false`
- Reject non-loopback `node.api_addr` when the API is enabled unless that
  explicit unsafe flag is set
- Added tests for IPv4 loopback, IPv6 loopback, default rejection of
  non-loopback, and the explicit unsafe override

Files:

- `crates/freeq-config/src/node.rs`
- `crates/freeq-config/src/lib.rs`

### 23. Strict cloaking config now selects fail-closed endpoint binding

Problem:

- The transport crate already had a `StrictCloaked` bind mode that refuses a
  direct Quinn bind until pre-QUIC admission exists, but daemon startup always
  used the direct bind helper.

Fix:

- Added `node.strict_cloaking`, defaulting to `false`
- Wire daemon endpoint binding through `Endpoint::bind_with_mode`
- When `strict_cloaking` is true, startup selects `StrictCloaked` and therefore
  fails closed until the pre-QUIC admission gate exists
- Added daemon coverage for the bind-mode selection

Files:

- `crates/freeq-config/src/node.rs`
- `daemon/src/main.rs`

## Tests Added or Strengthened

The following areas now have direct test coverage that did not exist or was not
previously meaningful enough:

- bulk crypto round trips
- security audit regression checks
- IPv4 parsing from unaligned input
- tunnel pipeline encrypt/decrypt round trip
- transport frame decode/reassembly
- QUIC connection pool reuse
- real QUIC dataplane forwarding over local sockets
- daemon packet-I/O bridge behavior
- shared API state snapshot behavior
- status and metrics handler runtime reporting
- invite pairing-code independence from public bundle nonce
- status last-error redaction
- existing identity key permission rejection
- local API loopback bind enforcement
- strict cloaking fail-closed endpoint mode selection

Primary files:

- `crates/freeq-crypto/tests/security_audits.rs`
- `crates/freeq-transport/src/frame.rs`
- `crates/freeq-transport/src/pool.rs`
- `crates/freeq-tunnel/src/packet.rs`
- `crates/freeq-tunnel/src/pipeline.rs`
- `crates/freeq-tunnel/src/service.rs`
- `crates/freeq-api/src/state.rs`
- `crates/freeq-api/src/handlers/status.rs`
- `crates/freeq-api/src/handlers/metrics.rs`
- `daemon/src/main.rs`

## Still Incomplete

### 0. July 2026 node security audit produced a hardening queue

Current state:

- A focused node risk-surface audit was performed after reviewing VPN
  vulnerability patterns that chain network-facing services, local management
  APIs, privileged helpers, and TUN/TAP driver boundaries.
- The audit did not replace an independent cryptographic audit, but it did
  identify concrete implementation and deployment hardening work that should
  be treated as release-blocking before any FreeQ Linux distro or appliance
  image is promoted beyond prototype/alpha use.
- The resulting local-SLM work queue is proposal-only and lives outside this
  repo in the continual harness:
  `dev-packets/freeq-core-node-hardening-24-2026-07-18/`.
- The first application pass applied the independent invite pairing-code fix,
  status last-error redaction, and existing identity key permission checks.

Remaining primary findings:

- Local API mutating routes rely too heavily on loopback binding and need
  setup-token protection and browser-triggered request guards. Loopback bind
  validation is now enforced by default.
- Full transport cloaking still requires a pre-QUIC UDP admission gate; direct
  Quinn binding is not enough for a strict no-response posture. The
  `strict_cloaking` config path now fails closed until that gate exists.
- macOS setup scripts should parse env files instead of sourcing them before
  privileged route/interface commands.
- User-writable pid files need process validation before any privileged kill.
- Linux systemd hardening is already strong, but should be tightened further
  where compatible with TUN and QUIC operation.
- Status/API error surfaces should avoid leaking local paths or sensitive
  endpoint detail.

Tracked proposal packets:

- invite pairing-code hardening and tests
- local API loopback validation, setup token, and CSRF-style guard
- dashboard setup-token header flow without browser storage secrets
- identity key permission checks
- peer receive directory boundary cleanup
- status error redaction
- strict cloaking config and fail-closed daemon wiring
- no-tunnel-data-before-key-confirmation regression tests
- macOS setup script env parsing and pidfile validation
- peer env validator tightening
- systemd and Ansible hardening
- threat model, local API contract, OpenVPN lesson ADR, distro security
  checklist, and regression plan docs

Main files expected to change after review:

- `crates/freeq-api/src/handlers/peers.rs`
- `crates/freeq-api/src/router.rs`
- `crates/freeq-api/src/state.rs`
- `crates/freeq-api/src/handlers/status.rs`
- `crates/freeq-config/src/lib.rs`
- `crates/freeq-config/src/node.rs`
- `crates/freeq-config/src/peer.rs`
- `crates/freeq-transport/src/endpoint.rs`
- `crates/freeq-auth/src/handshake.rs`
- `daemon/src/main.rs`
- `dashboard/index.html`
- `scripts/setup/`
- `deploy/ansible/roles/freeqd/`
- `docs/`

### 1. Live QUIC datagram budget handling is not implemented

Current state:

- Transport frame sizing uses a conservative fixed payload cap
- The egress path does not yet adapt dynamically to each live connection's
  actual QUIC datagram budget

Main file:

- `crates/freeq-transport/src/frame.rs`

### 2. Packet buffer reuse and batching are still open optimization work

Current state:

- The current code is safer and more explicit than the original scaffold
- It is not yet the final high-throughput Linux dataplane design
- Future work should look at:
  - packet buffer reuse
  - batched send/receive
  - multiqueue Linux TUN
  - possible `io_uring` integration

Main files:

- `crates/freeq-tunnel/src/iface.rs`
- `daemon/src/main.rs`
- `docs/architecture.md`

### 3. Real host deployment validation is still limited

Current state:

- The Ansible layer parses and resolves correctly
- The macOS and Linux host TUN layers compile in-repo, but Linux host bring-up
  still needs validation on a real machine
- Full Linux host bring-up and RHEL-shaped performance validation still need to
  be exercised on actual machines

Main files:

- `deploy/ansible/`
- `crates/freeq-tunnel/src/iface.rs`

### 4. Full transport-level cloaking still requires a pre-QUIC gate

Current state:

- FreeQ now silently drops unauthenticated traffic at the inner handshake layer
- `freeq-transport` still binds Quinn directly, so the QUIC stack can respond
  before FreeQ identity verification runs
- This is not sufficient for a strict "no response to non-FreeQ probes"
  federal/defense/finance/critical-infrastructure posture

Required fix:

- Add a pre-QUIC UDP admission gate that validates a compact FreeQ-authenticated
  first datagram before forwarding traffic into Quinn
- Ensure non-FreeQ datagrams are dropped without a QUIC response, API error
  record, or warning-level log
- Add an integration test that sends random UDP and generic QUIC Initial probes
  and asserts no observable FreeQ response path is created

Main files:

- `crates/freeq-transport/src/endpoint.rs`
- `crates/freeq-auth/src/cloaking.rs`
- `daemon/src/main.rs`

### 5. Setup reachability classification is still too implicit

Current state:

- Field testing proved that a node behind Starlink residential/CGNAT can
  install successfully, authenticate a peer session outbound, and process
  tunnel packets while still being unable to accept direct inbound UDP.
- The setup website currently exposes peer and tunnel counters, but it does not
  classify whether a node is outbound-only, inbound-reachable,
  bidirectional-direct, or relay-required.
- Non-technical users can misread a failed symmetric ping as a failed install
  even when the direct network topology is the real blocker.

Required fix:

- Add setup/API fields for node and peer connectivity capability.
- Teach the setup flow to detect or ask about CGNAT/Starlink-style networks.
- Show capability badges in the local setup website.
- Recommend direct peer, reachable gateway, or Cloud relay/rendezvous based on
  the observed capability.

Main files:

- `crates/freeq-api/src/models.rs`
- `crates/freeq-api/src/state.rs`
- `dashboard/index.html`
- `scripts/setup/`
- `docs/enterprise-telemetry-cloud-path.md`

## 2026-07-19 Unix/Linux Service Hardening Pass

Applied directly after reviewing the OpenVPN chained RCE/LPE lessons against
FreeQ's setup and deployment surfaces.

Changes made:

- Stopped `freeq-render-config.sh` and `freeq-start-macos.sh` from sourcing
  setup/profile and peer env files. They now parse explicit keys as data.
- Made `freeq-render-config.sh` encode parsed values as TOML strings instead
  of interpolating raw env-file values into the generated config.
- Added stricter public `peer.env` validation for IPv4 CIDR overlay addresses,
  IP socket listen addresses, node names, and base64 exchange keys.
- Added pid-file guardrails before `freeq-start-macos.sh --restart` uses
  `sudo kill`; the pid must be numeric, live, and match a `freeqd` command.
- Extended the Ansible Linux role to render `allow_unsafe_api_bind` and
  `strict_cloaking`, and to reject non-loopback API binds unless explicitly
  opted into.
- Added compatible systemd sandboxing controls around address families,
  kernel logs/tunables/modules, realtime, SUID/SGID, personality changes, and
  writable/executable memory.
- Added a required `X-FreeQ-Setup-Intent: local-dashboard` header on local API
  mutation routes and taught the bundled dashboard to send it, reducing
  browser-to-localhost write exposure.

Deliberately left for a real Linux host validation pass:

- `SystemCallFilter=` hardening. FreeQ's TUN and networking path is ioctl-heavy,
  so this should be added from observed syscall traces rather than guessed.
- `PrivateDevices=true`. The service needs `/dev/net/tun`; the current unit
  uses `DeviceAllow=/dev/net/tun rw` without hiding the device namespace.

## Suggested Next Issues

These make sense as explicit repository issues because they are concrete,
bounded, and actionable:

1. Honor live QUIC datagram size limits per connection
2. Add packet buffer reuse to tunnel and daemon dataplane paths
3. Add batched send/receive and evaluate Linux multiqueue design
4. Validate Ansible deployment against a real Linux host
5. Add host-level integration test documentation for macOS `utun` and Linux TUN
6. Add pre-QUIC UDP admission gate for true transport-level cloaking
7. Add node reachability classification and setup UI capability badges

## Suggested Use

If new issues are opened from this document, they should reference:

- the problem statement in this log
- the affected files
- whether the issue is correctness, performance, portability, or deployment

That keeps the repo easier to triage than a generic "AI code cleanup" bucket.
