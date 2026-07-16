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

## Suggested Next Issues

These make sense as explicit repository issues because they are concrete,
bounded, and actionable:

1. Honor live QUIC datagram size limits per connection
2. Add packet buffer reuse to tunnel and daemon dataplane paths
3. Add batched send/receive and evaluate Linux multiqueue design
4. Validate Ansible deployment against a real Linux host
5. Add host-level integration test documentation for macOS `utun` and Linux TUN
6. Add pre-QUIC UDP admission gate for true transport-level cloaking

## Suggested Use

If new issues are opened from this document, they should reference:

- the problem statement in this log
- the affected files
- whether the issue is correctness, performance, portability, or deployment

That keeps the repo easier to triage than a generic "AI code cleanup" bucket.
