# FreeQ Threat Model

## Adversary Assumptions

| Adversary | Capability | FreeQ Defense |
|-----------|-----------|---------------|
| Network observer (classical) | Intercept, record, replay packets | AES-256-GCM authenticated encryption |
| Nation-state (classical) | Harvest-now-decrypt-later | ML-KEM-768 post-quantum KEM |
| Quantum adversary (Shor) | Break X25519, RSA | ML-KEM-768 (not broken by Shor) |
| Active MITM | Intercept and modify packets | ML-DSA-65 mutual authentication |
| Port scanner | Discover network endpoints | Application-layer cloaking; full transport cloaking requires pre-QUIC admission |
| Unauthenticated peer | Send crafted packets | ML-DSA-65 cloaking: no FreeQ response, no tunnel session |

## What FreeQ Protects

- **Data in transit** between enrolled FreeQ nodes
- **FreeQ service visibility** — unauthenticated probes do not receive a FreeQ
  response or create a tunnel session
- **Forward secrecy** — past sessions not exposed by long-term key compromise

## What FreeQ Does NOT Protect

- **Data at rest** — use filesystem encryption (LUKS, FileVault) for that
- **Endpoint security** — FreeQ does not protect against compromise of the endpoint OS or application
- **Non-FreeQ traffic** — traffic not routed through the TUN interface is unaffected
- **Side channels** — no protection against timing attacks at the application layer
- **Denial of service** — an adversary can saturate the UDP port

## Harvest-Now-Decrypt-Later (HNDL)

FreeQ's primary threat model is the HNDL attack:

1. Adversary records encrypted WireGuard/TLS traffic today (2026)
2. Cryptographically-relevant quantum computer arrives (est. 2031–2041)
3. Adversary decrypts all recorded traffic using Shor's algorithm

FreeQ's ML-KEM-768 key encapsulation is not broken by Shor's algorithm. Traffic encrypted today will remain secure against future quantum adversaries.

## Classical Transport Bootstrap

The QUIC/TLS layer is treated only as a carrier for FreeQ handshake messages.
It is not a source of tunnel trust. The daemon must not install a usable tunnel
session until the inner FreeQ handshake has authenticated ML-DSA identities,
derived hybrid ML-KEM/X25519 material, rekeyed that material for traffic, and
verified a peer key-confirmation proof.

This means an attacker who records or interferes with the classical transport
handshake can cause denial of service, but must not gain FreeQ tunnel payload
confidentiality if ML-KEM remains secure.

Current implementation note: because `freeq-transport` binds Quinn directly,
generic QUIC probes can still elicit transport-level QUIC behavior before the
inner FreeQ handshake runs. Full network cloaking for federal, defense,
finance, and critical infrastructure targets requires a pre-QUIC authenticated
UDP gate that drops non-FreeQ datagrams before Quinn sees them.

## Node Hardening Audit Notes

A July 2026 node security review mapped FreeQ's local node surfaces against
common VPN failure patterns: unauthenticated network listeners, local management
APIs, setup/invite flows, privileged helper scripts, service-manager policy,
identity key handling, and the host TUN/TAP driver boundary.

This review produced a concrete proposal-only hardening queue in the continual
harness: `freeq-core-node-hardening-24-2026-07-18`. The first application pass
fixed invite pairing-code derivation, status error redaction, and existing
identity key permission checks. The second application pass added default
loopback enforcement for the local API and fail-closed strict-cloaking endpoint
mode selection. The remaining API token, browser request guard, setup-script,
service, and pre-QUIC admission-gate packets should be reviewed and applied
before a FreeQ Linux distro or appliance image is treated as more than
prototype/alpha work.

### Local Management API

The local API is intended to be loopback-only management surface. Mutating
routes such as peer add/remove, invite create/join, key rotation, and algorithm
switching must not be reachable from untrusted networks.

Required controls:

- reject non-loopback `api_addr` by default, with an explicit unsafe override
  required for any non-loopback bind
- protect mutating routes with setup-token or equivalent local authorization
- add a browser-triggered request guard so hostile web pages cannot drive local
  management actions through the user's browser
- avoid exposing sensitive path, endpoint, or key-material details through
  status responses

### Invite Pairing

Invite bundles must not contain enough information to derive the out-of-band
pairing code. Pairing codes are independent random material and should remain
short-lived, verified without logging, and kept out of browser storage.

### Identity Keys

Private identity key files must be owner-only readable before load. New keys are
created with `0600` permissions, and existing group/world-accessible keys fail
closed on Unix.

### Setup Scripts and Privileged Helpers

Setup scripts should treat env files as data, not executable shell. Peer and
local env files should be parsed with allowlisted keys and value validation
before their values are passed into `sudo ifconfig`, `route`, service restart,
or daemon commands.

User-writable pid files must not be trusted blindly for privileged process
termination. Restart flows should validate that a pid is numeric, still live,
owned as expected, and running the expected FreeQ daemon command before any
privileged kill.

### TUN and Service Boundary

The TUN interface is a privileged OS boundary. Linux deployments should keep
running `freeqd` as a dedicated non-login user with the smallest compatible
capability set, scoped device access to `/dev/net/tun`, strict filesystem
write paths, and additional systemd sandboxing where compatible with UDP QUIC
and TUN operation.

## Out-of-Scope Threats

- Physical access to a node
- Compromise of the FreeQ Cloud management plane (separate threat surface)
- Supply chain attacks on upstream Rust crates (mitigate with `cargo-audit`)
