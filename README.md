# FreeQ

**Post-quantum encrypted overlay network. Open source. Free forever.**

[![CI](https://github.com/freeq-io/freeq-core/actions/workflows/ci.yml/badge.svg)](https://github.com/freeq-io/freeq-core/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![Discord](https://img.shields.io/discord/placeholder?label=Discord&logo=discord)](https://discord.gg/freeq)

> ⚠️ **Alpha — not yet audited.** FreeQ has not received an independent cryptographic audit. Do not use to protect classified or life-safety data. See [SECURITY.md](SECURITY.md).

---

## The problem

Nation-state adversaries are recording your encrypted network traffic **right now** with the intent to decrypt it once quantum computers arrive — the **harvest now, decrypt later** attack. The timeline for cryptographically-relevant quantum computers is estimated at 10–15 years. Data with a long shelf life — health records, financial transactions, intellectual property, communications — is at immediate risk.

The most widely deployed network encryption tools were built on classical cryptography:

- **WireGuard** uses Curve25519 and ChaCha20 — both broken by Shor's algorithm
- **TLS 1.3** defaults to ECDHE with X25519 or P-256 — same story
- **OpenVPN / IPsec** — legacy protocols with no post-quantum roadmap

Every encrypted packet sent today over these protocols is a future liability.

## The solution

FreeQ wraps all traffic between trusted endpoints in **hybrid post-quantum tunnels** using NIST-finalized standards. Every connection is:

- **Double-encrypted** — X25519 (classical) + ML-KEM-768 (FIPS 203, post-quantum). Security holds if *either* algorithm remains unbroken.
- **Mutually authenticated** — ML-DSA-65 (FIPS 204) identity keys. Endpoints silently drop all packets from unauthenticated peers — no SYN-ACK, no banner, no ICMP response.
- **Forward-secret** — ephemeral KEM keypair per session. Long-term key compromise does not expose past traffic.
- **Crypto-agile** — switch ML-KEM parameter sets (512/768/1024) at runtime without restarting nodes.

## Quick comparison

|                        | FreeQ              | WireGuard     | Tailscale      |
|------------------------|--------------------|---------------|----------------|
| Post-quantum crypto    | ✅ FIPS 203/204/205 | ❌             | ❌              |
| Open source            | ✅ AGPL v3          | ✅ GPLv2       | Partial        |
| Self-hostable          | ✅ Full             | ✅ Full        | Via Headscale  |
| Memory safe            | ✅ Rust             | C (kernel)    | Go             |
| Endpoint cloaking      | ✅                  | ❌             | ❌              |
| Fleet management       | ✅ Paid (Cloud)     | DIY           | ✅ Paid         |

## How it works

Every FreeQ connection uses an 8-step mutual authentication and hybrid key exchange:

```
Node A → Node B   ML-DSA-65 signature over (nonce ‖ A_kem_pubkey)
Node B            Verify A's identity
Node B → Node A   ML-DSA-65 signature over (nonce ‖ A_nonce ‖ B_kem_pubkey)
Node A            Verify B's identity — mutual auth complete
Node A → Node B   ML-KEM-768 encapsulation
Both nodes        X25519 ECDH in parallel
Both nodes        session_key = HKDF-SHA256(kem_secret ‖ ecdh_secret, nonce)
Both nodes        AES-256-GCM bulk encryption begins. Ephemeral keys zeroized.
```

## Project structure

```
freeq-core/
├── crates/
│   ├── freeq-crypto/      # PQC primitives, hybrid KEM, crypto-agility traits
│   ├── freeq-transport/   # QUIC session management (quinn)
│   ├── freeq-tunnel/      # TUN/TAP interface, packet routing
│   ├── freeq-auth/        # ML-DSA-65 identity, peer registry, endpoint cloaking
│   ├── freeq-config/      # TOML configuration and peer policies
│   └── freeq-api/         # Local REST API — Apache 2.0 (FreeQ Cloud agent bridge)
├── daemon/                # freeqd — the overlay network daemon
├── cli/                   # freeq — management CLI
└── docs/                  # Architecture, crypto design, threat model
```

## Cryptographic dependencies

| Crate             | Version       | Purpose                  | Standard  |
|-------------------|---------------|--------------------------|-----------|
| ml-kem            | 0.3.0-rc.2    | Key encapsulation        | FIPS 203  |
| ml-dsa            | 0.1.0-rc.8    | Digital signatures       | FIPS 204  |
| slh-dsa           | 0.2.0-rc.4    | Hash-based DSA (backup)  | FIPS 205  |
| x25519-dalek      | 2.0           | Classical ECDH           | RFC 7748  |
| hkdf              | 0.12          | Key derivation           | RFC 5869  |
| aes-gcm           | 0.10          | Bulk encryption          | FIPS 197  |
| chacha20poly1305  | 0.10          | Bulk encryption (ARM)    | RFC 8439  |
| quinn             | 0.11          | QUIC transport           | RFC 9000  |

## Roadmap

**v0.1 — Alpha (current)**
- [x] Workspace scaffold and crate architecture
- [ ] ML-KEM-768 + X25519 hybrid KEM implementation
- [ ] ML-DSA-65 mutual authentication
- [ ] QUIC transport via quinn
- [ ] TUN/TAP L3 overlay
- [ ] Endpoint cloaking
- [ ] Basic CLI (init, up, down, peer add/remove, status)
- [ ] TOML configuration

**v0.2 — Q3 2026**
- [ ] io_uring data plane (Linux 5.19+)
- [ ] Session resumption and 0-RTT
- [ ] ML-KEM-1024 parameter set
- [ ] Kubernetes CNI plugin
- [ ] FreeQ Cloud agent

**v0.3 — Q4 2026**
- [ ] Windows (WinTUN)
- [ ] Mobile (iOS, Android via FFI)
- [ ] FreeQ Cloud beta (fleet dashboard, compliance reports)

**v1.0 — 2027**
- [ ] Stable API — no breaking changes
- [ ] Independent cryptographic audit
- [ ] FIPS 140-3 validated crypto module
- [ ] FedRAMP-ready deployment mode

## Platform support

| Platform       | Status        |
|----------------|---------------|
| Linux x86_64   | ✅ Primary     |
| Linux aarch64  | ✅ Supported   |
| macOS (Apple Silicon / Intel) | ✅ Supported |
| Windows        | 🔜 v0.3        |
| Docker         | ✅ Supported   |
| Kubernetes CNI | 🔜 v0.2        |

## Contributing

FreeQ is built in the open and contributions are welcome. All contributors must sign the CLA (automated on PR submission via [CLA Assistant](https://cla-assistant.io/)).

- **Good first issues** are tagged [`good first issue`](https://github.com/freeq-io/freeq-core/labels/good%20first%20issue) on GitHub
- Changes to `freeq-crypto` or `freeq-auth` require two maintainer approvals
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide

**Security vulnerabilities:** Email security@getfreeq.io — do not open public issues. See [SECURITY.md](SECURITY.md).

## Business model

FreeQ Core is and will always be free under AGPL v3. The commercial product is **FreeQ Cloud** — a paid management plane that connects to the local REST API on each node to provide fleet visibility, compliance reporting (CNSA 2.0, OMB M-23-02), network scanning, and remote operations.

Individuals, home labs, and self-hosters use FreeQ Core forever, for free.

## License

FreeQ Core is licensed under **AGPL v3**. See [LICENSE](LICENSE).

The `freeq-api` crate is licensed under **Apache 2.0** — this is the integration boundary between the AGPL core and the proprietary FreeQ Cloud agent.

---

*FreeQ — Quantum-safe networking, in the open.*
*[getfreeq.io](https://getfreeq.io) · [Discord](https://discord.gg/freeq) · [security@getfreeq.io](mailto:security@getfreeq.io)*
