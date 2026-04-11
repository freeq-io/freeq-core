# FreeQ Core

**Post-quantum encrypted overlay network. Free forever.**

FreeQ wraps all traffic between trusted endpoints in hybrid post-quantum tunnels using NIST-finalized standards (FIPS 203, 204, 205). Every connection is double-encrypted, mutually authenticated, and forward-secret.

> ⚠️ **Alpha software.** FreeQ has not yet received an independent cryptographic audit. Do not use to protect classified or life-safety data. See [SECURITY.md](SECURITY.md).

---

## Why FreeQ?

Nation-state adversaries are harvesting encrypted traffic today to decrypt it once quantum computers arrive — the **harvest now, decrypt later** attack. WireGuard and TLS 1.3 default to algorithms broken by Shor's algorithm. FreeQ is the open-source answer.

| | FreeQ | WireGuard | Tailscale |
|---|---|---|---|
| Post-quantum crypto | ✅ FIPS 203/204/205 | ❌ | ❌ |
| Open source | ✅ AGPL v3 | ✅ GPLv2 | Partial |
| Self-hostable | ✅ | ✅ | Via Headscale |
| Memory safe | ✅ Rust | C (kernel) | Go |
| Endpoint cloaking | ✅ | ❌ | ❌ |

## Cryptography

Every connection uses a **hybrid KEM**:

- **X25519** (classical ECDH, RFC 7748) + **ML-KEM-768** (FIPS 203, post-quantum)
- Combined via **HKDF-SHA256** (RFC 5869) → 256-bit session key
- **ML-DSA-65** (FIPS 204) for mutual authentication
- **AES-256-GCM** (x86/AES-NI) or **ChaCha20-Poly1305** (ARM) for bulk encryption

Security holds if *either* X25519 or ML-KEM-768 remains unbroken.

## Project Structure

```
freeq-core/
├── crates/
│   ├── freeq-crypto/     # PQC primitives, hybrid KEM, crypto-agility traits
│   ├── freeq-transport/  # QUIC session management and connection pool
│   ├── freeq-tunnel/     # TUN/TAP interface, packet routing, I/O
│   ├── freeq-auth/       # ML-DSA identity, peer registry, endpoint cloaking
│   ├── freeq-config/     # TOML configuration and peer policies
│   └── freeq-api/        # Local REST API (Apache 2.0 — consumed by Cloud agent)
├── daemon/               # freeqd — the main daemon binary
├── cli/                  # freeq — the management CLI
└── docs/                 # Architecture, crypto design, threat model
```

## Quick Start

```sh
# Install
cargo install --git https://github.com/freeq-io/freeq-core freeqd freeq

# Initialize a node
sudo freeq init --name nyc-01

# Add a peer
sudo freeq peer add \
  --name lon-01 \
  --public-key <ML-DSA-65 pubkey> \
  --kem-key <ML-KEM-768 pubkey> \
  --endpoint lon-01.example.com:51820 \
  --allowed-ips 10.0.0.2/32

# Start the daemon
sudo freeqd --foreground
```

## License

FreeQ Core is licensed under **AGPL v3**. See [LICENSE](LICENSE).

The `freeq-api` crate is licensed under **Apache 2.0** to allow the proprietary FreeQ Cloud agent to link against it.

## Contributing

All contributions require a signed CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).

Security issues: email security@freeq.io — see [SECURITY.md](SECURITY.md).
