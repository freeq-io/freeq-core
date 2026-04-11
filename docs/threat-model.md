# FreeQ Threat Model

## Adversary Assumptions

| Adversary | Capability | FreeQ Defense |
|-----------|-----------|---------------|
| Network observer (classical) | Intercept, record, replay packets | AES-256-GCM authenticated encryption |
| Nation-state (classical) | Harvest-now-decrypt-later | ML-KEM-768 post-quantum KEM |
| Quantum adversary (Shor) | Break X25519, RSA | ML-KEM-768 (not broken by Shor) |
| Active MITM | Intercept and modify packets | ML-DSA-65 mutual authentication |
| Port scanner | Discover network endpoints | Endpoint cloaking (silent drop) |
| Unauthenticated peer | Send crafted packets | ML-DSA-65 cloaking — zero response |

## What FreeQ Protects

- **Data in transit** between enrolled FreeQ nodes
- **Node visibility** — cloaked nodes are invisible to unauthenticated probes
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

## Out-of-Scope Threats

- Physical access to a node
- Compromise of the FreeQ Cloud management plane (separate threat surface)
- Supply chain attacks on upstream Rust crates (mitigate with `cargo-audit`)
