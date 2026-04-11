# FreeQ Architecture

## System Layer Diagram

```
┌─────────────────────────────────────────────────────────┐
│  APPLICATION LAYER — your services, APIs, microservices  │
├─────────────────────────────────────────────────────────┤
│  FREEQ CLOUD (paid) — Fleet Dashboard · Scanner · NMS   │
├─────────────────────────────────────────────────────────┤
│  FREEQ CORE DAEMON (AGPL v3)                            │
│  ┌──────────────────┐  ┌──────────────────────────────┐ │
│  │  Control Plane   │  │       Data Plane             │ │
│  │  freeq-config    │  │  freeq-crypto                │ │
│  │  freeq-auth      │  │  freeq-transport (QUIC)      │ │
│  │  freeq-api       │  │  freeq-tunnel (TUN/TAP)      │ │
│  └──────────────────┘  └──────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│  CRYPTO — FIPS 203 ML-KEM · FIPS 204 ML-DSA · X25519   │
├─────────────────────────────────────────────────────────┤
│  TRANSPORT — QUIC (RFC 9000) · UDP · io_uring (Linux)   │
├─────────────────────────────────────────────────────────┤
│  OS — Linux TUN/TAP · macOS utun · Windows WinTUN       │
└─────────────────────────────────────────────────────────┘
```

## Hybrid KEM Handshake (8 Steps)

| Step | Party    | Action |
|------|----------|--------|
| 1    | A → B    | Send ML-DSA-65 signature over `(nonce ∥ A_kem_pubkey)` |
| 2    | B        | Verify A's signature against registered public key |
| 3    | B → A    | Return ML-DSA-65 signature over `(nonce ∥ A_nonce ∥ B_kem_pubkey)` |
| 4    | A        | Verify B's signature — mutual authentication complete |
| 5    | A → B    | ML-KEM-768 encapsulation: generate shared secret + ciphertext |
| 6    | Both     | X25519 ECDH key exchange in parallel with step 5 |
| 7    | Both     | `session_key = HKDF-SHA256(kem_secret ∥ ecdh_secret, nonce, info)` |
| 8    | Both     | AES-256-GCM bulk encryption begins. Ephemeral keys zeroized. |

## Crate Dependency Graph

```
freeqd (daemon binary)
├── freeq-crypto     (no internal deps)
├── freeq-config     (no internal deps)
├── freeq-transport  → freeq-crypto
├── freeq-auth       → freeq-crypto, freeq-config
├── freeq-tunnel     → freeq-crypto, freeq-transport, freeq-auth, freeq-config
└── freeq-api        → freeq-config, freeq-auth

freeq (CLI binary)
├── freeq-config
└── freeq-api
```
