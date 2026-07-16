# FreeQ Cryptographic Design

## Algorithm Selection

| Component | Algorithm | Standard | Parameter Set | Security Level |
|-----------|-----------|----------|--------------|----------------|
| KEM (PQ)  | ML-KEM    | FIPS 203 | ML-KEM-768 (default) | Cat. 3 ≈ AES-192 |
| KEM (classical) | X25519 | RFC 7748 | — | ~128-bit |
| Signatures | ML-DSA   | FIPS 204 | ML-DSA-65 (default) | Cat. 3 |
| KDF       | HKDF-SHA256 | RFC 5869 | — | — |
| Bulk (x86) | AES-256-GCM | FIPS 197 | — | 256-bit |
| Bulk (ARM) | ChaCha20-Poly1305 | RFC 8439 | — | 256-bit |

## Hybrid Security Rationale

The `session_key = HKDF(kem_secret ∥ ecdh_secret)` construction provides:

- **Classical security**: X25519 provides ~128-bit security against classical adversaries
- **Post-quantum security**: ML-KEM-768 provides Category 3 security against quantum adversaries
- **Defense in depth**: Security holds if *either* algorithm remains unbroken

This follows IETF draft-ietf-tls-ecdhe-mlkem and is deployed by Cloudflare (X25519MLKEM768) and AWS.

## Key Lifecycle

| Key | Lifetime | Rotation |
|-----|----------|---------|
| ML-DSA-65 identity key | Long-term (months/years) | Manual via `freeq key rotate` |
| ML-KEM-768 ephemeral key | One handshake | Automatic per session |
| X25519 ephemeral key | One handshake | Automatic per session |
| AES-256-GCM session key | One session | On reconnect or rotation timer |

## Transport Bootstrap Boundary

FreeQ may use classical QUIC/TLS as a packet carrier, but QUIC/TLS is not the
FreeQ trust boundary. No tunnel payload is accepted as protected until the
inner FreeQ handshake completes:

1. ML-DSA identity signatures authenticate the peer and bind the signed
   handshake material.
2. X25519 and ML-KEM-768 shared secrets are combined through HKDF.
3. The hybrid handshake output is immediately rekeyed with a distinct
   `freeq v1 post-handshake rekey` label before traffic keys are derived.
4. Both peers exchange key-confirmation proofs derived from the rekeyed
   material.
5. The daemon installs an active tunnel session only after the remote
   confirmation proof verifies.

This prevents the classical transport bootstrap from silently becoming the
security boundary. A quantum break of the carrier handshake must not expose
FreeQ tunnel traffic keys as long as ML-KEM remains sound.

## HKDF Domain Separation

All HKDF invocations use distinct `info` labels to prevent cross-context key reuse:

- `b"freeq v1 handshake"` — session key derivation
- `b"freeq v1 post-handshake rekey"` — rekey from hybrid handshake output to traffic material
- `b"freeq v1 inbound"` — inbound traffic subkey
- `b"freeq v1 outbound"` — outbound traffic subkey
- `b"freeq v1 key confirm initiator"` — initiator confirmation proof
- `b"freeq v1 key confirm responder"` — responder confirmation proof

## Key Zeroization

All ephemeral key material is zeroized from memory after use via the `zeroize` crate. The `ZeroizeOnDrop` derive macro is applied to all secret key types.

## Nonce Construction

AES-256-GCM and ChaCha20-Poly1305 require unique 96-bit nonces per (key, message) pair. FreeQ derives nonces as:

```
nonce = HKDF(session_key, counter_bytes, b"freeq v1 nonce")
```

Where `counter_bytes` is a monotonically incrementing 64-bit big-endian counter. The session key is never reused across renegotiations.
