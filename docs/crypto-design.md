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

## HKDF Domain Separation

All HKDF invocations use distinct `info` labels to prevent cross-context key reuse:

- `b"freeq v1 handshake"` — session key derivation
- `b"freeq v1 inbound"`  — inbound traffic subkey
- `b"freeq v1 outbound"` — outbound traffic subkey

## Key Zeroization

All ephemeral key material is zeroized from memory after use via the `zeroize` crate. The `ZeroizeOnDrop` derive macro is applied to all secret key types.

## Nonce Construction

AES-256-GCM and ChaCha20-Poly1305 require unique 96-bit nonces per (key, message) pair. FreeQ derives nonces as:

```
nonce = HKDF(session_key, counter_bytes, b"freeq v1 nonce")
```

Where `counter_bytes` is a monotonically incrementing 64-bit big-endian counter. The session key is never reused across renegotiations.
