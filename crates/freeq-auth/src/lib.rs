//! # freeq-auth
//!
//! ML-DSA-65 node identity, peer registry, and endpoint cloaking.
//!
//! ## Endpoint cloaking
//!
//! Every inbound packet that does not carry a valid ML-DSA-65 signature
//! from a registered peer is silently dropped — before any response is
//! issued. The node is invisible to port scanners and unauthenticated
//! probes. No SYN-ACK, no banner, no ICMP unreachable.
//!
//! ## Handshake flow (8 steps, see founding doc §4.2)
//!
//! 1. A → B: ML-DSA-65 signature over (nonce || A_kem_pubkey)
//! 2. B: verify A's signature against registered public key
//! 3. B → A: ML-DSA-65 signature over (nonce || A_nonce || B_kem_pubkey)
//! 4. A: verify B's signature — mutual authentication complete
//! 5. A → B: ML-KEM-768 encapsulation
//! 6. Both: X25519 ECDH in parallel
//! 7. Both: HKDF combine → session key
//! 8. Both: AES-256-GCM bulk encryption begins

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used)]

pub mod cloaking;
pub mod error;
pub mod handshake;
pub mod registry;

pub use error::AuthError;

/// Library-wide result type.
pub type Result<T> = std::result::Result<T, AuthError>;
