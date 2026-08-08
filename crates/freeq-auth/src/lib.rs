//! # freeq-auth
//!
//! ML-DSA-65 node identity, peer registry, and endpoint cloaking.
//!
//! ## Endpoint cloaking
//!
//! Every FreeQ handshake packet that does not carry a valid ML-DSA-65
//! signature from a registered peer is silently dropped before any FreeQ
//! response is issued. Full network-level invisibility also requires the
//! transport layer to gate packets before QUIC emits a response.
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
//! 8. Both: post-handshake rekey and key confirmation
//! 9. Both: AES-256-GCM bulk encryption begins

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used)]

pub mod cloaking;
pub mod error;
pub mod handshake;
pub mod registry;

pub use error::AuthError;

/// Library-wide result type.
pub type Result<T> = std::result::Result<T, AuthError>;
