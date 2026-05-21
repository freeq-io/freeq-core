//! # freeq-crypto
//!
//! Post-quantum cryptographic primitives for the FreeQ overlay network.
//!
//! Implements a hybrid key-encapsulation and authentication stack:
//!
//! - **KEM**: X25519 (classical) + ML-KEM-768 (FIPS 203, post-quantum)
//! - **Signatures**: ML-DSA-65 (FIPS 204)
//! - **Backup signatures**: SLH-DSA-SHA2-128f (FIPS 205)
//! - **KDF**: HKDF-SHA256 (RFC 5869) combining both KEM shared secrets
//! - **Bulk encryption**: AES-256-GCM (x86 AES-NI) or ChaCha20-Poly1305 (ARM)
//!
//! ## Security invariant
//!
//! The hybrid construction provides security if *either* X25519 *or* ML-KEM
//! remains unbroken. A quantum adversary breaks X25519 but not ML-KEM; a
//! classical mathematical break of ML-KEM lattice assumptions leaves X25519
//! intact. Either algorithm alone is sufficient.

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used)]

pub mod agility;
pub mod bulk;
pub mod error;
pub mod kdf;
pub mod kem;
pub mod sign;

pub use error::CryptoError;

/// Library-wide result type.
pub type Result<T> = std::result::Result<T, CryptoError>;
