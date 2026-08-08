//! Crypto error types.

use thiserror::Error;

/// Errors returned by freeq-crypto operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// ML-KEM key encapsulation or decapsulation failed.
    #[error("KEM operation failed")]
    KemFailure,

    /// ML-DSA or SLH-DSA signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// AEAD authentication tag mismatch (ciphertext tampering detected).
    #[error("AEAD authentication failed — possible ciphertext tampering")]
    AeadAuthFailure,

    /// Key derivation produced an unexpected output length.
    #[error("KDF output length error")]
    KdfLength,

    /// Algorithm parameter set is not supported or disabled at compile time.
    #[error("unsupported algorithm parameter set: {0}")]
    UnsupportedAlgorithm(String),

    /// Serialization or deserialization of key material failed.
    #[error("key encoding error: {0}")]
    Encoding(String),
}
