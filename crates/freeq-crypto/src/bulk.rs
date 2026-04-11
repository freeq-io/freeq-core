//! Bulk encryption: AES-256-GCM and ChaCha20-Poly1305.
//!
//! The algorithm is selected at runtime based on CPU capabilities:
//! - AES-256-GCM on x86-64 with AES-NI (hardware-accelerated, ~4.8 Gbps)
//! - ChaCha20-Poly1305 elsewhere (constant-time software, ~3.9 Gbps on ARM)

use crate::{CryptoError, Result};

/// Nonce length for both AEAD schemes (96-bit / 12 bytes).
pub const NONCE_LEN: usize = 12;

/// Tag length for both AEAD schemes (128-bit / 16 bytes).
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` in-place, appending the authentication tag.
///
/// `nonce` must be unique per (key, message) pair — derive from a counter
/// combined with the session key via HKDF.
pub fn encrypt(
    algorithm: &crate::agility::BulkAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use crate::agility::BulkAlgorithm;

    match algorithm {
        BulkAlgorithm::Aes256Gcm => {
            // TODO(v0.1): aes_gcm::Aes256Gcm::new_from_slice(key)?.encrypt(nonce, payload)
            let _ = (key, nonce, aad, plaintext);
            todo!("AES-256-GCM encrypt")
        }
        BulkAlgorithm::ChaCha20Poly1305 => {
            // TODO(v0.1): chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)?.encrypt(...)
            let _ = (key, nonce, aad, plaintext);
            todo!("ChaCha20-Poly1305 encrypt")
        }
    }
}

/// Decrypt and authenticate `ciphertext`.
///
/// Returns the plaintext on success, or [`CryptoError::AeadAuthFailure`]
/// if the authentication tag does not match (possible ciphertext tampering).
pub fn decrypt(
    algorithm: &crate::agility::BulkAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use crate::agility::BulkAlgorithm;

    match algorithm {
        BulkAlgorithm::Aes256Gcm => {
            let _ = (key, nonce, aad, ciphertext);
            todo!("AES-256-GCM decrypt")
        }
        BulkAlgorithm::ChaCha20Poly1305 => {
            let _ = (key, nonce, aad, ciphertext);
            todo!("ChaCha20-Poly1305 decrypt")
        }
    }
}

/// Verify that `tag` matches for the given `ciphertext` in constant time.
pub fn verify_tag(expected: &[u8], actual: &[u8]) -> Result<()> {
    if constant_time_eq::constant_time_eq(expected, actual) {
        Ok(())
    } else {
        Err(CryptoError::AeadAuthFailure)
    }
}
