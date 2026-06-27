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
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    match algorithm {
        BulkAlgorithm::Aes256Gcm => {
            let cipher =
                aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KdfLength)?;
            cipher
                .encrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadAuthFailure)
        }
        BulkAlgorithm::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KdfLength)?;
            cipher
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadAuthFailure)
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
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    match algorithm {
        BulkAlgorithm::Aes256Gcm => {
            let cipher =
                aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::KdfLength)?;
            cipher
                .decrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadAuthFailure)
        }
        BulkAlgorithm::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KdfLength)?;
            cipher
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::AeadAuthFailure)
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

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use crate::agility::BulkAlgorithm;

    #[test]
    fn aes_gcm_round_trip() -> crate::Result<()> {
        round_trip(BulkAlgorithm::Aes256Gcm)
    }

    #[test]
    fn chacha20_poly1305_round_trip() -> crate::Result<()> {
        round_trip(BulkAlgorithm::ChaCha20Poly1305)
    }

    fn round_trip(algorithm: BulkAlgorithm) -> crate::Result<()> {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let aad = b"freeq-bulk-test";
        let plaintext = b"freeq packet payload";

        let ciphertext = encrypt(&algorithm, &key, &nonce, aad, plaintext)?;
        let decrypted = decrypt(&algorithm, &key, &nonce, aad, &ciphertext)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }
}
