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
        BulkAlgorithm::Aes256Gcm => encrypt_aes256_gcm(key, nonce, aad, plaintext),
        BulkAlgorithm::ChaCha20Poly1305 => encrypt_chacha20_poly1305(key, nonce, aad, plaintext),
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
        BulkAlgorithm::Aes256Gcm => decrypt_aes256_gcm(key, nonce, aad, ciphertext),
        BulkAlgorithm::ChaCha20Poly1305 => decrypt_chacha20_poly1305(key, nonce, aad, ciphertext),
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

fn encrypt_aes256_gcm(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuthFailure)
}

fn decrypt_aes256_gcm(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuthFailure)
}

fn encrypt_chacha20_poly1305(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuthFailure)
}

fn decrypt_chacha20_poly1305(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuthFailure)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, verify_tag, TAG_LEN};
    use crate::agility::BulkAlgorithm;

    const KEY: [u8; 32] = [7u8; 32];
    const NONCE: [u8; 12] = [9u8; 12];
    const AAD: &[u8] = b"freeq aad";
    const PLAINTEXT: &[u8] = b"encrypted overlay payload";

    #[test]
    fn aes256_gcm_round_trip() {
        round_trip(BulkAlgorithm::Aes256Gcm);
    }

    #[test]
    fn chacha20_poly1305_round_trip() {
        round_trip(BulkAlgorithm::ChaCha20Poly1305);
    }

    #[test]
    fn tampering_is_detected() {
        for algorithm in [BulkAlgorithm::Aes256Gcm, BulkAlgorithm::ChaCha20Poly1305] {
            let mut ciphertext =
                encrypt(&algorithm, &KEY, &NONCE, AAD, PLAINTEXT).expect("encrypt");
            let last = ciphertext.last_mut().expect("tag byte");
            *last ^= 0x01;

            let err = decrypt(&algorithm, &KEY, &NONCE, AAD, &ciphertext)
                .expect_err("tampered ciphertext should fail");
            assert!(matches!(err, crate::CryptoError::AeadAuthFailure));
        }
    }

    #[test]
    fn aad_mismatch_is_detected() {
        for algorithm in [BulkAlgorithm::Aes256Gcm, BulkAlgorithm::ChaCha20Poly1305] {
            let ciphertext = encrypt(&algorithm, &KEY, &NONCE, AAD, PLAINTEXT).expect("encrypt");

            let err = decrypt(&algorithm, &KEY, &NONCE, b"wrong aad", &ciphertext)
                .expect_err("wrong aad should fail");
            assert!(matches!(err, crate::CryptoError::AeadAuthFailure));
        }
    }

    #[test]
    fn verify_tag_uses_constant_time_comparison() {
        let expected = [1u8; TAG_LEN];
        let actual = [1u8; TAG_LEN];
        verify_tag(&expected, &actual).expect("matching tags");

        let mut wrong = actual;
        wrong[0] ^= 0x01;
        let err = verify_tag(&expected, &wrong).expect_err("tag mismatch");
        assert!(matches!(err, crate::CryptoError::AeadAuthFailure));
    }

    fn round_trip(algorithm: BulkAlgorithm) {
        let ciphertext = encrypt(&algorithm, &KEY, &NONCE, AAD, PLAINTEXT).expect("encrypt");
        assert!(ciphertext.len() >= PLAINTEXT.len() + TAG_LEN);

        let plaintext = decrypt(&algorithm, &KEY, &NONCE, AAD, &ciphertext).expect("decrypt");
        assert_eq!(plaintext, PLAINTEXT);
    }
}
