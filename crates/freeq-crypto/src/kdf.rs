//! HKDF-SHA256 key derivation (RFC 5869).
//!
//! Used to combine the X25519 and ML-KEM shared secrets into a single
//! session key, and to derive sub-keys from the session key.

use crate::{CryptoError, Result};

/// Domain separation labels.
pub mod labels {
    /// Primary handshake KDF label.
    pub const HANDSHAKE: &[u8] = b"freeq v1 handshake";
    /// Label for deriving the inbound traffic key.
    pub const INBOUND:   &[u8] = b"freeq v1 inbound";
    /// Label for deriving the outbound traffic key.
    pub const OUTBOUND:  &[u8] = b"freeq v1 outbound";
}

/// Derive a 32-byte key from `ikm` using HKDF-SHA256.
///
/// # Arguments
/// * `salt`  – optional salt (use `&[]` to let HKDF use the zero-length default)
/// * `ikm`   – input key material (the concatenated KEM shared secrets)
/// * `info`  – domain-separation label (see [`labels`])
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::KdfLength)?;
    Ok(out)
}

/// Combine two KEM shared secrets into a session key.
///
/// `session_key = HKDF-SHA256(ikm = ecdh_secret || mlkem_secret, info = label)`
///
/// Both secrets are zeroized from stack memory after use.
pub fn derive_session_key(
    ecdh_secret: &[u8; 32],
    mlkem_secret: &[u8],
    nonce: &[u8],
) -> Result<[u8; 32]> {
    use zeroize::Zeroize;

    let mut ikm = Vec::with_capacity(32 + mlkem_secret.len());
    ikm.extend_from_slice(ecdh_secret);
    ikm.extend_from_slice(mlkem_secret);

    let key = hkdf_sha256(Some(nonce), &ikm, labels::HANDSHAKE)?;

    ikm.zeroize();
    Ok(key)
}
