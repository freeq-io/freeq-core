//! HKDF-SHA256 key derivation (RFC 5869).
//!
//! Used to combine the X25519 and ML-KEM shared secrets into a single
//! session key, and to derive sub-keys from the session key.

use crate::{CryptoError, Result};

const HYBRID_COMBINER_SALT: &[u8] = b"FreeQ-v1-Hybrid-Combiner-Salt";
const HYBRID_COMBINER_INFO: &[u8] = b"FreeQ-v1-Hybrid-Combiner";
const MLKEM_SHARED_SECRET_LEN: usize = 32;
const COMBINE_CONTEXT_LEN: usize = HYBRID_COMBINER_INFO.len() + 64;

/// Domain separation labels.
pub mod labels {
    /// Primary handshake KDF label.
    pub const HANDSHAKE: &[u8] = b"freeq v1 handshake";
    /// Label for deriving the inbound traffic key.
    pub const INBOUND: &[u8] = b"freeq v1 inbound";
    /// Label for deriving the outbound traffic key.
    pub const OUTBOUND: &[u8] = b"freeq v1 outbound";
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

/// Combine fixed-size X25519 and ML-KEM shared secrets into a session key.
///
/// The public-key ordering is included in the HKDF `info` value so the
/// derivation is domain separated and non-commutative across roles.
pub fn combine_secrets(
    x25519_secret: &[u8; 32],
    mlkem_secret: &[u8; 32],
    client_pk_x25519: &[u8; 32],
    server_pk_x25519: &[u8; 32],
) -> [u8; 32] {
    use zeroize::Zeroize;

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_secret);
    ikm[32..].copy_from_slice(mlkem_secret);

    let mut context = [0u8; COMBINE_CONTEXT_LEN];
    let mut offset = HYBRID_COMBINER_INFO.len();
    context[..offset].copy_from_slice(HYBRID_COMBINER_INFO);
    context[offset..offset + 32].copy_from_slice(client_pk_x25519);
    offset += 32;
    context[offset..].copy_from_slice(server_pk_x25519);

    let key = hkdf_sha256(Some(HYBRID_COMBINER_SALT), &ikm, &context)
        .unwrap_or_else(|_| unreachable!("HKDF output length is fixed at 32 bytes"));
    ikm.zeroize();
    context.zeroize();
    key
}

/// Combine two KEM shared secrets into a session key.
///
/// `session_key = HKDF-SHA256(ikm = x25519_secret || mlkem_secret, info = label || nonce)`.
///
/// Both secrets are zeroized from stack memory after use.
pub fn derive_session_key(
    ecdh_secret: &[u8; 32],
    mlkem_secret: &[u8],
    nonce: &[u8],
) -> Result<[u8; 32]> {
    use zeroize::Zeroize;

    let mlkem_secret: &[u8; MLKEM_SHARED_SECRET_LEN] = mlkem_secret
        .try_into()
        .map_err(|_| CryptoError::KdfLength)?;
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ecdh_secret);
    ikm[32..].copy_from_slice(mlkem_secret);

    let mut info = Vec::with_capacity(labels::HANDSHAKE.len() + nonce.len());
    info.extend_from_slice(labels::HANDSHAKE);
    info.extend_from_slice(nonce);

    let key = hkdf_sha256(Some(HYBRID_COMBINER_SALT), &ikm, &info)?;

    ikm.zeroize();
    info.zeroize();
    Ok(key)
}
