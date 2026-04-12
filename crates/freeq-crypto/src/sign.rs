//! ML-DSA-65 (FIPS 204) mutual authentication.
//!
//! Every FreeQ node has a long-term ML-DSA-65 identity keypair.
//! The public key is registered in the peer registry; inbound packets
//! are silently dropped if they carry no valid ML-DSA-65 signature.

use crate::Result;

/// An ML-DSA-65 signing keypair (long-term node identity).
///
/// The secret key is wrapped in a `zeroize`-on-drop guard.
pub struct IdentityKeypair {
    // TODO(v0.1): wrap ml_dsa::SigningKey<ml_dsa::MlDsa65>
    _private: (),
}

/// An ML-DSA-65 verification (public) key — safe to share with peers.
pub struct IdentityPublicKey {
    // TODO(v0.1): wrap ml_dsa::VerifyingKey<ml_dsa::MlDsa65>
    _private: (),
}

/// A raw ML-DSA-65 signature.
pub struct Signature(
    /// The raw signature bytes.
    pub Vec<u8>,
);

impl IdentityKeypair {
    /// Generate a fresh identity keypair.
    pub fn generate(_rng: &mut impl rand_core::CryptoRngCore) -> Result<(Self, IdentityPublicKey)> {
        // TODO(v0.1): ml_dsa::MlDsa65::key_gen(rng)
        todo!("ML-DSA-65 key generation")
    }

    /// Sign a handshake challenge: `sign(nonce || kem_pubkey)`.
    pub fn sign_challenge(&self, _nonce: &[u8], _kem_pubkey: &[u8]) -> Result<Signature> {
        // TODO(v0.1): serialize challenge, call ml_dsa sign
        todo!("ML-DSA-65 sign challenge")
    }
}

impl IdentityPublicKey {
    /// Verify a handshake challenge signature from a remote peer.
    ///
    /// Returns `Ok(())` on success, `Err(CryptoError::SignatureInvalid)` on failure.
    pub fn verify_challenge(
        &self,
        _nonce: &[u8],
        _kem_pubkey: &[u8],
        _sig: &Signature,
    ) -> Result<()> {
        // TODO(v0.1): reconstruct challenge bytes, call ml_dsa verify
        todo!("ML-DSA-65 verify challenge")
    }

    /// Serialize the public key to bytes for transmission in the handshake.
    pub fn to_bytes(&self) -> Vec<u8> {
        todo!("ML-DSA-65 public key serialization")
    }

    /// Deserialize a public key from bytes received in a handshake message.
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
        todo!("ML-DSA-65 public key deserialization")
    }
}
