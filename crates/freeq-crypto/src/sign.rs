//! ML-DSA-65 (FIPS 204) mutual authentication.
//!
//! Every FreeQ node has a long-term ML-DSA-65 identity keypair.
//! The public key is registered in the peer registry; inbound packets
//! are silently dropped if they carry no valid ML-DSA-65 signature.

use crate::{CryptoError, Result};
use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use ml_dsa::{KeyGen as _, MlDsa65};
use zeroize::Zeroize;

/// An ML-DSA-65 signing keypair (long-term node identity).
///
/// The secret key is wrapped in a `zeroize`-on-drop guard.
pub struct IdentityKeypair {
    inner: ml_dsa::ExpandedSigningKey<MlDsa65>,
    seed: Vec<u8>,
}

/// An ML-DSA-65 verification (public) key — safe to share with peers.
#[derive(Clone)]
pub struct IdentityPublicKey {
    inner: ml_dsa::VerifyingKey<MlDsa65>,
}

/// A raw ML-DSA-65 signature.
pub struct Signature(
    /// The raw signature bytes.
    pub Vec<u8>,
);

impl IdentityKeypair {
    /// Generate a fresh identity keypair.
    pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> Result<(Self, IdentityPublicKey)> {
        let mut seed = ml_dsa::Seed::default();
        rng.fill_bytes(&mut seed);

        Self::from_seed(seed)
    }

    /// Sign a handshake challenge: `sign(nonce || kem_pubkey)`.
    pub fn sign_challenge(&self, nonce: &[u8], kem_pubkey: &[u8]) -> Result<Signature> {
        self.sign_message(&challenge_bytes(nonce, kem_pubkey))
    }

    /// Sign an arbitrary message with the long-term identity key.
    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        let signature = self.inner.sign(msg);
        Ok(Signature(signature.encode().to_vec()))
    }

    /// Serialize the private key to bytes for storage.
    ///
    /// The encoding is the 32-byte ML-DSA seed used to reconstruct the keypair.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.seed.clone()
    }

    /// Derive the public key corresponding to this private key.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Reconstruct a private key from the serialized seed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let seed = ml_dsa::Seed::try_from(bytes)
            .map_err(|_| CryptoError::Encoding("invalid ML-DSA-65 seed length".into()))?;

        let (keypair, _) = Self::from_seed(seed)?;
        Ok(keypair)
    }

    fn from_seed(seed: ml_dsa::Seed) -> Result<(Self, IdentityPublicKey)> {
        let keypair = MlDsa65::from_seed(&seed);
        let public_key = IdentityPublicKey {
            inner: keypair.verifying_key(),
        };

        Ok((
            Self {
                inner: keypair.signing_key().clone(),
                seed: seed.to_vec(),
            },
            public_key,
        ))
    }
}

impl Drop for IdentityKeypair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl IdentityPublicKey {
    /// Verify a handshake challenge signature from a remote peer.
    ///
    /// Returns `Ok(())` on success, `Err(CryptoError::SignatureInvalid)` on failure.
    pub fn verify_challenge(&self, nonce: &[u8], kem_pubkey: &[u8], sig: &Signature) -> Result<()> {
        self.verify_message(&challenge_bytes(nonce, kem_pubkey), sig)
    }

    /// Verify a signature over an arbitrary message.
    pub fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let signature = ml_dsa::Signature::<MlDsa65>::try_from(sig.0.as_slice())
            .map_err(|_| CryptoError::SignatureInvalid)?;

        self.inner
            .verify(msg, &signature)
            .map_err(|_| CryptoError::SignatureInvalid)
    }

    /// Serialize the public key to bytes for transmission in the handshake.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.encode().to_vec()
    }

    /// Deserialize a public key from bytes received in a handshake message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|_| CryptoError::Encoding("invalid ML-DSA-65 public key length".into()))?;

        Ok(Self {
            inner: ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded),
        })
    }
}

fn challenge_bytes(nonce: &[u8], kem_pubkey: &[u8]) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(nonce.len() + kem_pubkey.len());
    challenge.extend_from_slice(nonce);
    challenge.extend_from_slice(kem_pubkey);
    challenge
}

#[cfg(test)]
mod tests {
    use super::{IdentityKeypair, IdentityPublicKey};

    #[test]
    fn identity_keypair_round_trips_through_seed_bytes() {
        let mut rng = rand::thread_rng();
        let (keypair, public_key) = IdentityKeypair::generate(&mut rng).expect("key generation");

        let restored = IdentityKeypair::from_bytes(&keypair.to_bytes()).expect("seed decode");

        assert_eq!(public_key.to_bytes(), restored.public_key().to_bytes());
    }

    #[test]
    fn public_key_round_trips_through_bytes() {
        let mut rng = rand::thread_rng();
        let (_keypair, public_key) = IdentityKeypair::generate(&mut rng).expect("key generation");

        let restored = IdentityPublicKey::from_bytes(&public_key.to_bytes()).expect("vk decode");

        assert_eq!(public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn signatures_verify_after_serialization_round_trip() {
        let mut rng = rand::thread_rng();
        let (keypair, public_key) = IdentityKeypair::generate(&mut rng).expect("key generation");
        let nonce = b"nonce";
        let kem_pubkey = b"peer-kem-pubkey";

        let signature = keypair
            .sign_challenge(nonce, kem_pubkey)
            .expect("signature");
        let restored_public_key =
            IdentityPublicKey::from_bytes(&public_key.to_bytes()).expect("vk decode");

        restored_public_key
            .verify_challenge(nonce, kem_pubkey, &signature)
            .expect("signature verification");
    }

    #[test]
    fn arbitrary_message_signatures_verify() {
        let mut rng = rand::thread_rng();
        let (keypair, public_key) = IdentityKeypair::generate(&mut rng).expect("key generation");
        let msg = b"registry payload";

        let signature = keypair.sign_message(msg).expect("signature");

        public_key
            .verify_message(msg, &signature)
            .expect("signature verification");
    }
}
