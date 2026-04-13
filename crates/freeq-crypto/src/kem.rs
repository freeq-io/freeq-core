//! Hybrid KEM: X25519 (classical) + ML-KEM-768 (post-quantum).
//!
//! Both shared secrets are combined via HKDF-SHA256 into a single session key.
//! Security holds if *either* algorithm remains unbroken.

use ml_kem::kem::{Decapsulate as _, Encapsulate as _, KeyExport as _};
use ml_kem::{DecapsulationKey768, EncapsulationKey768};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::{kdf, CryptoError, Result};

const X25519_PUBLIC_KEY_LEN: usize = 32;
const X25519_SECRET_KEY_LEN: usize = 32;
const MLKEM_SEED_LEN: usize = 64;

/// Hybrid per-session secret key material.
///
/// This contains the local X25519 static secret and the ML-KEM-768 seed used
/// to reconstruct the decapsulation key.
#[derive(ZeroizeOnDrop)]
pub struct HybridSecretKey {
    x25519_secret: [u8; X25519_SECRET_KEY_LEN],
    mlkem_seed: [u8; MLKEM_SEED_LEN],
}

/// Hybrid per-session public key material.
#[derive(Clone, Debug)]
pub struct HybridPublicKey {
    x25519_public: [u8; X25519_PUBLIC_KEY_LEN],
    mlkem_public: Vec<u8>,
}

/// Combined output of a hybrid KEM encapsulation.
#[derive(ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    /// The 32-byte session key derived by HKDF over both KEM outputs.
    pub session_key: [u8; 32],
}

/// Ciphertext produced by [`hybrid_encapsulate`], sent to the remote peer.
#[derive(Clone, Debug)]
pub struct HybridCiphertext {
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_epk: [u8; 32],
    /// ML-KEM ciphertext (size varies by parameter set).
    pub mlkem_ct: Vec<u8>,
}

impl HybridSecretKey {
    /// Generate a fresh hybrid KEM keypair.
    pub fn generate<R>(rng: &mut R) -> Result<(Self, HybridPublicKey)>
    where
        R: rand_core::CryptoRng + rand_core::RngCore + ?Sized,
    {
        let x25519_secret = X25519StaticSecret::random_from_rng(&mut *rng).to_bytes();
        let mut mlkem_seed = [0u8; MLKEM_SEED_LEN];
        rng.fill_bytes(&mut mlkem_seed);

        let secret = Self {
            x25519_secret,
            mlkem_seed,
        };
        let public = secret.public_key()?;

        Ok((secret, public))
    }

    /// Serialize the private key for transient storage or testing.
    ///
    /// The encoding is `x25519_secret || mlkem_seed`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_SECRET_KEY_LEN + MLKEM_SEED_LEN);
        out.extend_from_slice(&self.x25519_secret);
        out.extend_from_slice(&self.mlkem_seed);
        out
    }

    /// Reconstruct a secret key from `x25519_secret || mlkem_seed`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_SECRET_KEY_LEN + MLKEM_SEED_LEN {
            return Err(CryptoError::Encoding(
                "invalid hybrid secret key length".into(),
            ));
        }

        let x25519_secret = bytes[..X25519_SECRET_KEY_LEN]
            .try_into()
            .map_err(|_| CryptoError::Encoding("invalid X25519 secret key".into()))?;
        let mlkem_seed = bytes[X25519_SECRET_KEY_LEN..]
            .try_into()
            .map_err(|_| CryptoError::Encoding("invalid ML-KEM seed".into()))?;

        Ok(Self {
            x25519_secret,
            mlkem_seed,
        })
    }

    /// Derive the corresponding hybrid public key.
    pub fn public_key(&self) -> Result<HybridPublicKey> {
        let x25519_secret = X25519StaticSecret::from(self.x25519_secret);
        let x25519_public = X25519PublicKey::from(&x25519_secret).to_bytes();
        let mlkem_secret = mlkem_secret_from_seed(&self.mlkem_seed);
        let mlkem_public = mlkem_secret.encapsulation_key().to_bytes().to_vec();

        Ok(HybridPublicKey {
            x25519_public,
            mlkem_public,
        })
    }

    /// Return the serialized X25519 secret bytes.
    pub fn x25519_secret_bytes(&self) -> [u8; X25519_SECRET_KEY_LEN] {
        self.x25519_secret
    }

    /// Return the serialized ML-KEM seed bytes.
    pub fn mlkem_seed_bytes(&self) -> [u8; MLKEM_SEED_LEN] {
        self.mlkem_seed
    }
}

impl HybridPublicKey {
    /// Serialize the public key as `x25519_public || mlkem_public`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PUBLIC_KEY_LEN + self.mlkem_public.len());
        out.extend_from_slice(&self.x25519_public);
        out.extend_from_slice(&self.mlkem_public);
        out
    }

    /// Parse and validate a public key from `x25519_public || mlkem_public`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= X25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::Encoding(
                "invalid hybrid public key length".into(),
            ));
        }

        let x25519_public = bytes[..X25519_PUBLIC_KEY_LEN]
            .try_into()
            .map_err(|_| CryptoError::Encoding("invalid X25519 public key".into()))?;
        let mlkem_public = bytes[X25519_PUBLIC_KEY_LEN..].to_vec();
        validate_mlkem_public_key(&mlkem_public)?;

        Ok(Self {
            x25519_public,
            mlkem_public,
        })
    }

    /// Return the X25519 portion of the public key.
    pub fn x25519_public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.x25519_public
    }

    /// Return the serialized ML-KEM public key bytes.
    pub fn mlkem_public_key(&self) -> &[u8] {
        &self.mlkem_public
    }
}

impl HybridCiphertext {
    /// Serialize the ciphertext as `x25519_epk || mlkem_ct`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PUBLIC_KEY_LEN + self.mlkem_ct.len());
        out.extend_from_slice(&self.x25519_epk);
        out.extend_from_slice(&self.mlkem_ct);
        out
    }

    /// Parse a ciphertext from `x25519_epk || mlkem_ct`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= X25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::Encoding(
                "invalid hybrid ciphertext length".into(),
            ));
        }

        Ok(Self {
            x25519_epk: bytes[..X25519_PUBLIC_KEY_LEN]
                .try_into()
                .map_err(|_| CryptoError::Encoding("invalid X25519 ciphertext".into()))?,
            mlkem_ct: bytes[X25519_PUBLIC_KEY_LEN..].to_vec(),
        })
    }
}

/// Encapsulate a shared secret for `peer_x25519_pk` and `peer_mlkem_pk`.
///
/// Returns the [`HybridSharedSecret`] (kept local) and [`HybridCiphertext`]
/// (sent to the peer in the handshake message).
pub fn hybrid_encapsulate<R>(
    peer_x25519_pk: &[u8; 32],
    peer_mlkem_pk: &[u8],
    session_info: &[u8],
    rng: &mut R,
) -> Result<(HybridSharedSecret, HybridCiphertext)>
where
    R: rand_core::CryptoRng + rand_core::RngCore + ?Sized,
{
    let ephemeral_secret = X25519StaticSecret::random_from_rng(&mut *rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let peer_x25519_pk = X25519PublicKey::from(*peer_x25519_pk);
    let ecdh_secret = ephemeral_secret.diffie_hellman(&peer_x25519_pk);

    if !ecdh_secret.was_contributory() {
        return Err(CryptoError::KemFailure);
    }

    let peer_mlkem_pk = mlkem_public_key_from_bytes(peer_mlkem_pk)?;
    let (mlkem_ct, mlkem_secret): (ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey) =
        peer_mlkem_pk.encapsulate();
    let session_key = kdf::derive_session_key(
        &ecdh_secret.to_bytes(),
        mlkem_secret.as_slice(),
        session_info,
    )?;

    Ok((
        HybridSharedSecret { session_key },
        HybridCiphertext {
            x25519_epk: ephemeral_public,
            mlkem_ct: mlkem_ct.as_slice().to_vec(),
        },
    ))
}

/// Decapsulate a [`HybridCiphertext`] using this node's static keys.
pub fn hybrid_decapsulate(
    ct: &HybridCiphertext,
    x25519_sk: &[u8; 32],
    mlkem_sk: &[u8],
    session_info: &[u8],
) -> Result<HybridSharedSecret> {
    let x25519_sk = X25519StaticSecret::from(*x25519_sk);
    let peer_x25519_pk = X25519PublicKey::from(ct.x25519_epk);
    let ecdh_secret = x25519_sk.diffie_hellman(&peer_x25519_pk);

    if !ecdh_secret.was_contributory() {
        return Err(CryptoError::KemFailure);
    }

    let mlkem_seed: [u8; MLKEM_SEED_LEN] =
        mlkem_sk.try_into().map_err(|_| CryptoError::KemFailure)?;
    let mlkem_sk = mlkem_secret_from_seed(&mlkem_seed);
    let mlkem_ct: ml_kem::ml_kem_768::Ciphertext = ct
        .mlkem_ct
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KemFailure)?;
    let mlkem_secret = mlkem_sk.decapsulate(&mlkem_ct);
    let session_key = kdf::derive_session_key(
        &ecdh_secret.to_bytes(),
        mlkem_secret.as_slice(),
        session_info,
    )?;

    Ok(HybridSharedSecret { session_key })
}

fn validate_mlkem_public_key(bytes: &[u8]) -> Result<()> {
    let _ = mlkem_public_key_from_bytes(bytes)?;
    Ok(())
}

fn mlkem_public_key_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey768> {
    let key = bytes
        .try_into()
        .map_err(|_| CryptoError::Encoding("invalid ML-KEM public key length".into()))?;
    EncapsulationKey768::new(&key)
        .map_err(|_| CryptoError::Encoding("invalid ML-KEM public key".into()))
}

fn mlkem_secret_from_seed(seed: &[u8; MLKEM_SEED_LEN]) -> DecapsulationKey768 {
    let seed: ml_kem::Seed = (*seed).into();
    DecapsulationKey768::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::{hybrid_decapsulate, hybrid_encapsulate, HybridPublicKey, HybridSecretKey};

    #[test]
    fn hybrid_secret_key_round_trips() {
        let mut rng = rand::thread_rng();
        let (secret, public) = HybridSecretKey::generate(&mut rng).expect("key generation");

        let restored = HybridSecretKey::from_bytes(&secret.to_bytes()).expect("decode");

        assert_eq!(
            public.to_bytes(),
            restored.public_key().expect("derive public").to_bytes()
        );
    }

    #[test]
    fn hybrid_public_key_round_trips() {
        let mut rng = rand::thread_rng();
        let (_secret, public) = HybridSecretKey::generate(&mut rng).expect("key generation");

        let restored = HybridPublicKey::from_bytes(&public.to_bytes()).expect("decode");

        assert_eq!(public.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn hybrid_kem_round_trip_matches() {
        let mut rng = rand::thread_rng();
        let (responder_secret, responder_public) =
            HybridSecretKey::generate(&mut rng).expect("key generation");
        let session_info = b"freeq handshake test";

        let (initiator_shared, ct) = hybrid_encapsulate(
            &responder_public.x25519_public_key(),
            responder_public.mlkem_public_key(),
            session_info,
            &mut rng,
        )
        .expect("encapsulate");
        let responder_bytes = responder_secret.to_bytes();
        let responder_mlkem_seed = &responder_bytes[32..];
        let responder_shared = hybrid_decapsulate(
            &ct,
            &responder_bytes[..32].try_into().expect("x25519 secret"),
            responder_mlkem_seed,
            session_info,
        )
        .expect("decapsulate");

        assert_eq!(initiator_shared.session_key, responder_shared.session_key);
    }
}
