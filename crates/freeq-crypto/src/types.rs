//! Cryptographic key container types.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Test and FFI-friendly keypair container with automatic secret erasure.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FreeQKeyPair {
    /// Raw X25519 private key bytes.
    pub x25519_private: [u8; 32],
    /// Raw X25519 public key bytes.
    #[zeroize(skip)]
    pub x25519_public: [u8; 32],
    /// Raw ML-KEM private key bytes.
    pub mlkem_private: [u8; 2400],
}

impl FreeQKeyPair {
    /// Generate ephemeral key material for local test and benchmark harnesses.
    pub fn generate_ephemeral_test_pair() -> crate::Result<Self> {
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        let mut x25519_private = [0u8; 32];
        let mut x25519_public = [0u8; 32];
        let mut mlkem_private = [0u8; 2400];

        rng.fill_bytes(&mut x25519_private);
        rng.fill_bytes(&mut x25519_public);
        rng.fill_bytes(&mut mlkem_private);

        Ok(Self {
            x25519_private,
            x25519_public,
            mlkem_private,
        })
    }
}
