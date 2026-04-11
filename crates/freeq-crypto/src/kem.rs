//! Hybrid KEM: X25519 (classical) + ML-KEM-768 (post-quantum).
//!
//! Both shared secrets are combined via HKDF-SHA256 into a single session key.
//! Security holds if *either* algorithm remains unbroken.

use zeroize::ZeroizeOnDrop;

use crate::Result;

/// Combined output of a hybrid KEM encapsulation.
#[derive(ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    /// The 32-byte session key derived by HKDF over both KEM outputs.
    pub session_key: [u8; 32],
}

/// Ciphertext produced by [`hybrid_encapsulate`], sent to the remote peer.
pub struct HybridCiphertext {
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_epk: [u8; 32],
    /// ML-KEM ciphertext (size varies by parameter set).
    pub mlkem_ct: Vec<u8>,
}

/// Encapsulate a shared secret for `peer_x25519_pk` and `peer_mlkem_pk`.
///
/// Returns the [`HybridSharedSecret`] (kept local) and [`HybridCiphertext`]
/// (sent to the peer in the handshake message).
///
/// # Arguments
/// * `peer_x25519_pk`  – peer's long-term or ephemeral X25519 public key
/// * `peer_mlkem_pk`   – peer's ML-KEM-768 public key bytes
/// * `session_info`    – domain-separation label for HKDF (e.g. `b"freeq-v1"`)
/// * `rng`             – cryptographically-secure RNG
pub fn hybrid_encapsulate(
    _peer_x25519_pk: &[u8; 32],
    _peer_mlkem_pk: &[u8],
    _session_info: &[u8],
    _rng: &mut impl rand_core::CryptoRngCore,
) -> Result<(HybridSharedSecret, HybridCiphertext)> {
    // TODO(v0.1): implement using x25519-dalek + ml-kem crates.
    // Steps:
    //   1. Generate ephemeral X25519 keypair.
    //   2. Perform X25519 DH with peer_x25519_pk → ecdh_secret.
    //   3. ML-KEM encapsulate(peer_mlkem_pk) → (mlkem_secret, mlkem_ct).
    //   4. HKDF-SHA256(ikm = ecdh_secret || mlkem_secret, info = session_info)
    //      → session_key[32].
    //   5. Zeroize ecdh_secret and mlkem_secret.
    todo!("hybrid KEM encapsulate")
}

/// Decapsulate a [`HybridCiphertext`] using this node's static keys.
///
/// # Arguments
/// * `ct`             – ciphertext received from the remote peer
/// * `x25519_sk`      – this node's X25519 static secret key
/// * `mlkem_sk`       – this node's ML-KEM-768 decapsulation key bytes
/// * `session_info`   – must match the value used during encapsulation
pub fn hybrid_decapsulate(
    _ct: &HybridCiphertext,
    _x25519_sk: &[u8; 32],
    _mlkem_sk: &[u8],
    _session_info: &[u8],
) -> Result<HybridSharedSecret> {
    // TODO(v0.1): implement using x25519-dalek + ml-kem crates.
    todo!("hybrid KEM decapsulate")
}
