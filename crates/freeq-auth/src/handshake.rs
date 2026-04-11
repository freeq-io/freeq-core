//! 8-step mutual authentication and hybrid KEM handshake (§4.2).

use crate::Result;

/// State machine for the initiating side of the handshake (Node A).
pub struct InitiatorHandshake {
    // TODO(v0.1): track step, ephemeral keys, nonce
    _private: (),
}

/// State machine for the responding side of the handshake (Node B).
pub struct ResponderHandshake {
    _private: (),
}

/// The session keys derived at the end of a successful handshake.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SessionKeys {
    /// 32-byte outbound bulk encryption key.
    pub outbound: [u8; 32],
    /// 32-byte inbound bulk encryption key.
    pub inbound: [u8; 32],
}

impl InitiatorHandshake {
    /// Begin a new handshake as the initiating node.
    ///
    /// Step 1: emit ML-DSA-65 signature over (nonce || A_kem_pubkey).
    pub fn new(
        _identity_sk: &freeq_crypto::sign::IdentityKeypair,
        _kem_pubkey: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        // Returns (state, message_to_send)
        todo!("handshake init step 1")
    }

    /// Process Node B's response (steps 3-4) and emit KEM ciphertext (step 5).
    pub fn process_response(self, _msg: &[u8]) -> Result<(Self, Vec<u8>)> {
        todo!("handshake init steps 3-5")
    }

    /// Finalize: derive session keys after both sides complete the hybrid KEM.
    pub fn finalize(self) -> Result<SessionKeys> {
        todo!("handshake init finalize")
    }
}

impl ResponderHandshake {
    /// Process Node A's initial message (steps 2-3) and emit response.
    pub fn process_init(
        _identity_sk: &freeq_crypto::sign::IdentityKeypair,
        _registry: &crate::registry::PeerRegistry,
        _msg: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        // Returns (state, message_to_send)
        todo!("handshake responder steps 2-3")
    }

    /// Process Node A's KEM ciphertext (steps 5-8) and finalize.
    pub fn process_kem(self, _msg: &[u8]) -> Result<SessionKeys> {
        todo!("handshake responder steps 5-8")
    }
}
