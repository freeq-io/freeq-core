//! Auth error types.

use thiserror::Error;

/// Errors returned by freeq-auth operations.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Packet silently dropped — no valid ML-DSA-65 signature from a known peer.
    #[error("unauthenticated packet dropped (cloaking active)")]
    Cloaked,

    /// Peer is not in the registry (unknown public key).
    #[error("unknown peer: {0}")]
    UnknownPeer(String),

    /// Handshake authentication step failed.
    #[error("handshake failed at step {step}: {reason}")]
    HandshakeFailed { step: u8, reason: String },

    /// Underlying crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] freeq_crypto::CryptoError),
}
