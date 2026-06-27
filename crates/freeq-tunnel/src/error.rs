//! Tunnel error types.

use thiserror::Error;

/// Errors returned by freeq-tunnel operations.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Failed to open or configure the TUN interface.
    #[error("TUN interface error: {0}")]
    Interface(String),

    /// Packet routing failure (no matching peer for destination IP).
    #[error("no route to {dest}")]
    NoRoute {
        /// The destination IP address that could not be routed.
        dest: std::net::IpAddr,
    },

    /// Packet buffer ended before a required header could be read.
    #[error("packet buffer underflow")]
    BufferUnderflow,

    /// Packet failed basic structural validation.
    #[error("malformed packet: {0}")]
    MalformedPacket(String),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Crypto error while encrypting or decrypting a packet.
    #[error("crypto error: {0}")]
    Crypto(#[from] freeq_crypto::CryptoError),

    /// Transport framing or sending error.
    #[error("transport error: {0}")]
    Transport(#[from] freeq_transport::TransportError),
}
