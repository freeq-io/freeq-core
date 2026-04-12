//! Transport error types.

use thiserror::Error;

/// Errors returned by freeq-transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to bind a QUIC endpoint.
    #[error("failed to bind QUIC endpoint: {0}")]
    Bind(String),

    /// Connection to a peer failed.
    #[error("connection to {peer} failed: {reason}")]
    Connect {
        /// The peer address or name that could not be reached.
        peer: String,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// An established connection was lost unexpectedly.
    #[error("connection lost: {0}")]
    ConnectionLost(String),

    /// TLS/crypto configuration error.
    #[error("TLS configuration error: {0}")]
    Tls(String),

    /// I/O error at the socket level.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
