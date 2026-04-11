//! # freeq-transport
//!
//! QUIC-based transport layer for the FreeQ overlay network.
//!
//! Responsibilities:
//! - Establish and maintain QUIC connections (RFC 9000) via the `quinn` crate
//! - Manage the connection pool (idle connections, keepalive, reconnects)
//! - NAT traversal via QUIC's UDP-based transport
//! - Session resumption and 0-RTT (v0.2)
//! - io_uring zero-copy I/O on Linux 5.19+ (v0.2)

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used)]

pub mod connection;
pub mod endpoint;
pub mod error;
pub mod pool;

pub use error::TransportError;

/// Library-wide result type.
pub type Result<T> = std::result::Result<T, TransportError>;
