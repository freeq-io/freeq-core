//! Per-peer QUIC connection state.

use crate::{Result, TransportError};
use std::time::Duration;

/// Default timeouts used for transport send/receive operations.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(6);
/// Keepalive interval to keep NAT mappings warm and detect dead links quickly.
pub const QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
/// Short receive poll interval used by higher layers to notice dead peers promptly.
pub const QUIC_RECV_POLL_TIMEOUT: Duration = Duration::from_secs(2);

/// A live QUIC connection to a single remote FreeQ peer.
#[derive(Clone, Debug)]
pub struct PeerConnection {
    connection: quinn::Connection,
}

impl PeerConnection {
    pub(crate) fn new(connection: quinn::Connection) -> Self {
        Self { connection }
    }

    /// Send a packet to the remote peer.
    pub async fn send(&self, data: bytes::Bytes) -> Result<()> {
        self.send_timeout(data, QUIC_IDLE_TIMEOUT).await
    }

    /// Send a packet with an explicit timeout.
    pub async fn send_timeout(&self, data: bytes::Bytes, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.connection.send_datagram_wait(data))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Receive the next packet from the remote peer.
    pub async fn recv(&self) -> Result<bytes::Bytes> {
        self.recv_timeout(QUIC_IDLE_TIMEOUT).await
    }

    /// Receive the next packet with an explicit timeout.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<bytes::Bytes> {
        tokio::time::timeout(timeout, self.connection.read_datagram())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Returns `true` if the connection is currently active.
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Gracefully close the connection.
    pub async fn close(&self) -> Result<()> {
        self.connection.close(0u32.into(), b"shutdown");
        let _ = self.connection.closed().await;
        Ok(())
    }
}
