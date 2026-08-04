//! Per-peer QUIC connection state + datagram transport.
//!
//! # Battlefield path-loss timing
//!
//! FreeQ targets **authenticated rejoin within 3 seconds** after a path becomes
//! usable again (DoW intermittent-link objective). Path-loss detection and
//! keepalives are therefore aggressive:
//!
//! - keepalives every [`QUIC_KEEPALIVE_INTERVAL`] so NAT mappings stay warm and
//!   dead paths are noticed quickly
//! - idle timeout [`QUIC_IDLE_TIMEOUT`] so a blackholed path cannot look "up"
//!   for minutes
//!
//! Security over performance: a flap causes a **full** FreeQ handshake on
//! rejoin, never a silent reuse of dead session keys.

use crate::{Result, TransportError};
use bytes::Bytes;
use std::time::Duration;

/// QUIC max idle time without progress.
///
/// Sized for battlefield path-loss detection: a blackholed UDP path must not
/// appear healthy for long. Keepalives are shorter than this so healthy
/// sessions stay open.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Keepalive interval to keep NAT mappings warm and surface dead paths.
pub const QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_millis(400);

/// Operator budget: authenticated rejoin after known path loss / restore.
pub const BATTLEFIELD_REJOIN_BUDGET: Duration = Duration::from_secs(3);

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
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.send_timeout(data, QUIC_IDLE_TIMEOUT).await
    }

    /// Send a packet (send_datagram is synchronous in quinn 0.11).
    pub async fn send_timeout(&self, data: Bytes, _timeout: Duration) -> Result<()> {
        self.connection
            .send_datagram(data)
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Receive the next packet from the remote peer.
    pub async fn recv(&self) -> Result<Bytes> {
        self.recv_timeout(QUIC_IDLE_TIMEOUT).await
    }

    /// Receive the next packet with an explicit timeout.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Bytes> {
        tokio::time::timeout(timeout, self.connection.read_datagram())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Remote socket address for this connection.
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
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
