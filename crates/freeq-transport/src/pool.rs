//! Connection pool — reuse live QUIC connections to known peers.

use crate::{connection::PeerConnection, Result};

/// Manages live connections to all known peers.
///
/// On cache miss, opens a new QUIC connection and inserts it into the pool.
pub struct ConnectionPool {
    // TODO(v0.1): HashMap<PeerId, PeerConnection> + cleanup task
    _private: (),
}

impl ConnectionPool {
    /// Create an empty connection pool.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Get or create a connection to `peer_id`.
    pub async fn get_or_connect(
        &mut self,
        _peer_id: &str,
        _addr: std::net::SocketAddr,
    ) -> Result<&PeerConnection> {
        todo!("pool get_or_connect")
    }

    /// Remove a connection from the pool (e.g. after detecting it is dead).
    pub fn evict(&mut self, _peer_id: &str) {
        todo!("pool evict")
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
