//! Per-peer QUIC connection state.

use crate::Result;

/// A live QUIC connection to a single remote FreeQ peer.
pub struct PeerConnection {
    // TODO(v0.1): wrap quinn::Connection + session metadata
    _private: (),
}

impl PeerConnection {
    /// Send a packet to the remote peer.
    pub async fn send(&self, _data: bytes::Bytes) -> Result<()> {
        todo!("QUIC send")
    }

    /// Receive the next packet from the remote peer.
    pub async fn recv(&self) -> Result<bytes::Bytes> {
        todo!("QUIC recv")
    }

    /// Returns `true` if the connection is currently active.
    pub fn is_alive(&self) -> bool {
        todo!("connection liveness check")
    }

    /// Gracefully close the connection.
    pub async fn close(self) -> Result<()> {
        todo!("QUIC close")
    }
}
