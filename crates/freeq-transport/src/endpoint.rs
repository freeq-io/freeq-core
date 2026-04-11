//! QUIC endpoint — the local UDP socket that accepts incoming connections.

use crate::Result;

/// The local QUIC endpoint, bound to a UDP port.
///
/// Accepts incoming peer connections and initiates outgoing ones.
pub struct Endpoint {
    // TODO(v0.1): wrap quinn::Endpoint
    _private: (),
}

impl Endpoint {
    /// Bind a new QUIC endpoint to `addr`.
    ///
    /// `addr` is typically `0.0.0.0:51820` (user-configurable).
    pub async fn bind(_addr: std::net::SocketAddr) -> Result<Self> {
        todo!("QUIC endpoint bind")
    }

    /// Accept the next incoming peer connection.
    pub async fn accept(&self) -> Result<crate::connection::PeerConnection> {
        todo!("QUIC accept")
    }

    /// Connect to a remote peer at `addr`.
    pub async fn connect(
        &self,
        _addr: std::net::SocketAddr,
    ) -> Result<crate::connection::PeerConnection> {
        todo!("QUIC connect")
    }
}
