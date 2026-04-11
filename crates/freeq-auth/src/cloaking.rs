//! Endpoint cloaking — silent drop of unauthenticated packets.
//!
//! This module implements the core security invariant: *no response is
//! ever sent to an unauthenticated sender*. The node is invisible at the
//! network level until a peer presents a valid ML-DSA-65 signature.

use crate::{registry::PeerRegistry, AuthError, Result};

/// Decides whether an inbound packet should be processed or dropped.
///
/// Returns `Ok(())` if the packet is from a registered, authenticated peer.
/// Returns `Err(AuthError::Cloaked)` if it should be silently dropped.
///
/// This function must be called *before* any response is issued — including
/// ICMP errors, QUIC handshake responses, or TLS client hellos.
pub fn check_inbound(
    _registry: &PeerRegistry,
    _src_addr: std::net::SocketAddr,
    _packet: &[u8],
) -> Result<()> {
    // TODO(v0.1): parse leading ML-DSA-65 signature from packet header,
    // look up peer by src_addr or inline public key fingerprint,
    // call registry.verify_signature(peer_id, packet_without_sig, sig).
    //
    // On any failure: return Err(AuthError::Cloaked) — never log the sender.
    // Logging would create a side channel revealing the node's existence.
    todo!("cloaking check")
}
