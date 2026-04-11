//! Peer registry — the set of known, trusted peers and their public keys.

use crate::Result;

/// A registered peer's identity information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerEntry {
    /// Human-readable peer name from the config file.
    pub name: String,
    /// ML-DSA-65 public key bytes (used to verify handshake signatures).
    pub identity_pubkey: Vec<u8>,
    /// ML-KEM-768 public key bytes (used in hybrid KEM encapsulation).
    pub kem_pubkey: Vec<u8>,
    /// IP address or hostname for dialing this peer.
    pub endpoint: Option<String>,
    /// Allowed IP prefixes routed through this peer.
    pub allowed_ips: Vec<ipnetwork::IpNetwork>,
}

/// The in-memory peer registry.
///
/// Loaded from the TOML config at startup; updated dynamically via `freeq-api`.
pub struct PeerRegistry {
    // TODO(v0.1): Vec<PeerEntry> or HashMap<fingerprint, PeerEntry>
    _private: (),
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Add a peer to the registry.
    pub fn add_peer(&mut self, _peer: PeerEntry) {
        todo!("registry add peer")
    }

    /// Look up a peer by their ML-DSA-65 public key fingerprint.
    pub fn lookup_by_key(&self, _fingerprint: &[u8]) -> Option<&PeerEntry> {
        todo!("registry lookup")
    }

    /// Verify a peer's signature in constant time.
    pub fn verify_signature(
        &self,
        _peer_name: &str,
        _msg: &[u8],
        _sig: &[u8],
    ) -> Result<()> {
        todo!("registry verify signature")
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
