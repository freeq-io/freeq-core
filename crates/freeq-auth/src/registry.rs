//! Peer registry — the set of known, trusted peers and their public keys.

use crate::Result;
use std::collections::HashMap;

/// Length of the peer fingerprint used for lookups.
pub const FINGERPRINT_LEN: usize = 32;

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
    peers_by_name: HashMap<String, StoredPeer>,
    names_by_fingerprint: HashMap<[u8; FINGERPRINT_LEN], String>,
}

#[derive(Clone)]
struct StoredPeer {
    entry: PeerEntry,
    identity_key: freeq_crypto::sign::IdentityPublicKey,
    fingerprint: [u8; FINGERPRINT_LEN],
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            peers_by_name: HashMap::new(),
            names_by_fingerprint: HashMap::new(),
        }
    }

    /// Add a peer to the registry.
    pub fn add_peer(&mut self, peer: PeerEntry) -> Result<()> {
        let identity_key =
            freeq_crypto::sign::IdentityPublicKey::from_bytes(&peer.identity_pubkey)?;
        let fingerprint = fingerprint_for_key(&peer.identity_pubkey);

        if let Some(previous) = self.peers_by_name.insert(
            peer.name.clone(),
            StoredPeer {
                entry: peer.clone(),
                identity_key,
                fingerprint,
            },
        ) {
            self.names_by_fingerprint.remove(&previous.fingerprint);
        }

        self.names_by_fingerprint
            .insert(fingerprint, peer.name.clone());
        Ok(())
    }

    /// Return whether a peer name is already present in the registry.
    pub fn contains_peer(&self, peer_name: &str) -> bool {
        self.peers_by_name.contains_key(peer_name)
    }

    /// Remove a peer from the registry by name.
    pub fn remove_peer(&mut self, peer_name: &str) -> bool {
        let Some(previous) = self.peers_by_name.remove(peer_name) else {
            return false;
        };
        self.names_by_fingerprint.remove(&previous.fingerprint);
        true
    }

    /// Look up a peer by their ML-DSA-65 public key fingerprint.
    pub fn lookup_by_key(&self, fingerprint: &[u8]) -> Option<&PeerEntry> {
        let fingerprint = <[u8; FINGERPRINT_LEN]>::try_from(fingerprint).ok()?;
        let peer_name = self.names_by_fingerprint.get(&fingerprint)?;
        self.peers_by_name.get(peer_name).map(|peer| &peer.entry)
    }

    /// Verify a peer's signature in constant time.
    pub fn verify_signature(&self, peer_name: &str, msg: &[u8], sig: &[u8]) -> Result<()> {
        let peer = self
            .peers_by_name
            .get(peer_name)
            .ok_or_else(|| crate::AuthError::UnknownPeer(peer_name.into()))?;

        peer.identity_key
            .verify_message(msg, &freeq_crypto::sign::Signature(sig.to_vec()))?;
        Ok(())
    }

    /// Look up a peer by fingerprint and return both their name and entry.
    pub fn lookup_name_and_peer(&self, fingerprint: &[u8]) -> Option<(&str, &PeerEntry)> {
        let fingerprint = <[u8; FINGERPRINT_LEN]>::try_from(fingerprint).ok()?;
        let peer_name = self.names_by_fingerprint.get(&fingerprint)?;
        self.peers_by_name
            .get_key_value(peer_name)
            .map(|(name, peer)| (name.as_str(), &peer.entry))
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn fingerprint_for_key(public_key: &[u8]) -> [u8; FINGERPRINT_LEN] {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(public_key);
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::{fingerprint_for_key, PeerEntry, PeerRegistry};

    fn sample_peer(name: &str) -> (freeq_crypto::sign::IdentityKeypair, PeerEntry) {
        let mut rng = rand::thread_rng();
        let (keypair, _public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("key generation");
        let public_key = keypair.public_key();

        (
            keypair,
            PeerEntry {
                name: name.into(),
                identity_pubkey: public_key.to_bytes(),
                kem_pubkey: vec![1, 2, 3],
                endpoint: Some("peer.example.com:51820".into()),
                allowed_ips: vec!["10.0.0.2/32".parse().expect("cidr")],
            },
        )
    }

    #[test]
    fn registry_looks_up_peer_by_fingerprint() {
        let (_keypair, peer) = sample_peer("lon-01");
        let fingerprint = fingerprint_for_key(&peer.identity_pubkey);
        let mut registry = PeerRegistry::new();

        registry.add_peer(peer.clone()).expect("add peer");

        let found = registry.lookup_by_key(&fingerprint).expect("peer lookup");
        assert_eq!(found.name, peer.name);
    }

    #[test]
    fn registry_rejects_unknown_peer_verification() {
        let registry = PeerRegistry::new();

        let err = registry
            .verify_signature("missing", b"payload", b"signature")
            .expect_err("verification should fail");

        assert!(matches!(err, crate::AuthError::UnknownPeer(_)));
    }

    #[test]
    fn registry_verifies_known_peer_signatures() {
        let (keypair, peer) = sample_peer("lon-01");
        let mut registry = PeerRegistry::new();
        let msg = b"cloaked payload";
        let sig = keypair.sign_message(msg).expect("signature");

        registry.add_peer(peer.clone()).expect("add peer");
        registry
            .verify_signature(&peer.name, msg, &sig.0)
            .expect("signature verification");
    }
}
