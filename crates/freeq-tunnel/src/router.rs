//! Packet router — maps destination IP addresses to FreeQ peer IDs.

use std::{collections::HashMap, net::IpAddr};
use crate::Result;

/// The routing table: maps each allowed IP range to a peer identity.
pub struct Router {
    // TODO(v0.1): implement trie or prefix map for subnet routing
    _private: (),
}

impl Router {
    /// Build a router from the active peer configuration.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Look up the peer ID for a destination IP.
    ///
    /// Returns `None` if the packet is not destined for any known peer
    /// (should be dropped or forwarded to a default gateway).
    pub fn lookup(&self, _dest: IpAddr) -> Option<&str> {
        todo!("route lookup")
    }

    /// Add or update a routing entry.
    pub fn insert(&mut self, _prefix: ipnetwork::IpNetwork, _peer_id: String) {
        todo!("route insert")
    }

    /// Remove all routes for a given peer.
    pub fn remove_peer(&mut self, _peer_id: &str) {
        todo!("route remove peer")
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
