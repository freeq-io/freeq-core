//! Packet router — maps destination IP addresses to FreeQ peer IDs.

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The routing table: maps each allowed IP range to a peer identity.
///
/// Routes are stored in prefix buckets so lookup can perform longest-prefix
/// matching without scanning every configured subnet.
pub struct Router {
    ipv4_routes: BTreeMap<u8, HashMap<u32, String>>,
    ipv6_routes: BTreeMap<u8, HashMap<u128, String>>,
    peer_prefixes: HashMap<String, Vec<IpNetwork>>,
}

impl Router {
    /// Build a router from the active peer configuration.
    pub fn new() -> Self {
        Self {
            ipv4_routes: BTreeMap::new(),
            ipv6_routes: BTreeMap::new(),
            peer_prefixes: HashMap::new(),
        }
    }

    /// Look up the peer ID for a destination IP.
    ///
    /// Returns `None` if the packet is not destined for any known peer
    /// (should be dropped or forwarded to a default gateway).
    pub fn lookup(&self, dest: IpAddr) -> Option<&str> {
        match dest {
            IpAddr::V4(dest) => self.lookup_ipv4(dest),
            IpAddr::V6(dest) => self.lookup_ipv6(dest),
        }
    }

    /// Add or update a routing entry.
    pub fn insert(&mut self, prefix: IpNetwork, peer_id: String) {
        let prefix = canonicalize(prefix);
        self.remove_prefix_from_existing_owner(prefix, &peer_id);

        match prefix {
            IpNetwork::V4(prefix) => {
                self.ipv4_routes
                    .entry(prefix.prefix())
                    .or_default()
                    .insert(ipv4_bits(prefix.network()), peer_id.clone());
            }
            IpNetwork::V6(prefix) => {
                self.ipv6_routes
                    .entry(prefix.prefix())
                    .or_default()
                    .insert(ipv6_bits(prefix.network()), peer_id.clone());
            }
        }

        let peer_prefixes = self.peer_prefixes.entry(peer_id).or_default();
        if !peer_prefixes.contains(&prefix) {
            peer_prefixes.push(prefix);
        }
    }

    /// Remove all routes for a given peer.
    pub fn remove_peer(&mut self, peer_id: &str) {
        let Some(prefixes) = self.peer_prefixes.remove(peer_id) else {
            return;
        };

        for prefix in prefixes {
            match prefix {
                IpNetwork::V4(prefix) => {
                    let should_remove_bucket = self
                        .ipv4_routes
                        .get_mut(&prefix.prefix())
                        .map(|routes| {
                            routes.remove(&ipv4_bits(prefix.network()));
                            routes.is_empty()
                        })
                        .unwrap_or(false);

                    if should_remove_bucket {
                        self.ipv4_routes.remove(&prefix.prefix());
                    }
                }
                IpNetwork::V6(prefix) => {
                    let should_remove_bucket = self
                        .ipv6_routes
                        .get_mut(&prefix.prefix())
                        .map(|routes| {
                            routes.remove(&ipv6_bits(prefix.network()));
                            routes.is_empty()
                        })
                        .unwrap_or(false);

                    if should_remove_bucket {
                        self.ipv6_routes.remove(&prefix.prefix());
                    }
                }
            }
        }
    }

    fn lookup_ipv4(&self, dest: Ipv4Addr) -> Option<&str> {
        let dest_bits = ipv4_bits(dest);

        for (&prefix_len, routes) in self.ipv4_routes.iter().rev() {
            let masked = mask_ipv4(dest_bits, prefix_len);
            if let Some(peer_id) = routes.get(&masked) {
                return Some(peer_id.as_str());
            }
        }

        None
    }

    fn lookup_ipv6(&self, dest: Ipv6Addr) -> Option<&str> {
        let dest_bits = ipv6_bits(dest);

        for (&prefix_len, routes) in self.ipv6_routes.iter().rev() {
            let masked = mask_ipv6(dest_bits, prefix_len);
            if let Some(peer_id) = routes.get(&masked) {
                return Some(peer_id.as_str());
            }
        }

        None
    }

    fn remove_prefix_from_existing_owner(&mut self, prefix: IpNetwork, new_peer_id: &str) {
        let existing_owner = self
            .peer_prefixes
            .iter()
            .find(|(peer_id, prefixes)| {
                peer_id.as_str() != new_peer_id && prefixes.contains(&prefix)
            })
            .map(|(peer_id, _)| peer_id.clone());

        let Some(existing_owner) = existing_owner else {
            return;
        };

        if let Some(prefixes) = self.peer_prefixes.get_mut(&existing_owner) {
            prefixes.retain(|existing_prefix| *existing_prefix != prefix);
            if prefixes.is_empty() {
                self.peer_prefixes.remove(&existing_owner);
            }
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

fn canonicalize(prefix: IpNetwork) -> IpNetwork {
    match prefix {
        IpNetwork::V4(prefix) => IpNetwork::V4(
            Ipv4Network::new(prefix.network(), prefix.prefix()).expect("existing prefix is valid"),
        ),
        IpNetwork::V6(prefix) => IpNetwork::V6(
            Ipv6Network::new(prefix.network(), prefix.prefix()).expect("existing prefix is valid"),
        ),
    }
}

fn ipv4_bits(addr: Ipv4Addr) -> u32 {
    u32::from(addr)
}

fn ipv6_bits(addr: Ipv6Addr) -> u128 {
    u128::from(addr)
}

fn mask_ipv4(addr: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        let shift = 32 - u32::from(prefix_len);
        addr & (u32::MAX << shift)
    }
}

fn mask_ipv6(addr: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        let shift = 128 - u32::from(prefix_len);
        addr & (u128::MAX << shift)
    }
}

#[cfg(test)]
mod tests {
    use super::Router;
    use std::net::IpAddr;

    #[test]
    fn lookup_prefers_longest_ipv4_prefix_match() {
        let mut router = Router::new();
        router.insert("10.0.0.0/8".parse().expect("prefix"), "peer-a".into());
        router.insert("10.0.1.0/24".parse().expect("prefix"), "peer-b".into());

        assert_eq!(
            router.lookup(IpAddr::V4("10.0.1.42".parse().expect("ip"))),
            Some("peer-b")
        );
        assert_eq!(
            router.lookup(IpAddr::V4("10.2.1.42".parse().expect("ip"))),
            Some("peer-a")
        );
    }

    #[test]
    fn lookup_supports_ipv6_prefixes() {
        let mut router = Router::new();
        router.insert("fd00::/8".parse().expect("prefix"), "peer-v6".into());

        assert_eq!(
            router.lookup(IpAddr::V6("fd00::1234".parse().expect("ip"))),
            Some("peer-v6")
        );
        assert_eq!(
            router.lookup(IpAddr::V6("2001:db8::1".parse().expect("ip"))),
            None
        );
    }

    #[test]
    fn remove_peer_removes_all_routes_for_peer() {
        let mut router = Router::new();
        router.insert("10.0.0.0/8".parse().expect("prefix"), "peer-a".into());
        router.insert("10.1.0.0/16".parse().expect("prefix"), "peer-a".into());

        router.remove_peer("peer-a");

        assert_eq!(
            router.lookup(IpAddr::V4("10.1.2.3".parse().expect("ip"))),
            None
        );
        assert_eq!(
            router.lookup(IpAddr::V4("10.2.2.3".parse().expect("ip"))),
            None
        );
    }

    #[test]
    fn reinserting_prefix_moves_ownership_to_new_peer() {
        let mut router = Router::new();
        router.insert("10.0.0.0/24".parse().expect("prefix"), "peer-a".into());
        router.insert("10.0.0.0/24".parse().expect("prefix"), "peer-b".into());

        assert_eq!(
            router.lookup(IpAddr::V4("10.0.0.7".parse().expect("ip"))),
            Some("peer-b")
        );

        router.remove_peer("peer-b");

        assert_eq!(
            router.lookup(IpAddr::V4("10.0.0.7".parse().expect("ip"))),
            None
        );
    }
}
