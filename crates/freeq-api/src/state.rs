//! Shared runtime state exposed through the local REST API.

use crate::models::{AlgorithmResponse, PeerSummary, StatusResponse, TunnelStats};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Shared mutable API state used by the daemon and request handlers.
pub type SharedApiState = Arc<RwLock<ApiState>>;

/// In-memory runtime snapshot exposed through API reads.
pub struct ApiState {
    start_time: Instant,
    node_name: String,
    version: String,
    kem_algorithm: String,
    sign_algorithm: String,
    bulk_algorithm: String,
    peers: HashMap<String, PeerRuntime>,
    tunnels: HashMap<String, TunnelRuntime>,
}

struct PeerRuntime {
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    connected: bool,
    last_handshake: Option<DateTime<Utc>>,
}

struct TunnelRuntime {
    bytes_sent: u64,
    bytes_received: u64,
    latency_ms: Option<f64>,
    packet_loss_pct: Option<f64>,
}

impl ApiState {
    /// Build a fresh state snapshot from the daemon configuration.
    pub fn new(
        node_name: String,
        version: String,
        kem_algorithm: String,
        sign_algorithm: String,
        bulk_algorithm: String,
        peers: Vec<PeerSummary>,
    ) -> Self {
        let peers = peers
            .into_iter()
            .map(|peer| {
                (
                    peer.name.clone(),
                    PeerRuntime {
                        endpoint: peer.endpoint,
                        allowed_ips: peer.allowed_ips,
                        connected: peer.connected,
                        last_handshake: peer
                            .last_handshake
                            .as_deref()
                            .and_then(|timestamp| {
                                chrono::DateTime::parse_from_rfc3339(timestamp).ok()
                            })
                            .map(|timestamp| timestamp.with_timezone(&Utc)),
                    },
                )
            })
            .collect();

        Self {
            start_time: Instant::now(),
            node_name,
            version,
            kem_algorithm,
            sign_algorithm,
            bulk_algorithm,
            peers,
            tunnels: HashMap::new(),
        }
    }

    /// Create a shared API state handle.
    pub fn shared(self) -> SharedApiState {
        Arc::new(RwLock::new(self))
    }

    /// Mark a peer as connected and update their latest handshake time.
    pub fn mark_peer_connected(&mut self, peer_name: &str) {
        let now = Utc::now();
        if let Some(peer) = self.peers.get_mut(peer_name) {
            peer.connected = true;
            peer.last_handshake = Some(now);
        }

        self.tunnels
            .entry(peer_name.to_string())
            .or_insert(TunnelRuntime {
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                packet_loss_pct: None,
            });
    }

    /// Mark a peer as disconnected.
    pub fn mark_peer_disconnected(&mut self, peer_name: &str) {
        if let Some(peer) = self.peers.get_mut(peer_name) {
            peer.connected = false;
        }
    }

    /// Increment transmitted byte counters for a peer tunnel.
    pub fn add_bytes_sent(&mut self, peer_name: &str, bytes: u64) {
        self.tunnels
            .entry(peer_name.to_string())
            .or_insert(TunnelRuntime {
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                packet_loss_pct: None,
            })
            .bytes_sent += bytes;
    }

    /// Increment received byte counters for a peer tunnel.
    pub fn add_bytes_received(&mut self, peer_name: &str, bytes: u64) {
        self.tunnels
            .entry(peer_name.to_string())
            .or_insert(TunnelRuntime {
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                packet_loss_pct: None,
            })
            .bytes_received += bytes;
    }

    /// Build the current `/v1/status` response.
    pub fn status_response(&self) -> StatusResponse {
        StatusResponse {
            name: self.node_name.clone(),
            version: self.version.clone(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            kem_algorithm: self.kem_algorithm.clone(),
            sign_algorithm: self.sign_algorithm.clone(),
            bulk_algorithm: self.bulk_algorithm.clone(),
            peer_count: self.peers.len(),
            tunnel_count: self.tunnels.len(),
        }
    }

    /// Build the current `/v1/algorithm` response.
    pub fn algorithm_response(&self) -> AlgorithmResponse {
        AlgorithmResponse {
            kem_algorithm: self.kem_algorithm.clone(),
            sign_algorithm: self.sign_algorithm.clone(),
            bulk_algorithm: self.bulk_algorithm.clone(),
        }
    }

    /// Build the current `/v1/peers` response.
    pub fn peer_summaries(&self) -> Vec<PeerSummary> {
        let mut peers: Vec<_> = self
            .peers
            .iter()
            .map(|(name, peer)| PeerSummary {
                name: name.clone(),
                endpoint: peer.endpoint.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                connected: peer.connected,
                last_handshake: peer.last_handshake.map(|ts| ts.to_rfc3339()),
            })
            .collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name));
        peers
    }

    /// Build the current `/v1/tunnels` response.
    pub fn tunnel_stats(&self) -> Vec<TunnelStats> {
        let mut tunnels: Vec<_> = self
            .tunnels
            .iter()
            .map(|(peer, tunnel)| TunnelStats {
                peer: peer.clone(),
                bytes_sent: tunnel.bytes_sent,
                bytes_received: tunnel.bytes_received,
                latency_ms: tunnel.latency_ms,
                packet_loss_pct: tunnel.packet_loss_pct,
            })
            .collect();
        tunnels.sort_by(|a, b| a.peer.cmp(&b.peer));
        tunnels
    }

    /// Build a Prometheus-compatible text exposition snapshot.
    pub fn metrics_exposition(&self) -> String {
        let connected_peers = self.peers.values().filter(|peer| peer.connected).count();

        let mut lines = vec![
            "# HELP freeq_uptime_seconds Seconds since the daemon started.".to_string(),
            "# TYPE freeq_uptime_seconds gauge".to_string(),
            format!(
                "freeq_uptime_seconds {}",
                self.start_time.elapsed().as_secs()
            ),
            "# HELP freeq_configured_peers Total configured peers.".to_string(),
            "# TYPE freeq_configured_peers gauge".to_string(),
            format!("freeq_configured_peers {}", self.peers.len()),
            "# HELP freeq_connected_peers Peers with an active tunnel.".to_string(),
            "# TYPE freeq_connected_peers gauge".to_string(),
            format!("freeq_connected_peers {}", connected_peers),
            "# HELP freeq_active_tunnels Total active tunnel entries.".to_string(),
            "# TYPE freeq_active_tunnels gauge".to_string(),
            format!("freeq_active_tunnels {}", self.tunnels.len()),
            "# HELP freeq_peer_connected Peer connection state (1=connected, 0=disconnected)."
                .to_string(),
            "# TYPE freeq_peer_connected gauge".to_string(),
            "# HELP freeq_tunnel_bytes_sent_total Bytes sent through each peer tunnel.".to_string(),
            "# TYPE freeq_tunnel_bytes_sent_total counter".to_string(),
            "# HELP freeq_tunnel_bytes_received_total Bytes received through each peer tunnel."
                .to_string(),
            "# TYPE freeq_tunnel_bytes_received_total counter".to_string(),
        ];

        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (peer_name, peer) in peers {
            lines.push(format!(
                "freeq_peer_connected{{peer=\"{}\"}} {}",
                peer_name,
                if peer.connected { 1 } else { 0 }
            ));
        }

        let mut tunnels: Vec<_> = self.tunnels.iter().collect();
        tunnels.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (peer_name, tunnel) in tunnels {
            lines.push(format!(
                "freeq_tunnel_bytes_sent_total{{peer=\"{}\"}} {}",
                peer_name, tunnel.bytes_sent
            ));
            lines.push(format!(
                "freeq_tunnel_bytes_received_total{{peer=\"{}\"}} {}",
                peer_name, tunnel.bytes_received
            ));
        }

        lines.push(String::new());
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::ApiState;
    use crate::models::PeerSummary;

    #[test]
    fn state_tracks_peer_and_tunnel_counters() {
        let mut state = ApiState::new(
            "nyc-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "chacha20-poly1305".into(),
            vec![PeerSummary {
                name: "lon-01".into(),
                endpoint: Some("lon.example.com:51820".into()),
                allowed_ips: vec!["10.0.0.2/32".into()],
                connected: false,
                last_handshake: None,
            }],
        );

        state.mark_peer_connected("lon-01");
        state.add_bytes_sent("lon-01", 128);
        state.add_bytes_received("lon-01", 256);

        let status = state.status_response();
        let algorithms = state.algorithm_response();
        let peers = state.peer_summaries();
        let tunnels = state.tunnel_stats();
        let metrics = state.metrics_exposition();

        assert_eq!(status.peer_count, 1);
        assert_eq!(status.tunnel_count, 1);
        assert_eq!(algorithms.kem_algorithm, "ml-kem-768");
        assert_eq!(algorithms.sign_algorithm, "ml-dsa-65");
        assert_eq!(algorithms.bulk_algorithm, "chacha20-poly1305");
        assert!(peers[0].connected);
        assert!(peers[0].last_handshake.is_some());
        assert_eq!(tunnels[0].bytes_sent, 128);
        assert_eq!(tunnels[0].bytes_received, 256);
        assert!(metrics.contains("freeq_connected_peers 1"));
        assert!(metrics.contains("freeq_tunnel_bytes_sent_total{peer=\"lon-01\"} 128"));
    }
}
