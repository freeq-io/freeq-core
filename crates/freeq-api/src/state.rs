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
    counters: RuntimeCounters,
}

struct PeerRuntime {
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    connected: bool,
    last_handshake: Option<DateTime<Utc>>,
    connect_failures: u64,
    handshake_failures: u64,
    last_handshake_duration_ms: Option<f64>,
}

struct TunnelRuntime {
    bytes_sent: u64,
    bytes_received: u64,
    latency_ms: Option<f64>,
    packet_loss_pct: Option<f64>,
}

#[derive(Default)]
struct RuntimeCounters {
    incoming_accept_failures: u64,
    outbound_connect_failures: u64,
    outbound_handshake_failures: u64,
    inbound_handshake_failures: u64,
    tun_read_errors: u64,
    tun_write_errors: u64,
    packet_forward_failures: u64,
    peer_receive_errors: u64,
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
                        connect_failures: 0,
                        handshake_failures: 0,
                        last_handshake_duration_ms: None,
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
            counters: RuntimeCounters::default(),
        }
    }

    /// Create a shared API state handle.
    pub fn shared(self) -> SharedApiState {
        Arc::new(RwLock::new(self))
    }

    /// Mark a peer as connected and update their latest handshake time.
    pub fn mark_peer_connected(&mut self, peer_name: &str) {
        self.record_handshake_success(peer_name, None);
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

    /// Record a successful handshake and optional duration sample for a peer.
    pub fn record_handshake_success(&mut self, peer_name: &str, duration_ms: Option<f64>) {
        let now = Utc::now();
        if let Some(peer) = self.peers.get_mut(peer_name) {
            peer.connected = true;
            peer.last_handshake = Some(now);
            peer.last_handshake_duration_ms = duration_ms;
        }

        let tunnel = self
            .tunnels
            .entry(peer_name.to_string())
            .or_insert(TunnelRuntime {
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                packet_loss_pct: None,
            });
        if let Some(duration_ms) = duration_ms {
            tunnel.latency_ms = Some(duration_ms);
        }
    }

    /// Record an outbound connection failure for a peer.
    pub fn record_outbound_connect_failure(&mut self, peer_name: &str) {
        self.counters.outbound_connect_failures =
            self.counters.outbound_connect_failures.saturating_add(1);
        if let Some(peer) = self.peers.get_mut(peer_name) {
            peer.connect_failures = peer.connect_failures.saturating_add(1);
            peer.connected = false;
        }
    }

    /// Record a handshake failure on the inbound or outbound control path.
    pub fn record_handshake_failure(&mut self, peer_name: Option<&str>, inbound: bool) {
        if inbound {
            self.counters.inbound_handshake_failures =
                self.counters.inbound_handshake_failures.saturating_add(1);
        } else {
            self.counters.outbound_handshake_failures =
                self.counters.outbound_handshake_failures.saturating_add(1);
        }

        if let Some(peer_name) = peer_name {
            if let Some(peer) = self.peers.get_mut(peer_name) {
                peer.handshake_failures = peer.handshake_failures.saturating_add(1);
                peer.connected = false;
            }
        }
    }

    /// Record a failed incoming connection accept.
    pub fn record_incoming_accept_failure(&mut self) {
        self.counters.incoming_accept_failures =
            self.counters.incoming_accept_failures.saturating_add(1);
    }

    /// Record a TUN read error.
    pub fn record_tun_read_error(&mut self) {
        self.counters.tun_read_errors = self.counters.tun_read_errors.saturating_add(1);
    }

    /// Record a TUN write error.
    pub fn record_tun_write_error(&mut self) {
        self.counters.tun_write_errors = self.counters.tun_write_errors.saturating_add(1);
    }

    /// Record a packet forward failure.
    pub fn record_packet_forward_failure(&mut self) {
        self.counters.packet_forward_failures =
            self.counters.packet_forward_failures.saturating_add(1);
    }

    /// Record a peer receive error.
    pub fn record_peer_receive_error(&mut self) {
        self.counters.peer_receive_errors = self.counters.peer_receive_errors.saturating_add(1);
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
            "# HELP freeq_incoming_accept_failures_total Failed inbound connection accepts."
                .to_string(),
            "# TYPE freeq_incoming_accept_failures_total counter".to_string(),
            format!(
                "freeq_incoming_accept_failures_total {}",
                self.counters.incoming_accept_failures
            ),
            "# HELP freeq_outbound_connect_failures_total Failed outbound peer connects."
                .to_string(),
            "# TYPE freeq_outbound_connect_failures_total counter".to_string(),
            format!(
                "freeq_outbound_connect_failures_total {}",
                self.counters.outbound_connect_failures
            ),
            "# HELP freeq_outbound_handshake_failures_total Failed outbound handshakes."
                .to_string(),
            "# TYPE freeq_outbound_handshake_failures_total counter".to_string(),
            format!(
                "freeq_outbound_handshake_failures_total {}",
                self.counters.outbound_handshake_failures
            ),
            "# HELP freeq_inbound_handshake_failures_total Failed inbound handshakes."
                .to_string(),
            "# TYPE freeq_inbound_handshake_failures_total counter".to_string(),
            format!(
                "freeq_inbound_handshake_failures_total {}",
                self.counters.inbound_handshake_failures
            ),
            "# HELP freeq_tun_read_errors_total Failed TUN reads.".to_string(),
            "# TYPE freeq_tun_read_errors_total counter".to_string(),
            format!("freeq_tun_read_errors_total {}", self.counters.tun_read_errors),
            "# HELP freeq_tun_write_errors_total Failed TUN writes.".to_string(),
            "# TYPE freeq_tun_write_errors_total counter".to_string(),
            format!("freeq_tun_write_errors_total {}", self.counters.tun_write_errors),
            "# HELP freeq_packet_forward_failures_total Failed routed packet forwards."
                .to_string(),
            "# TYPE freeq_packet_forward_failures_total counter".to_string(),
            format!(
                "freeq_packet_forward_failures_total {}",
                self.counters.packet_forward_failures
            ),
            "# HELP freeq_peer_receive_errors_total Failed encrypted peer receives."
                .to_string(),
            "# TYPE freeq_peer_receive_errors_total counter".to_string(),
            format!(
                "freeq_peer_receive_errors_total {}",
                self.counters.peer_receive_errors
            ),
            "# HELP freeq_peer_connect_failures_total Failed outbound connects by peer."
                .to_string(),
            "# TYPE freeq_peer_connect_failures_total counter".to_string(),
            "# HELP freeq_peer_handshake_failures_total Failed handshakes by peer."
                .to_string(),
            "# TYPE freeq_peer_handshake_failures_total counter".to_string(),
            "# HELP freeq_peer_last_handshake_duration_ms Last successful handshake duration by peer."
                .to_string(),
            "# TYPE freeq_peer_last_handshake_duration_ms gauge".to_string(),
        ];

        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (peer_name, peer) in peers {
            lines.push(format!(
                "freeq_peer_connected{{peer=\"{}\"}} {}",
                peer_name,
                if peer.connected { 1 } else { 0 }
            ));
            lines.push(format!(
                "freeq_peer_connect_failures_total{{peer=\"{}\"}} {}",
                peer_name, peer.connect_failures
            ));
            lines.push(format!(
                "freeq_peer_handshake_failures_total{{peer=\"{}\"}} {}",
                peer_name, peer.handshake_failures
            ));
            if let Some(duration_ms) = peer.last_handshake_duration_ms {
                lines.push(format!(
                    "freeq_peer_last_handshake_duration_ms{{peer=\"{}\"}} {:.3}",
                    peer_name, duration_ms
                ));
            }
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
        state.record_outbound_connect_failure("lon-01");
        state.record_handshake_failure(Some("lon-01"), false);
        state.record_incoming_accept_failure();
        state.record_tun_read_error();
        state.record_tun_write_error();
        state.record_packet_forward_failure();
        state.record_peer_receive_error();
        state.record_handshake_success("lon-01", Some(12.5));

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
        assert!(metrics.contains("freeq_outbound_connect_failures_total 1"));
        assert!(metrics.contains("freeq_inbound_handshake_failures_total 0"));
        assert!(metrics.contains("freeq_outbound_handshake_failures_total 1"));
        assert!(metrics.contains("freeq_tun_read_errors_total 1"));
        assert!(metrics.contains("freeq_tun_write_errors_total 1"));
        assert!(metrics.contains("freeq_packet_forward_failures_total 1"));
        assert!(metrics.contains("freeq_peer_receive_errors_total 1"));
        assert!(metrics.contains("freeq_peer_connect_failures_total{peer=\"lon-01\"} 1"));
        assert!(metrics.contains("freeq_peer_handshake_failures_total{peer=\"lon-01\"} 1"));
        assert!(metrics.contains("freeq_peer_last_handshake_duration_ms{peer=\"lon-01\"} 12.500"));
    }
}
