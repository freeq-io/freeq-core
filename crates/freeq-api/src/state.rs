//! Shared runtime state exposed through the local REST API.

use crate::models::{AlgorithmResponse, PeerSummary, StatusResponse, TunnelStats};
use chrono::{TimeZone, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const NONE_I64: i64 = -1;
const NONE_U64: u64 = u64::MAX;
const MICROS_PER_MILLISECOND: f64 = 1_000.0;

/// Shared API state used by the daemon and request handlers.
pub type SharedApiState = Arc<ApiState>;

/// In-memory runtime snapshot exposed through API reads.
pub struct ApiState {
    start_time: Instant,
    node_name: String,
    version: String,
    kem_algorithm: String,
    sign_algorithm: String,
    bulk_algorithm: String,
    peers: HashMap<String, PeerRuntime>,
    counters: RuntimeCounters,
}

struct PeerRuntime {
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    connected: AtomicBool,
    last_handshake_unix_ms: AtomicI64,
    connect_failures: AtomicU64,
    handshake_failures: AtomicU64,
    last_handshake_duration_micros: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    latency_micros: AtomicU64,
    packet_loss_milli_pct: AtomicU64,
}

#[derive(Default)]
struct RuntimeCounters {
    incoming_accept_failures: AtomicU64,
    outbound_connect_failures: AtomicU64,
    outbound_handshake_failures: AtomicU64,
    inbound_handshake_failures: AtomicU64,
    tun_read_errors: AtomicU64,
    tun_write_errors: AtomicU64,
    packet_forward_failures: AtomicU64,
    peer_receive_errors: AtomicU64,
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
                        connected: AtomicBool::new(peer.connected),
                        last_handshake_unix_ms: AtomicI64::new(
                            peer.last_handshake
                                .as_deref()
                                .and_then(parse_rfc3339_unix_millis)
                                .unwrap_or(NONE_I64),
                        ),
                        connect_failures: AtomicU64::new(0),
                        handshake_failures: AtomicU64::new(0),
                        last_handshake_duration_micros: AtomicU64::new(NONE_U64),
                        bytes_sent: AtomicU64::new(0),
                        bytes_received: AtomicU64::new(0),
                        latency_micros: AtomicU64::new(NONE_U64),
                        packet_loss_milli_pct: AtomicU64::new(NONE_U64),
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
            counters: RuntimeCounters::default(),
        }
    }

    /// Create a shared API state handle.
    pub fn shared(self) -> SharedApiState {
        Arc::new(self)
    }

    /// Mark a peer as connected and update their latest handshake time.
    pub fn mark_peer_connected(&self, peer_name: &str) {
        self.record_handshake_success(peer_name, None);
    }

    /// Mark a peer as disconnected.
    pub fn mark_peer_disconnected(&self, peer_name: &str) {
        if let Some(peer) = self.peers.get(peer_name) {
            peer.connected.store(false, Ordering::Relaxed);
        }
    }

    /// Increment transmitted byte counters for a peer tunnel.
    pub fn add_bytes_sent(&self, peer_name: &str, bytes: u64) {
        if let Some(peer) = self.peers.get(peer_name) {
            peer.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Increment received byte counters for a peer tunnel.
    pub fn add_bytes_received(&self, peer_name: &str, bytes: u64) {
        if let Some(peer) = self.peers.get(peer_name) {
            peer.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record a successful handshake and optional duration sample for a peer.
    pub fn record_handshake_success(&self, peer_name: &str, duration_ms: Option<f64>) {
        let Some(peer) = self.peers.get(peer_name) else {
            return;
        };

        peer.connected.store(true, Ordering::Relaxed);
        peer.last_handshake_unix_ms
            .store(Utc::now().timestamp_millis(), Ordering::Relaxed);

        if let Some(duration_ms) = duration_ms {
            let duration_micros = duration_ms_to_micros(duration_ms);
            peer.last_handshake_duration_micros
                .store(duration_micros, Ordering::Relaxed);
            peer.latency_micros
                .store(duration_micros, Ordering::Relaxed);
        }
    }

    /// Record an outbound connection failure for a peer.
    pub fn record_outbound_connect_failure(&self, peer_name: &str) {
        self.counters
            .outbound_connect_failures
            .fetch_add(1, Ordering::Relaxed);
        if let Some(peer) = self.peers.get(peer_name) {
            peer.connect_failures.fetch_add(1, Ordering::Relaxed);
            peer.connected.store(false, Ordering::Relaxed);
        }
    }

    /// Record a handshake failure on the inbound or outbound control path.
    pub fn record_handshake_failure(&self, peer_name: Option<&str>, inbound: bool) {
        if inbound {
            self.counters
                .inbound_handshake_failures
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters
                .outbound_handshake_failures
                .fetch_add(1, Ordering::Relaxed);
        }

        if let Some(peer_name) = peer_name {
            if let Some(peer) = self.peers.get(peer_name) {
                peer.handshake_failures.fetch_add(1, Ordering::Relaxed);
                peer.connected.store(false, Ordering::Relaxed);
            }
        }
    }

    /// Record a failed incoming connection accept.
    pub fn record_incoming_accept_failure(&self) {
        self.counters
            .incoming_accept_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a TUN read error.
    pub fn record_tun_read_error(&self) {
        self.counters
            .tun_read_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a TUN write error.
    pub fn record_tun_write_error(&self) {
        self.counters
            .tun_write_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet forward failure.
    pub fn record_packet_forward_failure(&self) {
        self.counters
            .packet_forward_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a peer receive error.
    pub fn record_peer_receive_error(&self) {
        self.counters
            .peer_receive_errors
            .fetch_add(1, Ordering::Relaxed);
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
            tunnel_count: self
                .peers
                .values()
                .filter(|peer| peer.connected.load(Ordering::Relaxed))
                .count(),
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
                connected: peer.connected.load(Ordering::Relaxed),
                last_handshake: load_timestamp_rfc3339(&peer.last_handshake_unix_ms),
            })
            .collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name));
        peers
    }

    /// Build the current `/v1/tunnels` response.
    pub fn tunnel_stats(&self) -> Vec<TunnelStats> {
        let mut tunnels: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer_name, peer)| {
                let bytes_sent = peer.bytes_sent.load(Ordering::Relaxed);
                let bytes_received = peer.bytes_received.load(Ordering::Relaxed);
                let latency_ms = load_optional_ms(&peer.latency_micros);
                let packet_loss_pct = load_optional_milli_pct(&peer.packet_loss_milli_pct);
                let connected = peer.connected.load(Ordering::Relaxed);

                if !connected
                    && bytes_sent == 0
                    && bytes_received == 0
                    && latency_ms.is_none()
                    && packet_loss_pct.is_none()
                {
                    return None;
                }

                Some(TunnelStats {
                    peer: peer_name.clone(),
                    bytes_sent,
                    bytes_received,
                    latency_ms,
                    packet_loss_pct,
                })
            })
            .collect();
        tunnels.sort_by(|a, b| a.peer.cmp(&b.peer));
        tunnels
    }

    /// Build a Prometheus-compatible text exposition snapshot.
    pub fn metrics_exposition(&self) -> String {
        let connected_peers = self
            .peers
            .values()
            .filter(|peer| peer.connected.load(Ordering::Relaxed))
            .count();

        let mut lines = vec![
            "# HELP freeq_uptime_seconds Seconds since the daemon started.".to_string(),
            "# TYPE freeq_uptime_seconds gauge".to_string(),
            format!("freeq_uptime_seconds {}", self.start_time.elapsed().as_secs()),
            "# HELP freeq_configured_peers Total configured peers.".to_string(),
            "# TYPE freeq_configured_peers gauge".to_string(),
            format!("freeq_configured_peers {}", self.peers.len()),
            "# HELP freeq_connected_peers Peers with an active tunnel.".to_string(),
            "# TYPE freeq_connected_peers gauge".to_string(),
            format!("freeq_connected_peers {}", connected_peers),
            "# HELP freeq_active_tunnels Total active tunnel entries.".to_string(),
            "# TYPE freeq_active_tunnels gauge".to_string(),
            format!("freeq_active_tunnels {}", connected_peers),
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
                self.counters
                    .incoming_accept_failures
                    .load(Ordering::Relaxed)
            ),
            "# HELP freeq_outbound_connect_failures_total Failed outbound peer connects."
                .to_string(),
            "# TYPE freeq_outbound_connect_failures_total counter".to_string(),
            format!(
                "freeq_outbound_connect_failures_total {}",
                self.counters
                    .outbound_connect_failures
                    .load(Ordering::Relaxed)
            ),
            "# HELP freeq_outbound_handshake_failures_total Failed outbound handshakes."
                .to_string(),
            "# TYPE freeq_outbound_handshake_failures_total counter".to_string(),
            format!(
                "freeq_outbound_handshake_failures_total {}",
                self.counters
                    .outbound_handshake_failures
                    .load(Ordering::Relaxed)
            ),
            "# HELP freeq_inbound_handshake_failures_total Failed inbound handshakes."
                .to_string(),
            "# TYPE freeq_inbound_handshake_failures_total counter".to_string(),
            format!(
                "freeq_inbound_handshake_failures_total {}",
                self.counters
                    .inbound_handshake_failures
                    .load(Ordering::Relaxed)
            ),
            "# HELP freeq_tun_read_errors_total Failed TUN reads.".to_string(),
            "# TYPE freeq_tun_read_errors_total counter".to_string(),
            format!(
                "freeq_tun_read_errors_total {}",
                self.counters.tun_read_errors.load(Ordering::Relaxed)
            ),
            "# HELP freeq_tun_write_errors_total Failed TUN writes.".to_string(),
            "# TYPE freeq_tun_write_errors_total counter".to_string(),
            format!(
                "freeq_tun_write_errors_total {}",
                self.counters.tun_write_errors.load(Ordering::Relaxed)
            ),
            "# HELP freeq_packet_forward_failures_total Failed routed packet forwards."
                .to_string(),
            "# TYPE freeq_packet_forward_failures_total counter".to_string(),
            format!(
                "freeq_packet_forward_failures_total {}",
                self.counters
                    .packet_forward_failures
                    .load(Ordering::Relaxed)
            ),
            "# HELP freeq_peer_receive_errors_total Failed encrypted peer receives."
                .to_string(),
            "# TYPE freeq_peer_receive_errors_total counter".to_string(),
            format!(
                "freeq_peer_receive_errors_total {}",
                self.counters.peer_receive_errors.load(Ordering::Relaxed)
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
                if peer.connected.load(Ordering::Relaxed) {
                    1
                } else {
                    0
                }
            ));
            lines.push(format!(
                "freeq_peer_connect_failures_total{{peer=\"{}\"}} {}",
                peer_name,
                peer.connect_failures.load(Ordering::Relaxed)
            ));
            lines.push(format!(
                "freeq_peer_handshake_failures_total{{peer=\"{}\"}} {}",
                peer_name,
                peer.handshake_failures.load(Ordering::Relaxed)
            ));
            if let Some(duration_ms) = load_optional_ms(&peer.last_handshake_duration_micros) {
                lines.push(format!(
                    "freeq_peer_last_handshake_duration_ms{{peer=\"{}\"}} {:.3}",
                    peer_name, duration_ms
                ));
            }
            lines.push(format!(
                "freeq_tunnel_bytes_sent_total{{peer=\"{}\"}} {}",
                peer_name,
                peer.bytes_sent.load(Ordering::Relaxed)
            ));
            lines.push(format!(
                "freeq_tunnel_bytes_received_total{{peer=\"{}\"}} {}",
                peer_name,
                peer.bytes_received.load(Ordering::Relaxed)
            ));
        }

        lines.push(String::new());
        lines.join("\n")
    }
}

fn parse_rfc3339_unix_millis(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp_millis())
}

fn load_timestamp_rfc3339(timestamp: &AtomicI64) -> Option<String> {
    let unix_ms = timestamp.load(Ordering::Relaxed);
    if unix_ms == NONE_I64 {
        return None;
    }

    Utc.timestamp_millis_opt(unix_ms)
        .single()
        .map(|timestamp| timestamp.to_rfc3339())
}

fn duration_ms_to_micros(duration_ms: f64) -> u64 {
    (duration_ms * MICROS_PER_MILLISECOND).round() as u64
}

fn load_optional_ms(value: &AtomicU64) -> Option<f64> {
    let raw = value.load(Ordering::Relaxed);
    if raw == NONE_U64 {
        None
    } else {
        Some(raw as f64 / MICROS_PER_MILLISECOND)
    }
}

fn load_optional_milli_pct(value: &AtomicU64) -> Option<f64> {
    let raw = value.load(Ordering::Relaxed);
    if raw == NONE_U64 {
        None
    } else {
        Some(raw as f64 / 1_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::ApiState;
    use crate::models::PeerSummary;

    #[test]
    fn state_tracks_peer_and_tunnel_counters() {
        let state = ApiState::new(
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
        assert_eq!(tunnels[0].latency_ms, Some(12.5));
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
