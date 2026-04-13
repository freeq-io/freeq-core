//! REST API request/response models.

use serde::{Deserialize, Serialize};

/// Response from `GET /v1/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node name from config.
    pub name: String,
    /// Daemon version string.
    pub version: String,
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Active KEM algorithm.
    pub kem_algorithm: String,
    /// Active signature algorithm.
    pub sign_algorithm: String,
    /// Active bulk encryption algorithm.
    pub bulk_algorithm: String,
    /// Number of configured peers.
    pub peer_count: usize,
    /// Number of currently active tunnels.
    pub tunnel_count: usize,
}

/// A peer summary returned from `GET /v1/peers`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerSummary {
    /// Peer name.
    pub name: String,
    /// Peer endpoint address, if known.
    pub endpoint: Option<String>,
    /// Allowed IP prefixes.
    pub allowed_ips: Vec<String>,
    /// Whether a tunnel is currently active.
    pub connected: bool,
    /// Last handshake timestamp (ISO 8601), if any.
    pub last_handshake: Option<String>,
}

/// Request body for `POST /v1/peers`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddPeerRequest {
    /// Human-readable peer name.
    pub name: String,
    /// ML-DSA-65 public key (base64).
    pub public_key: String,
    /// ML-KEM-768 public key (base64).
    pub kem_key: String,
    /// Optional endpoint address.
    pub endpoint: Option<String>,
    /// IP prefixes to route through this peer.
    pub allowed_ips: Vec<String>,
}

/// Request body for `POST /v1/algorithm`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AlgorithmSwitchRequest {
    /// New KEM algorithm (e.g. `"ml-kem-1024"`).
    pub kem: Option<String>,
    /// New signature algorithm.
    pub sign: Option<String>,
}

/// Response from `GET /v1/algorithm`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AlgorithmResponse {
    /// Active KEM algorithm.
    pub kem_algorithm: String,
    /// Active signature algorithm.
    pub sign_algorithm: String,
    /// Active bulk encryption algorithm.
    pub bulk_algorithm: String,
}

/// Tunnel statistics from `GET /v1/tunnels`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelStats {
    /// Peer name.
    pub peer: String,
    /// Bytes sent through this tunnel.
    pub bytes_sent: u64,
    /// Bytes received through this tunnel.
    pub bytes_received: u64,
    /// Round-trip latency in milliseconds.
    pub latency_ms: Option<f64>,
    /// Packet loss percentage.
    pub packet_loss_pct: Option<f64>,
}
