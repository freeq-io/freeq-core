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
    /// Name of the active tunnel interface, if initialized.
    pub interface_name: Option<String>,
    /// MTU of the active tunnel interface, if initialized.
    pub interface_mtu: Option<usize>,
    /// Tunnel packets accepted by the daemon packet pipeline.
    pub packets_ingested: u64,
    /// Tunnel bytes emitted after encryption.
    pub encrypted_bytes: u64,
    /// QUIC-sized transport frames emitted by the tunnel pipeline.
    pub transport_frames: u64,
    /// Packets rejected because no route matched the destination IP.
    pub route_misses: u64,
    /// Packets rejected as structurally malformed.
    pub malformed_packet_errors: u64,
    /// Packets rejected during crypto processing.
    pub crypto_errors: u64,
    /// Packets rejected during transport framing.
    pub transport_errors: u64,
    /// Most recent daemon error summary, if any.
    pub last_error: Option<String>,
    /// Startup blockers currently preventing the full daemon main loop.
    pub startup_blockers: Vec<String>,
}

/// A peer summary returned from `GET /v1/peers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSummary {
    /// Stable peer node identifier for UI display.
    pub node_id: Option<String>,
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
    /// Enrollment or trust state shown by the setup UI.
    pub trust_state: Option<String>,
    /// Source that enrolled this peer, such as `invite`.
    pub enrollment_source: Option<String>,
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

/// Request body for `POST /v1/invites`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteCreateRequest {
    /// Human-readable peer label for the invite.
    pub label: Option<String>,
    /// Optional endpoint hint to include in the public invite bundle.
    pub endpoint: Option<String>,
    /// Optional overlay prefixes to include in the public invite bundle.
    pub allowed_ips: Option<Vec<String>>,
}

/// Response body from `POST /v1/invites`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteCreateResponse {
    /// Suggested file name for the public invite bundle.
    pub bundle_name: String,
    /// Public invite bundle text to send to the invitee.
    pub bundle_text: String,
    /// UTC expiry timestamp. Default invite lifetime is 15 minutes.
    pub expires_at: String,
    /// Pairing code to send out-of-band.
    pub pairing_code_display: String,
    /// Human-readable next step.
    pub message: String,
}

/// Request body for `POST /v1/invites/join`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteJoinRequest {
    /// Public invite bundle text received from the inviter.
    pub bundle_text: String,
    /// Out-of-band pairing code received separately from the bundle.
    pub pairing_code: String,
}

/// Response body from `POST /v1/invites/join`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteJoinResponse {
    /// Whether the invite was accepted.
    pub accepted: bool,
    /// Peer name enrolled from the invite, if accepted.
    pub peer_name: Option<String>,
    /// Peer node identifier enrolled from the invite, if accepted.
    pub node_id: Option<String>,
    /// Human-readable PASS/FAIL message.
    pub message: String,
}

/// Public invite bundle format sent from inviter to invitee.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteBundle {
    /// Bundle schema marker.
    pub schema: String,
    /// Inviter node display name.
    pub inviter_name: String,
    /// Public inviter node identifier.
    pub inviter_node_id: String,
    /// Optional public endpoint hint for the inviter.
    pub endpoint: Option<String>,
    /// Public overlay prefixes the inviter wants to share.
    pub allowed_ips: Vec<String>,
    /// UTC issue timestamp.
    pub issued_at: String,
    /// UTC expiry timestamp.
    pub expires_at: String,
    /// SHA-256 hash of the out-of-band pairing code and invite nonce.
    pub pairing_hash: String,
    /// Public invite nonce.
    pub nonce: String,
}

/// Request body for `POST /v1/algorithm`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AlgorithmSwitchRequest {
    /// New KEM algorithm (e.g. `"ml-kem-1024"`).
    pub kem: Option<String>,
    /// New signature algorithm.
    pub sign: Option<String>,
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
