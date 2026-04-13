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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPeerRequest {
    /// Human-readable peer name.
    pub name: String,
    /// ML-DSA-65 public key (base64).
    pub public_key: String,
    /// ML-KEM-768 public key (base64).
    pub kem_key: String,
    /// Optional endpoint address.
    pub endpoint: Option<String>,
    /// Optional SHA-256 fingerprint of the peer's QUIC transport certificate, hex-encoded.
    pub transport_cert_fingerprint: Option<String>,
    /// IP prefixes to route through this peer.
    pub allowed_ips: Vec<String>,
}

impl AddPeerRequest {
    /// Validate that the request is internally consistent and cryptographically well-formed.
    pub fn validate(&self) -> crate::Result<()> {
        use base64::Engine as _;

        if self.name.trim().is_empty() {
            return Err(crate::ApiError::BadRequest(
                "peer name must not be empty".into(),
            ));
        }

        let public_key = base64::engine::general_purpose::STANDARD
            .decode(self.public_key.trim())
            .map_err(|_| {
                crate::ApiError::BadRequest("peer public_key must be valid base64".into())
            })?;
        freeq_crypto::sign::IdentityPublicKey::from_bytes(&public_key)
            .map_err(|e| crate::ApiError::BadRequest(format!("peer public_key is invalid: {e}")))?;

        let kem_key = base64::engine::general_purpose::STANDARD
            .decode(self.kem_key.trim())
            .map_err(|_| crate::ApiError::BadRequest("peer kem_key must be valid base64".into()))?;
        freeq_crypto::kem::HybridPublicKey::from_bytes(&kem_key)
            .map_err(|e| crate::ApiError::BadRequest(format!("peer kem_key is invalid: {e}")))?;

        if let Some(endpoint) = &self.endpoint {
            if endpoint.trim().is_empty() {
                return Err(crate::ApiError::BadRequest(
                    "peer endpoint must not be empty when provided".into(),
                ));
            }
            let Some(fingerprint) = &self.transport_cert_fingerprint else {
                return Err(crate::ApiError::BadRequest(
                    "peer transport_cert_fingerprint is required when endpoint is set".into(),
                ));
            };
            let fingerprint = fingerprint.trim();
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(crate::ApiError::BadRequest(
                    "peer transport_cert_fingerprint must be a 64-character hex SHA-256 digest"
                        .into(),
                ));
            }
        }

        for prefix in &self.allowed_ips {
            prefix.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                crate::ApiError::BadRequest(format!(
                    "peer allowed_ips entry '{prefix}' is invalid: {e}"
                ))
            })?;
        }

        Ok(())
    }
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
