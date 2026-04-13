//! Per-peer configuration.

/// Configuration for a single trusted peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerConfig {
    /// Human-readable peer name.
    pub name: String,

    /// The peer's ML-DSA-65 identity public key (base64-encoded).
    pub public_key: String,

    /// The peer's ML-KEM-768 public key (base64-encoded).
    pub kem_key: String,

    /// Optional endpoint address for dialing this peer (`host:port`).
    ///
    /// If absent, the peer is passive (we wait for them to initiate).
    pub endpoint: Option<String>,

    /// Optional SHA-256 fingerprint of the peer's QUIC transport certificate, hex-encoded.
    ///
    /// Required when `endpoint` is configured.
    #[serde(default)]
    pub transport_cert_fingerprint: Option<String>,

    /// IP prefixes routed through this peer (e.g. `["10.0.0.2/32"]`).
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// Key rotation interval in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_rotation")]
    pub key_rotation_secs: u64,
}

fn default_rotation() -> u64 {
    3600
}
