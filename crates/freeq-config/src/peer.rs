//! Per-peer configuration.

/// Connectivity mode for a configured peer.
///
/// FreeQ keeps two lanes separate: direct peer connection and gateway relay.
/// Missing / default mode is [`PeerMode::Direct`] so existing configs keep
/// working with zero gateway present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerMode {
    /// Direct peer connection — either side may dial when an endpoint is set.
    #[default]
    Direct,
    /// This node dials a public gateway outbound-only (leaf gateway-client).
    GatewayClient,
    /// Peer is a leaf that may only connect inbound to a gateway.
    ///
    /// On a gateway, every configured leaf peer uses this mode. The gateway
    /// must never dial a `RelayLeaf` peer, regardless of any documented
    /// endpoint value.
    RelayLeaf,
}

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
    /// For [`PeerMode::RelayLeaf`], any endpoint is documentation-only and
    /// must not be used for dialing.
    pub endpoint: Option<String>,

    /// Connectivity mode for this peer.
    ///
    /// When omitted from TOML, defaults to [`PeerMode::Direct`].
    #[serde(default)]
    pub mode: Option<PeerMode>,

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

impl PeerConfig {
    /// Effective connectivity mode (defaults to [`PeerMode::Direct`]).
    pub fn effective_mode(&self) -> PeerMode {
        self.mode.unwrap_or(PeerMode::Direct)
    }

    /// Whether this peer may be dialed outbound.
    ///
    /// [`PeerMode::RelayLeaf`] is never dialable — gateway never initiates to
    /// a leaf. Direct and gateway-client peers are dialable only when an
    /// endpoint is configured.
    pub fn is_dialable(&self) -> bool {
        match self.effective_mode() {
            PeerMode::RelayLeaf => false,
            PeerMode::Direct | PeerMode::GatewayClient => self.endpoint.is_some(),
        }
    }
}
