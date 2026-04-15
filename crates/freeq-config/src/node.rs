//! Node-level configuration.

/// Configuration for this FreeQ node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeConfig {
    /// Human-readable node name (used in logs and the Cloud dashboard).
    pub name: String,

    /// UDP socket address to listen on.
    ///
    /// Default: `"0.0.0.0:51820"`
    #[serde(default = "default_listen")]
    pub listen: String,

    /// The VPN IP address and prefix length for this node (e.g. `"10.0.0.1/24"`).
    pub address: String,

    /// Path to this node's private identity key file.
    ///
    /// Default: `/etc/freeq/identity.key`
    #[serde(default = "default_key_path")]
    pub key_path: String,

    /// KEM algorithm parameter set.
    ///
    /// Default: `"ml-kem-768"`
    #[serde(default = "default_kem")]
    pub algorithm: String,

    /// Signature algorithm parameter set.
    ///
    /// Default: `"ml-dsa-65"`
    #[serde(default = "default_sign")]
    pub sign: String,

    /// Enable the local REST API for FreeQ Cloud agent.
    ///
    /// Default: `true`
    #[serde(default = "default_true")]
    pub api_enabled: bool,

    /// Address for the local REST API.
    ///
    /// Default: `"127.0.0.1:6789"`
    #[serde(default = "default_api_addr")]
    pub api_addr: String,
}

fn default_listen() -> String {
    "0.0.0.0:51820".into()
}
fn default_key_path() -> String {
    "/etc/freeq/identity.key".into()
}
fn default_kem() -> String {
    "ml-kem-768".into()
}
fn default_sign() -> String {
    "ml-dsa-65".into()
}
fn default_true() -> bool {
    true
}
fn default_api_addr() -> String {
    "127.0.0.1:6789".into()
}
