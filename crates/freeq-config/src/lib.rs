//! # freeq-config
//!
//! TOML-based configuration for the FreeQ daemon.
//!
//! Config is loaded at startup from `/etc/freeq/freeq.toml` (Linux),
//! `~/Library/Application Support/freeq/freeq.toml` (macOS), or
//! the path specified via `--config`.
//!
//! ## Example config
//!
//! ```toml
//! [node]
//! name       = "nyc-01"
//! listen     = "0.0.0.0:51820"
//! address    = "10.0.0.1/24"
//! algorithm  = "ml-kem-768"    # or ml-kem-512, ml-kem-1024
//! sign       = "ml-dsa-65"     # or ml-dsa-44, ml-dsa-87
//!
//! [[peer]]
//! name        = "lon-01"
//! endpoint    = "lon-01.example.com:51820"
//! public_key  = "base64encodedMLDSApublickey..."
//! kem_key     = "base64encodedMLKEMpublickey..."
//! allowed_ips = ["10.0.0.2/32"]
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used)]

pub mod error;
pub mod node;
pub mod peer;

use std::path::Path;

pub use error::ConfigError;
pub use node::NodeConfig;
pub use peer::PeerConfig;

/// The root configuration structure loaded from `freeq.toml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// This node's identity and network settings.
    pub node: NodeConfig,
    /// The list of trusted peers.
    #[serde(default)]
    pub peer: Vec<PeerConfig>,
}

impl Config {
    /// Load configuration from a TOML file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        toml::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Validate the configuration for obvious errors.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.node.name.is_empty() {
            return Err(ConfigError::Invalid("node.name must not be empty".into()));
        }
        Ok(())
    }
}

/// Library-wide result type.
pub type Result<T, E = ConfigError> = std::result::Result<T, E>;
