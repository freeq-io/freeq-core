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

use std::collections::HashSet;
use std::net::SocketAddr;
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
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        toml::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Validate the configuration for obvious errors.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.node.name.trim().is_empty() {
            return Err(ConfigError::Invalid("node.name must not be empty".into()));
        }

        if self.node.key_path.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "node.key_path must not be empty".into(),
            ));
        }

        parse_socket_addr("node.listen", &self.node.listen)?;
        parse_socket_addr("node.api_addr", &self.node.api_addr)?;
        parse_ip_network("node.address", &self.node.address)?;
        validate_kem_algorithm(&self.node.algorithm)?;
        validate_sign_algorithm(&self.node.sign)?;

        let mut peer_names = HashSet::with_capacity(self.peer.len());
        for peer in &self.peer {
            if peer.name.trim().is_empty() {
                return Err(ConfigError::Invalid("peer.name must not be empty".into()));
            }

            if !peer_names.insert(peer.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate peer name: {}",
                    peer.name
                )));
            }

            decode_base64_field(&format!("peer.{}.public_key", peer.name), &peer.public_key)?;
            decode_base64_field(&format!("peer.{}.kem_key", peer.name), &peer.kem_key)?;

            if let Some(endpoint) = &peer.endpoint {
                validate_endpoint(&format!("peer.{}.endpoint", peer.name), endpoint)?;
            }

            if peer.key_rotation_secs == 0 {
                return Err(ConfigError::Invalid(format!(
                    "peer.{}.key_rotation_secs must be greater than zero",
                    peer.name
                )));
            }

            for allowed_ip in &peer.allowed_ips {
                parse_ip_network(&format!("peer.{}.allowed_ips", peer.name), allowed_ip)?;
            }
        }

        Ok(())
    }
}

/// Library-wide result type.
pub type Result<T, E = ConfigError> = std::result::Result<T, E>;

fn parse_socket_addr(field: &str, value: &str) -> Result<SocketAddr, ConfigError> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| ConfigError::Invalid(format!("{field} must be a valid socket address: {e}")))
}

fn parse_ip_network(field: &str, value: &str) -> Result<ipnetwork::IpNetwork, ConfigError> {
    value
        .parse::<ipnetwork::IpNetwork>()
        .map_err(|e| ConfigError::Invalid(format!("{field} must be a valid IP network: {e}")))
}

fn validate_kem_algorithm(value: &str) -> Result<(), ConfigError> {
    match value {
        "ml-kem-512" | "ml-kem-768" | "ml-kem-1024" => Ok(()),
        _ => Err(ConfigError::Invalid(format!(
            "node.algorithm must be one of ml-kem-512, ml-kem-768, ml-kem-1024; got {value}"
        ))),
    }
}

fn validate_sign_algorithm(value: &str) -> Result<(), ConfigError> {
    match value {
        "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" | "slh-dsa-sha2-128f" => Ok(()),
        _ => Err(ConfigError::Invalid(format!(
            "node.sign must be one of ml-dsa-44, ml-dsa-65, ml-dsa-87, slh-dsa-sha2-128f; got {value}"
        ))),
    }
}

fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>, ConfigError> {
    use base64::Engine as _;

    if value.trim().is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| ConfigError::Invalid(format!("{field} must be valid base64: {e}")))
}

fn validate_endpoint(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }

    let (host, port) = value.rsplit_once(':').ok_or_else(|| {
        ConfigError::Invalid(format!(
            "{field} must be a valid host:port or socket address"
        ))
    })?;

    if host.trim().is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{field} host must not be empty"
        )));
    }

    port.parse::<u16>()
        .map_err(|e| ConfigError::Invalid(format!("{field} port must be a valid u16: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn sample_config() -> Config {
        toml::from_str(
            r#"
            [node]
            name = "nyc-01"
            listen = "0.0.0.0:51820"
            address = "10.0.0.1/24"
            key_path = "/etc/freeq/identity.key"
            algorithm = "ml-kem-768"
            sign = "ml-dsa-65"
            api_enabled = true
            api_addr = "127.0.0.1:6789"

            [[peer]]
            name = "lon-01"
            endpoint = "lon-01.example.com:51820"
            public_key = "AQIDBA=="
            kem_key = "BQYHCA=="
            allowed_ips = ["10.0.0.2/32"]
            key_rotation_secs = 3600
            "#,
        )
        .expect("sample config should deserialize")
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        sample_config().validate().expect("config should validate");
    }

    #[test]
    fn validate_rejects_invalid_algorithm() {
        let mut config = sample_config();
        config.node.algorithm = "ml-kem-2048".into();

        let err = config.validate().expect_err("config should fail");
        assert!(err.to_string().contains("node.algorithm"));
    }

    #[test]
    fn validate_rejects_duplicate_peer_names() {
        let mut config = sample_config();
        config.peer.push(config.peer[0].clone());

        let err = config.validate().expect_err("config should fail");
        assert!(err.to_string().contains("duplicate peer name"));
    }

    #[test]
    fn validate_rejects_invalid_peer_endpoint() {
        let mut config = sample_config();
        config.peer[0].endpoint = Some("missing-port".into());

        let err = config.validate().expect_err("config should fail");
        assert!(err.to_string().contains("endpoint"));
    }
}
