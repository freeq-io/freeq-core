//! freeq — command-line interface for the FreeQ daemon.
//!
//! Communicates with the local `freeqd` via the REST API at `127.0.0.1:6789`.
//!
//! ## Commands
//!
//! ```text
//! freeq init              Generate identity keypair and write initial config
//! freeq up                Bring the daemon up (or start if not running)
//! freeq down              Gracefully stop the daemon
//! freeq status            Show node status and active tunnels
//! freeq peer add          Add a peer (keys via env or stdin JSON)
//! freeq peer remove <n>   Remove a peer by name
//! freeq peer list         List all configured peers
//! freeq key rotate        Rotate keys for all peers (or --peer <name>)
//! freeq algorithm set     Hot-swap the active crypto algorithm
//! freeq logs              Tail daemon logs
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use freeq_api::models::{
    AddPeerRequest, AlgorithmResponse, AlgorithmSwitchRequest, PeerSummary, StatusResponse,
};
use serde::Deserialize;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// freeq — FreeQ post-quantum overlay network management CLI.
#[derive(Parser, Debug)]
#[command(name = "freeq", version, about)]
struct Cli {
    /// API address of the local freeqd instance.
    #[arg(long, env = "FREEQ_API", default_value = "http://127.0.0.1:6789")]
    api: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate identity keypair and write initial config.
    Init {
        /// Config file path to create.
        #[arg(short, long, default_value = "/etc/freeq/freeq.toml")]
        config: std::path::PathBuf,
        /// Node name.
        #[arg(long)]
        name: Option<String>,
    },

    /// Show node status.
    Status,

    /// Peer management subcommands.
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },

    /// Key rotation.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },

    /// Hot-swap the active crypto algorithm.
    Algorithm {
        #[command(subcommand)]
        action: AlgorithmAction,
    },
}

#[derive(Subcommand, Debug)]
enum PeerAction {
    /// List all configured peers.
    List,
    /// Add a peer.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        transport_cert_fingerprint: Option<String>,
        #[arg(long)]
        allowed_ips: Vec<String>,
        #[arg(
            long,
            help = "Read peer key material from stdin as JSON {\"public_key\":\"...\",\"kem_key\":\"...\"}"
        )]
        stdin: bool,
    },
    /// Remove a peer by name.
    Remove { name: String },
}

#[derive(Subcommand, Debug)]
enum KeyAction {
    /// Rotate keys for all peers (or a specific peer).
    Rotate {
        /// Rotate only this peer's keys.
        #[arg(long)]
        peer: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AlgorithmAction {
    /// Print the active algorithm configuration.
    Get,
    /// Switch to a different algorithm.
    Set {
        #[arg(long)]
        kem: Option<String>,
        #[arg(long)]
        sign: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let status: StatusResponse = api_get(&cli.api, "/v1/status").await?;
            println!(
                "{} uptime={}s peers={} tunnels={} kem={} sign={} bulk={}",
                status.name,
                status.uptime_secs,
                status.peer_count,
                status.tunnel_count,
                status.kem_algorithm,
                status.sign_algorithm,
                status.bulk_algorithm
            );
        }
        Commands::Init { config, name } => {
            let summary = initialize_config(config, name)?;
            println!(
                "initialized node '{}' config={} key_path={} address={}",
                summary.node_name,
                summary.config_path.display(),
                summary.key_path.display(),
                summary.address
            );
        }
        Commands::Peer { action } => match action {
            PeerAction::Add {
                name,
                endpoint,
                transport_cert_fingerprint,
                allowed_ips,
                stdin,
            } => {
                let keys = if stdin {
                    load_peer_key_material_from_reader(std::io::stdin().lock())?
                } else {
                    load_peer_key_material_from_env()?
                };
                let _request = AddPeerRequest {
                    name: name.clone(),
                    public_key: keys.public_key,
                    kem_key: keys.kem_key,
                    endpoint,
                    transport_cert_fingerprint,
                    allowed_ips,
                };
                let peer: PeerSummary = api_post(&cli.api, "/v1/peers", &_request).await?;
                println!(
                    "added peer '{}' endpoint={} routes={}",
                    peer.name,
                    peer.endpoint.as_deref().unwrap_or("passive"),
                    peer.allowed_ips.join(",")
                );
            }
            PeerAction::List => {
                let peers: Vec<PeerSummary> = api_get(&cli.api, "/v1/peers").await?;
                for peer in peers {
                    println!(
                        "{} connected={} endpoint={} allowed_ips={}",
                        peer.name,
                        peer.connected,
                        peer.endpoint.as_deref().unwrap_or("passive"),
                        peer.allowed_ips.join(",")
                    );
                }
            }
            PeerAction::Remove { name } => {
                api_delete(&cli.api, &format!("/v1/peers/{name}")).await?;
                println!("removed peer '{name}'");
            }
        },
        Commands::Key { action } => match action {
            KeyAction::Rotate { peer } => {
                if let Some(peer) = peer {
                    let rotated: Vec<String> =
                        api_post_without_body(&cli.api, &format!("/v1/peers/{peer}/rotate"))
                            .await?;
                    println!("rotated peer keys for {}", rotated.join(","));
                } else {
                    let peers: Vec<PeerSummary> = api_get(&cli.api, "/v1/peers").await?;
                    let mut rotated = Vec::new();
                    for peer in peers {
                        let mut names: Vec<String> = api_post_without_body(
                            &cli.api,
                            &format!("/v1/peers/{}/rotate", peer.name),
                        )
                        .await?;
                        rotated.append(&mut names);
                    }
                    println!("rotated peer keys for {}", rotated.join(","));
                }
            }
        },
        Commands::Algorithm { action } => match action {
            AlgorithmAction::Get => {
                let algorithm: AlgorithmResponse = api_get(&cli.api, "/v1/algorithm").await?;
                println!(
                    "kem={} sign={} bulk={}",
                    algorithm.kem_algorithm, algorithm.sign_algorithm, algorithm.bulk_algorithm
                );
            }
            AlgorithmAction::Set { kem, sign } => {
                let algorithm: AlgorithmResponse = api_post(
                    &cli.api,
                    "/v1/algorithm",
                    &AlgorithmSwitchRequest { kem, sign },
                )
                .await?;
                println!(
                    "algorithm suite unchanged kem={} sign={} bulk={}",
                    algorithm.kem_algorithm, algorithm.sign_algorithm, algorithm.bulk_algorithm
                );
            }
        },
    }

    Ok(())
}

#[derive(Debug)]
struct InitSummary {
    node_name: String,
    config_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    address: String,
}

fn initialize_config(config_path: std::path::PathBuf, name: Option<String>) -> Result<InitSummary> {
    if config_path.exists() {
        anyhow::bail!("config file '{}' already exists", config_path.display());
    }

    let node_name = name.unwrap_or_else(default_node_name);
    let config_dir = config_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let key_path = config_dir.join("identity.key");

    if key_path.exists() {
        anyhow::bail!("identity key '{}' already exists", key_path.display());
    }

    std::fs::create_dir_all(&config_dir).with_context(|| {
        format!(
            "failed to create configuration directory '{}'",
            config_dir.display()
        )
    })?;

    let mut rng = rand::thread_rng();
    let (identity, _public_key) = freeq_crypto::sign::IdentityKeypair::generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("identity key generation failed: {e}"))?;
    std::fs::write(&key_path, identity.to_bytes())
        .with_context(|| format!("failed to write identity key '{}'", key_path.display()))?;
    set_private_key_permissions(&key_path)?;

    let config = freeq_config::Config {
        node: freeq_config::NodeConfig {
            name: node_name.clone(),
            listen: "0.0.0.0:51820".into(),
            address: "10.0.0.1/24".into(),
            key_path: key_path.to_string_lossy().into_owned(),
            algorithm: "ml-kem-768".into(),
            sign: "ml-dsa-65".into(),
            api_enabled: true,
            api_addr: "127.0.0.1:6789".into(),
        },
        peer: Vec::new(),
    };
    config.validate()?;

    let rendered =
        toml::to_string_pretty(&config).context("failed to render configuration TOML")?;
    std::fs::write(&config_path, rendered)
        .with_context(|| format!("failed to write config '{}'", config_path.display()))?;

    Ok(InitSummary {
        node_name,
        config_path,
        key_path,
        address: config.node.address,
    })
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "freeq-node".into())
}

fn set_private_key_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on '{}'", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

async fn api_get<T>(api_base: &str, path: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}{}", api_base.trim_end_matches('/'), path))
        .send()
        .await
        .context("failed to contact local freeqd API")?;
    parse_api_response(response).await
}

async fn api_post<T, B>(api_base: &str, path: &str, body: &B) -> Result<T>
where
    T: serde::de::DeserializeOwned,
    B: serde::Serialize + ?Sized,
{
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}{}", api_base.trim_end_matches('/'), path))
        .json(body)
        .send()
        .await
        .context("failed to contact local freeqd API")?;
    parse_api_response(response).await
}

async fn api_delete(api_base: &str, path: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}{}", api_base.trim_end_matches('/'), path))
        .send()
        .await
        .context("failed to contact local freeqd API")?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    anyhow::bail!("API request failed with status {}: {}", status, body.trim());
}

async fn api_post_without_body<T>(api_base: &str, path: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}{}", api_base.trim_end_matches('/'), path))
        .send()
        .await
        .context("failed to contact local freeqd API")?;
    parse_api_response(response).await
}

async fn parse_api_response<T>(response: reqwest::Response) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("API request failed with status {}: {}", status, body.trim());
    }

    response
        .json()
        .await
        .context("failed to decode local freeqd API response")
}

#[derive(Debug, PartialEq, Eq)]
struct PeerKeyMaterial {
    public_key: String,
    kem_key: String,
}

#[derive(Debug, Deserialize)]
struct StdinPeerKeyMaterial {
    public_key: String,
    kem_key: String,
}

fn load_peer_key_material_from_env() -> Result<PeerKeyMaterial> {
    let public_key = std::env::var("FREEQ_PEER_PUBLIC_KEY").with_context(|| {
        "set FREEQ_PEER_PUBLIC_KEY or pass --stdin to read peer keys from standard input"
    })?;
    let kem_key = std::env::var("FREEQ_PEER_KEM_KEY").with_context(|| {
        "set FREEQ_PEER_KEM_KEY or pass --stdin to read peer keys from standard input"
    })?;

    normalize_peer_key_material(PeerKeyMaterial {
        public_key,
        kem_key,
    })
}

fn load_peer_key_material_from_reader(mut reader: impl Read) -> Result<PeerKeyMaterial> {
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .context("failed to read peer keys from stdin")?;

    let parsed: StdinPeerKeyMaterial = serde_json::from_str(&body)
        .context("stdin must be valid JSON with public_key and kem_key fields")?;

    normalize_peer_key_material(PeerKeyMaterial {
        public_key: parsed.public_key,
        kem_key: parsed.kem_key,
    })
}

fn normalize_peer_key_material(keys: PeerKeyMaterial) -> Result<PeerKeyMaterial> {
    let public_key = keys.public_key.trim().to_owned();
    let kem_key = keys.kem_key.trim().to_owned();

    if public_key.is_empty() {
        anyhow::bail!("peer public key must not be empty");
    }
    if kem_key.is_empty() {
        anyhow::bail!("peer KEM key must not be empty");
    }

    Ok(PeerKeyMaterial {
        public_key,
        kem_key,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        initialize_config, load_peer_key_material_from_env, load_peer_key_material_from_reader,
    };

    #[test]
    fn loads_peer_key_material_from_env() {
        std::env::set_var("FREEQ_PEER_PUBLIC_KEY", "  pubkey  ");
        std::env::set_var("FREEQ_PEER_KEM_KEY", "  kemkey  ");

        let keys = load_peer_key_material_from_env().expect("env key material should parse");

        assert_eq!(keys.public_key, "pubkey");
        assert_eq!(keys.kem_key, "kemkey");

        std::env::remove_var("FREEQ_PEER_PUBLIC_KEY");
        std::env::remove_var("FREEQ_PEER_KEM_KEY");
    }

    #[test]
    fn loads_peer_key_material_from_stdin_json() {
        let input = r#"{"public_key":"  pubkey ","kem_key":" kemkey  "}"#;

        let keys =
            load_peer_key_material_from_reader(input.as_bytes()).expect("stdin JSON should parse");

        assert_eq!(keys.public_key, "pubkey");
        assert_eq!(keys.kem_key, "kemkey");
    }

    #[test]
    fn rejects_empty_peer_key_material() {
        let input = r#"{"public_key":"   ","kem_key":" kemkey "}"#;

        let error =
            load_peer_key_material_from_reader(input.as_bytes()).expect_err("empty key rejected");

        assert!(error
            .to_string()
            .contains("peer public key must not be empty"));
    }

    #[test]
    fn init_writes_config_and_identity_key() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("freeq.toml");

        let summary = initialize_config(config_path.clone(), Some("chi-01".into()))
            .expect("init should succeed");

        assert_eq!(summary.node_name, "chi-01");
        assert!(config_path.exists());
        assert!(summary.key_path.exists());

        let config = freeq_config::Config::load(&config_path).expect("config load");
        config.validate().expect("config validate");
        assert_eq!(config.node.name, "chi-01");
        assert_eq!(config.node.key_path, summary.key_path.to_string_lossy());
    }

    #[test]
    fn init_rejects_existing_config() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("freeq.toml");
        std::fs::write(&config_path, "existing").expect("seed config");

        let error = initialize_config(config_path, Some("chi-01".into()))
            .expect_err("existing config should be rejected");

        assert!(error.to_string().contains("config file"));
    }
}
