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
use freeq_api::models::AddPeerRequest;
use serde::Deserialize;
use std::io::Read;

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
            // TODO(v0.1): GET {api}/v1/status and pretty-print
            println!("freeq status — not yet implemented");
        }
        Commands::Init { config: _, name: _ } => {
            // TODO(v0.1): generate identity keypair, write config
            println!("freeq init — not yet implemented");
        }
        Commands::Peer { action } => match action {
            PeerAction::Add {
                name,
                endpoint,
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
                    allowed_ips,
                };
                println!(
                    "freeq peer add for '{name}' is prepared securely, but peer creation is not implemented yet"
                );
            }
            _ => {
                // TODO(v0.1): dispatch remaining peer API handlers
                println!("freeq peer — not yet implemented");
            }
        },
        Commands::Key { action: _ } => {
            println!("freeq key — not yet implemented");
        }
        Commands::Algorithm { action: _ } => {
            println!("freeq algorithm — not yet implemented");
        }
    }

    Ok(())
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
    use super::{load_peer_key_material_from_env, load_peer_key_material_from_reader};

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
}
