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
//! freeq peer add          Add a peer (interactive or from flags)
//! freeq peer remove <n>   Remove a peer by name
//! freeq peer list         List all configured peers
//! freeq key rotate        Rotate keys for all peers (or --peer <name>)
//! freeq algorithm set     Hot-swap the active crypto algorithm
//! freeq logs              Tail daemon logs
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        #[arg(long)] name: String,
        #[arg(long)] public_key: String,
        #[arg(long)] kem_key: String,
        #[arg(long)] endpoint: Option<String>,
        #[arg(long)] allowed_ips: Vec<String>,
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
        #[arg(long)] kem: Option<String>,
        #[arg(long)] sign: Option<String>,
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
        Commands::Peer { action: _ } => {
            // TODO(v0.1): dispatch to peer API handlers
            println!("freeq peer — not yet implemented");
        }
        Commands::Key { action: _ } => {
            println!("freeq key — not yet implemented");
        }
        Commands::Algorithm { action: _ } => {
            println!("freeq algorithm — not yet implemented");
        }
    }

    Ok(())
}
