//! freeq — command-line interface for the FreeQ daemon.
//!
//! Communicates with the local `freeqd` via the REST API at `127.0.0.1:6789`.
//!
//! ## Commands
//!
//! ```text
//! brew install freeq      Install FreeQ
//! brew upgrade freeq      Update FreeQ
//! freeq setup             Prepare this Mac and start the local setup node
//! freeq gateway           Connect or reconnect to a gateway/peer file
//! freeq stop              Stop FreeQ and roll networking back
//! freeq status            Show node status and active tunnels
//! ```

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

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
    /// Prepare this Mac and start the local setup node.
    Setup,

    /// Connect or reconnect this Mac to the gateway/peer file in ~/FreeQ.
    Gateway,

    /// Stop FreeQ and roll this Mac back to normal networking.
    Stop,

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
        public_key: String,
        #[arg(long)]
        kem_key: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        allowed_ips: Vec<String>,
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
        Commands::Setup => {
            run_script(&["scripts", "install", "freeq-install-macos.sh"], &[])?;
        }
        Commands::Gateway => {
            run_script(
                &["scripts", "setup", "freeq-connect-macos.sh"],
                &["--restart"],
            )?;
        }
        Commands::Stop => {
            run_script(
                &["scripts", "setup", "freeq-stop-macos.sh"],
                &["--renew-dhcp"],
            )?;
        }
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

fn run_script(relative_path: &[&str], args: &[&str]) -> Result<()> {
    if env::consts::OS != "macos" {
        bail!("this convenience action is currently implemented for macOS only");
    }

    let repo_root = find_freeq_root().context(
        "could not find FreeQ scripts; set FREEQ_INSTALL_DIR to the freeq-core checkout",
    )?;
    let script = relative_path
        .iter()
        .fold(repo_root.clone(), |path, component| path.join(component));
    if !script.exists() {
        bail!("missing FreeQ helper script: {}", script.display());
    }

    let status = Command::new(&script)
        .args(args)
        .current_dir(&repo_root)
        .status()
        .with_context(|| format!("failed to run {}", script.display()))?;
    if !status.success() {
        bail!("{} exited with {}", script.display(), status);
    }
    Ok(())
}

fn find_freeq_root() -> Option<PathBuf> {
    if let Ok(path) = env::var("FREEQ_INSTALL_DIR") {
        if is_freeq_root(Path::new(&path)) {
            return Some(PathBuf::from(path));
        }
    }

    if let Some(path) = option_env!("FREEQ_PACKAGE_ROOT") {
        if is_freeq_root(Path::new(path)) {
            return Some(PathBuf::from(path));
        }
    }

    if let Ok(exe) = env::current_exe() {
        for ancestor in exe.ancestors() {
            if is_freeq_root(ancestor) {
                return Some(ancestor.to_path_buf());
            }
            let libexec = ancestor.join("libexec");
            if is_freeq_root(&libexec) {
                return Some(libexec);
            }
        }
    }

    if let Ok(cwd) = env::current_dir() {
        for ancestor in cwd.ancestors() {
            if is_freeq_root(ancestor) {
                return Some(ancestor.to_path_buf());
            }
        }
    }

    let home = env::var_os("HOME")?;
    let home_root = PathBuf::from(home).join("freeq-core");
    if is_freeq_root(&home_root) {
        return Some(home_root);
    }

    None
}

fn is_freeq_root(path: &Path) -> bool {
    path.join("scripts/install/freeq-install-macos.sh")
        .is_file()
        && path.join("scripts/setup/freeq-connect-macos.sh").is_file()
        && path.join("scripts/setup/freeq-stop-macos.sh").is_file()
}
