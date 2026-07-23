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
use freeq_api::models::StatusResponse;
use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
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
            print_status(&cli.api)?;
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

fn print_status(api: &str) -> Result<()> {
    let body = http_get(api, "/v1/status")?;
    let status: StatusResponse =
        serde_json::from_str(&body).context("failed to parse FreeQ status response")?;

    println!("FreeQ status");
    println!("  Node: {}", status.name);
    println!("  Version: {}", status.version);
    println!("  Uptime: {}", format_duration(status.uptime_secs));
    println!("  Peers: {}", status.peer_count);
    println!("  Active tunnels: {}", status.tunnel_count);
    if let Some(interface_name) = status.interface_name.as_deref() {
        match status.interface_mtu {
            Some(mtu) => println!("  Interface: {interface_name} / MTU {mtu}"),
            None => println!("  Interface: {interface_name}"),
        }
    } else {
        println!("  Interface: not active");
    }
    println!(
        "  Algorithms: {} / {} / {}",
        status.kem_algorithm, status.sign_algorithm, status.bulk_algorithm
    );
    println!(
        "  Traffic: {} packets, {} encrypted bytes, {} route misses",
        status.packets_ingested, status.encrypted_bytes, status.route_misses
    );
    if let Some(last_error) = status.last_error.as_deref() {
        println!("  Last error: {last_error}");
    }
    if status.startup_blockers.is_empty() {
        println!("  Startup blockers: none");
    } else {
        println!("  Startup blockers:");
        for blocker in status.startup_blockers {
            println!("    - {blocker}");
        }
    }
    Ok(())
}

fn http_get(api: &str, path: &str) -> Result<String> {
    let (host, port) = parse_local_http_api(api)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .with_context(|| {
            format!(
                "could not connect to FreeQ API at {host}:{port}; run `freeq gateway` or `freeq setup` first"
            )
        })?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("FreeQ API returned an invalid HTTP response")?;
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        bail!("FreeQ API returned {status_line}");
    }
    Ok(body.to_string())
}

fn parse_local_http_api(api: &str) -> Result<(String, u16)> {
    let without_scheme = api
        .strip_prefix("http://")
        .context("FREEQ_API must use http:// for the local FreeQ API")?;
    let authority = without_scheme
        .split('/')
        .next()
        .context("FREEQ_API is missing a host")?;
    let (host, port) = authority
        .rsplit_once(':')
        .context("FREEQ_API must include a port, such as http://127.0.0.1:6789")?;
    if host != "127.0.0.1" && host != "localhost" {
        bail!("freeq status only supports the local FreeQ API");
    }
    let port = port
        .parse::<u16>()
        .context("FREEQ_API port must be a number")?;
    Ok((host.to_string(), port))
}

fn format_duration(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
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
