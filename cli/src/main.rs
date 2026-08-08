//! freeq — command-line interface for the FreeQ daemon.
//!
//! Communicates with the local `freeqd` via the REST API at `127.0.0.1:6789`.
//!
//! ## Commands
//!
//! ```text
//! brew install freeq      Install FreeQ (macOS)
//! brew upgrade freeq      Update FreeQ (macOS)
//! freeq setup             Prepare this Mac and start the local setup node (macOS only)
//! freeq gateway           Connect or reconnect to a gateway/peer file (macOS only)
//! freeq gateway status    Show gateway file readiness
//! freeq doctor            Check local setup health and print next actions (macOS and Linux)
//! freeq stop              Stop FreeQ and roll networking back (macOS only)
//! freeq status            Show node status and active tunnels
//! ```
//!
//! Linux install today is `deploy/ansible/roles/freeqd`, not this CLI — see
//! `docs/linux-rhel-appliance.md`. `freeq doctor` works on a Linux host once
//! that role (or a `.deb`/`.rpm` built from `deploy/packaging`) has placed
//! this binary and `scripts/setup/freeq-doctor-linux.sh` on it.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use freeq_api::models::StatusResponse;
use std::{
    collections::BTreeMap,
    env, fs,
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

    /// Connect to or inspect a gateway/peer (uses ~/.freeq/peers when available).
    Gateway {
        #[command(subcommand)]
        action: Option<GatewayAction>,
    },

    /// Automatic public peer exchange (no ~/FreeQ folder drop).
    ///
    /// Direct: `freeq pair host` / `freeq pair join-host`
    /// Gateway leaf: `freeq pair gateway ...`
    /// Invite API: `freeq pair invite` / `freeq pair join`
    Pair {
        /// Arguments forwarded to scripts/setup/freeq-pair.sh
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Stop FreeQ and roll this Mac back to normal networking.
    Stop,

    /// Check local FreeQ setup health and print next actions.
    Doctor,

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
enum GatewayAction {
    /// Connect or reconnect this Mac to the gateway/peer file in ~/FreeQ.
    Connect,
    /// Show gateway readiness and the peer file that will be used.
    Status,
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
            require_os("freeq setup", "macos")?;
            run_script(&["scripts", "install", "freeq-install-macos.sh"], &[])?;
        }
        Commands::Gateway { action } => match action.unwrap_or(GatewayAction::Connect) {
            GatewayAction::Connect => {
                require_os("freeq gateway", "macos")?;
                run_script(
                    &["scripts", "setup", "freeq-connect-macos.sh"],
                    &["--restart"],
                )?;
            }
            GatewayAction::Status => {
                print_gateway_status(cli.api.as_str())?;
            }
        },
        Commands::Pair { args } => {
            require_os("freeq pair", "macos")?;
            let forwarded: Vec<&str> = args.iter().map(String::as_str).collect();
            run_script(&["scripts", "setup", "freeq-pair.sh"], &forwarded)?;
        }
        Commands::Stop => {
            require_os("freeq stop", "macos")?;
            run_script(
                &["scripts", "setup", "freeq-stop-macos.sh"],
                &["--renew-dhcp"],
            )?;
        }
        Commands::Doctor => {
            // Doctor is read-only on every platform it supports, so unlike
            // Setup/Gateway/Stop (which mutate host networking and only
            // exist for macOS today) it dispatches per-OS instead of
            // requiring a single platform.
            let script: &[&str] = match env::consts::OS {
                "macos" => &["scripts", "setup", "freeq-doctor-macos.sh"],
                "linux" => &["scripts", "setup", "freeq-doctor-linux.sh"],
                other => bail!(
                    "freeq doctor is not yet implemented for {other}; macOS and Linux are supported"
                ),
            };
            run_script(script, &[])?;
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

fn print_gateway_status(api: &str) -> Result<()> {
    let home = home_dir().context("HOME is not set")?;
    let receive_dir = env::var_os("FREEQ_PEERS_RECEIVED")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".freeq/peers/received"));
    let legacy_receive = home.join("FreeQ").join("02-put-peer-file-here");
    let local_env = env::var_os("FREEQ_LOCAL_ENV")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".freeq/perf/node.env"));
    let explicit_peer_env = env::var_os("FREEQ_PEER_ENV").map(PathBuf::from);

    println!("FreeQ gateway / peer status");
    println!("  State folder: ~/.freeq/");
    println!("  Peer receive: {}", receive_dir.display());

    if local_env.is_file() {
        let local = read_env_file(&local_env)?;
        println!(
            "  Local node: {} ({})",
            value_or_unknown(&local, "FREEQ_NODE_NAME"),
            value_or_unknown(&local, "FREEQ_NODE_ADDRESS")
        );
    } else {
        println!("  Local node: not set up");
        println!("  Next: run `freeq setup`");
    }

    // Prefer canonical receive dir; fall back to legacy drop folder.
    let selection =
        match select_gateway_peer_env(explicit_peer_env.as_deref(), &receive_dir, &local_env)? {
            PeerSelection::Missing => {
                select_gateway_peer_env(explicit_peer_env.as_deref(), &legacy_receive, &local_env)?
            }
            other => other,
        };

    match selection {
        PeerSelection::Ready(path) => {
            let peer = read_env_file(&path)?;
            println!("  Peer file: {}", path.display());
            println!(
                "  Peer node: {}",
                value_or_unknown(&peer, "FREEQ_NODE_NAME")
            );
            println!(
                "  Peer overlay: {}",
                value_or_unknown(&peer, "FREEQ_NODE_ADDRESS")
            );
            println!(
                "  Peer endpoint: {}",
                value_or_unknown(&peer, "FREEQ_PUBLIC_ENDPOINT")
            );
            println!("  Connect: freeq pair connect   # or freeq gateway");
        }
        PeerSelection::Missing => {
            println!("  Peer file: missing");
            println!("  Next (automatic exchange):");
            println!("    freeq pair host --code SECRET --port 8791 --auto-start");
            println!("    freeq pair join-host --url http://HOST:8791 --code SECRET --auto-start");
            println!(
                "    freeq pair gateway --gateway-endpoint IP:51820 --gateway-peer-env URL --remote-overlay X/32 --auto-start"
            );
        }
        PeerSelection::Multiple(paths) => {
            println!("  Peer file: ambiguous");
            for path in paths {
                println!("    - {}", path.display());
            }
            println!("  Next: freeq pair show");
        }
    }

    match try_status(api) {
        Ok(Some(status)) => {
            println!(
                "  Local daemon: running, {} peer(s), {} active tunnel(s)",
                status.peer_count, status.tunnel_count
            );
        }
        Ok(None) => {
            println!("  Local daemon: not reachable");
        }
        Err(err) => {
            println!("  Local daemon: status check failed ({err})");
        }
    }

    Ok(())
}

fn print_status(api: &str) -> Result<()> {
    let status = get_status(api)?;

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

fn try_status(api: &str) -> Result<Option<StatusResponse>> {
    match get_status(api) {
        Ok(status) => Ok(Some(status)),
        Err(_) => Ok(None),
    }
}

fn get_status(api: &str) -> Result<StatusResponse> {
    let body = http_get(api, "/v1/status")?;
    serde_json::from_str(&body).context("failed to parse FreeQ status response")
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

enum PeerSelection {
    Ready(PathBuf),
    Missing,
    Multiple(Vec<PathBuf>),
}

fn select_gateway_peer_env(
    explicit_peer_env: Option<&Path>,
    receive_dir: &Path,
    local_env: &Path,
) -> Result<PeerSelection> {
    if let Some(path) = explicit_peer_env {
        if path.is_file() {
            return Ok(PeerSelection::Ready(path.to_path_buf()));
        }
        return Ok(PeerSelection::Missing);
    }

    let local = if local_env.is_file() {
        read_env_file(local_env).unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let local_name = local.get("FREEQ_NODE_NAME").map(String::as_str);
    let local_address = local.get("FREEQ_NODE_ADDRESS").map(String::as_str);

    let mut remote_candidates = Vec::new();
    if receive_dir.is_dir() {
        for entry in fs::read_dir(receive_dir)
            .with_context(|| format!("failed to read {}", receive_dir.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("env") {
                continue;
            }
            let peer = read_env_file(&path).unwrap_or_default();
            let peer_name = peer.get("FREEQ_NODE_NAME").map(String::as_str);
            let peer_address = peer.get("FREEQ_NODE_ADDRESS").map(String::as_str);
            if local_name.is_some() && peer_name == local_name {
                continue;
            }
            if local_address.is_some() && peer_address == local_address {
                continue;
            }
            remote_candidates.push(path);
        }
    }

    match remote_candidates.len() {
        0 => Ok(PeerSelection::Missing),
        1 => Ok(PeerSelection::Ready(remote_candidates.remove(0))),
        _ => Ok(PeerSelection::Multiple(remote_candidates)),
    }
}

fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read env file {}", path.display()))?;
    let mut values = BTreeMap::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = raw_value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .unwrap_or(raw_value)
            .to_string();
        values.insert(key.to_string(), value);
    }
    Ok(values)
}

fn value_or_unknown<'a>(values: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    values
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
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

/// Fails with a clear message when the current OS isn't the one platform
/// a mutate-the-host command (setup/gateway/stop) currently supports.
/// Doctor doesn't use this — see the comment at its call site.
fn require_os(command: &str, required: &str) -> Result<()> {
    if env::consts::OS != required {
        bail!("{command} is currently implemented for {required} only");
    }
    Ok(())
}

fn run_script(relative_path: &[&str], args: &[&str]) -> Result<()> {
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
    let home = PathBuf::from(home);

    // Prebuilt release extract (binary installer default).
    let dist_current = home.join(".freeq/dist/current");
    if is_freeq_root(&dist_current) {
        return Some(dist_current);
    }

    let home_root = home.join("freeq-core");
    if is_freeq_root(&home_root) {
        return Some(home_root);
    }

    None
}

fn is_freeq_root(path: &Path) -> bool {
    let macos_layout = path
        .join("scripts/install/freeq-install-macos.sh")
        .is_file()
        && path.join("scripts/setup/freeq-connect-macos.sh").is_file()
        && path.join("scripts/setup/freeq-stop-macos.sh").is_file();
    // Linux only ships freeq-doctor-linux.sh today (setup/gateway/stop
    // aren't implemented for Linux yet), so it's checked on its own
    // rather than folded into the macOS three-script check above.
    let linux_layout = path.join("scripts/setup/freeq-doctor-linux.sh").is_file();
    // Release tarball layout: scripts + bin/freeqd
    let release_layout = path.join("scripts/setup/freeq-pair.sh").is_file()
        && path.join("bin/freeqd").is_file();
    macos_layout || linux_layout || release_layout
}
