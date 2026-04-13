//! freeqd — the FreeQ post-quantum overlay network daemon.
//!
//! # Startup sequence
//!
//! 1. Parse CLI flags (`--config`, `--log-level`, `--foreground`)
//! 2. Load and validate `freeq.toml`
//! 3. Load or generate the node's ML-DSA-65 identity keypair
//! 4. Bind the QUIC endpoint
//! 5. Open the TUN interface
//! 6. Start the local REST API server
//! 7. Enter the main event loop:
//!    - Accept inbound connections (cloaking check → handshake → tunnel)
//!    - Dial configured peers with persistent endpoints
//!    - Forward packets between TUN and tunnels
//!    - Handle key rotation timers
//!    - Respond to API requests

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

/// freeqd — FreeQ post-quantum overlay network daemon.
#[derive(Parser, Debug)]
#[command(name = "freeqd", version, about)]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/etc/freeq/freeq.toml")]
    config: PathBuf,

    /// Log level filter (e.g. "info", "debug", "freeqd=trace").
    #[arg(long, env = "FREEQ_LOG", default_value = "info")]
    log: String,

    /// Run in the foreground (do not daemonize).
    #[arg(long)]
    foreground: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(&args.log)
        .json()
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "freeqd starting");

    // Load configuration.
    let config = freeq_config::Config::load(&args.config)?;
    config.validate()?;

    tracing::info!(node = %config.node.name, "configuration loaded");

    // 1. Initialize identity keypair.
    let key_path = PathBuf::from(&config.node.key_path);
    let (_keypair, _identity) = init_identity(&key_path)?;
    tracing::info!(key_path = %key_path.display(), "identity keypair ready");

    // 2. Bind QUIC endpoint.
    let listen: std::net::SocketAddr = config
        .node
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address '{}': {e}", config.node.listen))?;
    let endpoint = freeq_transport::endpoint::Endpoint::bind(listen).await?;
    tracing::info!(%listen, "QUIC endpoint bound");

    // 3. Open TUN interface.
    let tun_ip: std::net::IpAddr = config
        .node
        .address
        .split('/')
        .next()
        .ok_or_else(|| anyhow::anyhow!("node.address '{}' has no IP part", config.node.address))?
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid node address: {e}"))?;
    let tun = freeq_tunnel::iface::TunInterface::open(Some("freeq0"), tun_ip).await?;
    tracing::info!(iface = tun.name(), "TUN interface open");

    // 4. Start REST API server.
    if config.node.api_enabled {
        let api_addr: std::net::SocketAddr = config
            .node
            .api_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid api_addr '{}': {e}", config.node.api_addr))?;
        let server = freeq_api::ApiServer::new(api_addr);
        tokio::spawn(async move {
            if let Err(e) = server.serve().await {
                tracing::error!(error = %e, "API server error");
            }
        });
    }

    // 5. Main event loop: accept inbound connections and handle shutdown.
    tracing::info!("freeqd initialized — entering main event loop");
    loop {
        tokio::select! {
            result = endpoint.accept() => {
                match result {
                    Ok(conn) => {
                        tracing::debug!("inbound connection accepted");
                        // TODO(v0.1): cloaking check → handshake → tunnel
                        let _ = conn;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "accept error; endpoint closed");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("freeqd shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Load an existing identity keypair from `path`, or generate and persist a new one.
///
/// Key material is stored at the path from `config.node.key_path`
/// (default `/etc/freeq/identity.key`).
fn init_identity(
    path: &std::path::Path,
) -> Result<(freeq_crypto::sign::IdentityKeypair, freeq_crypto::sign::IdentityPublicKey)> {
    if path.exists() {
        // TODO(v0.1): deserialize the stored keypair bytes once IdentityKeypair
        // gains zeroize-safe from_bytes / to_bytes serialization.
        anyhow::bail!(
            "loading an existing identity key at '{}' is not yet implemented",
            path.display()
        );
    }

    // First-time startup: generate a fresh keypair.
    let mut rng = rand::thread_rng();
    let (keypair, pubkey) = freeq_crypto::sign::IdentityKeypair::generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("identity key generation failed: {e}"))?;

    // Ensure the key directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // TODO(v0.1): persist the full keypair (including secret key, mode 0o600)
    // once IdentityKeypair gains serialization support.
    std::fs::write(path, pubkey.to_bytes())?;
    tracing::info!(key_path = %path.display(), "generated new identity keypair");

    Ok((keypair, pubkey))
}
