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

    // TODO(v0.1): initialize identity keypair
    // TODO(v0.1): bind QUIC endpoint
    // TODO(v0.1): open TUN interface
    // TODO(v0.1): start REST API server
    // TODO(v0.1): enter main event loop

    tracing::info!("freeqd initialized — entering main event loop");

    // Placeholder: park the runtime.
    tokio::signal::ctrl_c().await?;
    tracing::info!("freeqd shutting down");

    Ok(())
}
