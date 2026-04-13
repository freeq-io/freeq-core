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

    if args.foreground {
        tracing::info!("foreground mode selected");
    }

    let startup_blockers = collect_startup_blockers(&config);
    for blocker in &startup_blockers {
        tracing::warn!(%blocker, "startup blocked by unimplemented subsystem");
    }

    if !startup_blockers.is_empty() {
        anyhow::bail!(
            "freeqd cannot start yet; unimplemented startup subsystems: {}",
            startup_blockers.join(", ")
        );
    }

    Ok(())
}

fn collect_startup_blockers(config: &freeq_config::Config) -> Vec<String> {
    let mut blockers = vec![
        format!(
            "identity key load/generation is not implemented for {}",
            PathBuf::from(&config.node.key_path).display()
        ),
        format!(
            "QUIC endpoint binding is not implemented for {}",
            config.node.listen
        ),
        format!(
            "TUN interface bring-up is not implemented for {}",
            config.node.address
        ),
    ];

    if config.node.api_enabled {
        blockers.push(format!(
            "REST API startup is deferred until daemon state is available on {}",
            config.node.api_addr
        ));
    }

    blockers
}

#[cfg(test)]
mod tests {
    use super::collect_startup_blockers;

    fn sample_config() -> freeq_config::Config {
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
            "#,
        )
        .expect("sample config should deserialize")
    }

    #[test]
    fn startup_blockers_cover_stubbed_subsystems() {
        let blockers = collect_startup_blockers(&sample_config());

        assert_eq!(blockers.len(), 4);
        assert!(blockers.iter().any(|b| b.contains("identity key")));
        assert!(blockers.iter().any(|b| b.contains("QUIC endpoint")));
        assert!(blockers.iter().any(|b| b.contains("TUN interface")));
        assert!(blockers.iter().any(|b| b.contains("REST API startup")));
    }
}
