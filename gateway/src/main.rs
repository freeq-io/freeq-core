//! freeq-gateway — FreeQ gateway relay binary.
//!
//! # Outbound-only invariant
//!
//! FreeQ has two separate connectivity lanes:
//!
//! 1. **Direct peer connection** — either side may dial (`freeqd`).
//! 2. **Gateway relay** — leaves open outbound sessions only; this binary
//!    accepts those sessions and forwards between them.
//!
//! Hard rules enforced by this process:
//!
//! - The gateway **never** initiates a connection to a leaf.
//! - The session table is keyed by authenticated node identity, not public IP.
//! - If a destination leaf has no active inbound session, the forward path
//!   drops the packet and reports `"remote leaf offline"`.
//! - Failures are never silent: status state + counters + logs + self-heal.
//! - Process liveness is not network health; `/status` and periodic pulses
//!   always report explicit state.
//!
//! This binary reuses FreeQ's transport envelope helpers but does not open TUN
//! interfaces. Leaf dataplane remains the responsibility of `freeqd`.

mod accept;
mod session_table;
mod status;

use accept::{build_peer_registry, run_accept_supervisor, GatewayRuntime};
use anyhow::Result;
use clap::Parser;
use session_table::SessionTable;
use status::{run_status_http, run_status_pulse, GatewayDiagnostics, GatewayState};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Semaphore};

/// freeq-gateway — accept-only FreeQ relay for NAT/CGNAT leaves.
#[derive(Parser, Debug)]
#[command(name = "freeq-gateway", version, about)]
struct Args {
    /// Path to the gateway configuration file.
    #[arg(short, long, default_value = "/etc/freeq/gateway.toml")]
    config: PathBuf,

    /// Log level filter (e.g. "info", "debug", "freeq_gateway=trace").
    #[arg(long, env = "FREEQ_LOG", default_value = "info")]
    log: String,

    /// Loopback HTTP status bind address (`/status`, `/healthz`).
    ///
    /// Set empty string to disable. Default is loopback-only.
    #[arg(
        long,
        env = "FREEQ_GATEWAY_STATUS_ADDR",
        default_value = "127.0.0.1:6790"
    )]
    status_addr: String,

    /// Interval between structured status pulse logs.
    #[arg(long, default_value = "10")]
    status_pulse_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&args.log)
        .json()
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "freeq-gateway starting (accept-only; never dials leaves)"
    );

    let config = freeq_config::Config::load(&args.config).map_err(|err| {
        tracing::error!(error = %err, path = %args.config.display(), "failed to load gateway config");
        err
    })?;
    config.validate_for_gateway().map_err(|err| {
        tracing::error!(error = %err, "gateway config validation failed");
        err
    })?;

    // Hard production check (not debug_assert): refuse any dialable peer.
    for peer in &config.peer {
        if peer.is_dialable() {
            let msg = format!(
                "REFUSING START: peer '{}' is dialable (mode={:?}, endpoint={:?}); \
                 freeq-gateway must never dial leaves",
                peer.name,
                peer.effective_mode(),
                peer.endpoint
            );
            tracing::error!("{msg}");
            anyhow::bail!(msg);
        }
        if peer.effective_mode() != freeq_config::PeerMode::RelayLeaf {
            let msg = format!(
                "REFUSING START: peer '{}' mode must be relay_leaf, got {:?}",
                peer.name,
                peer.effective_mode()
            );
            tracing::error!("{msg}");
            anyhow::bail!(msg);
        }
        tracing::info!(
            peer = %peer.name,
            mode = ?peer.effective_mode(),
            dialable = false,
            has_doc_endpoint = peer.endpoint.is_some(),
            "registered relay leaf (inbound only; endpoint stripped from runtime registry)"
        );
    }

    let listen_addr = parse_listen_addr(&config)?;
    let status_addr = parse_optional_status_addr(&args.status_addr)?;

    let diagnostics = GatewayDiagnostics::new(
        config.node.name.clone(),
        listen_addr.to_string(),
        status_addr.map(|a| a.to_string()),
        config.peer.len(),
    );
    diagnostics
        .set_state(GatewayState::Starting, "configuration validated")
        .await;

    tracing::info!(
        node = %config.node.name,
        peers = config.peer.len(),
        %listen_addr,
        status_addr = ?status_addr,
        "gateway configuration loaded"
    );

    let key_path = PathBuf::from(&config.node.key_path);
    let (identity, public_key) = init_identity(&key_path)?;
    tracing::info!(
        key_path = %key_path.display(),
        public_key_len = public_key.to_bytes().len(),
        "gateway identity keypair ready"
    );

    let peer_registry = Arc::new(build_peer_registry(&config)?);
    let relay_router = Arc::new(build_relay_router(&config)?);
    let relay_tunnel = Arc::new(build_relay_tunnel()?);
    let sessions = SessionTable::new();

    let runtime = Arc::new(GatewayRuntime {
        listen_addr,
        identity: Arc::new(identity),
        peer_registry,
        relay_router,
        relay_tunnel,
        relay_packet_counter: Arc::new(AtomicU64::new(0)),
        sessions,
        diagnostics: Arc::clone(&diagnostics),
        handshake_limiter: Arc::new(Semaphore::new(256)),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Continuous diagnostics: never leave operators with silence.
    let pulse_secs = args.status_pulse_secs.max(1);
    let pulse_diag = Arc::clone(&diagnostics);
    let pulse_task = tokio::spawn(async move {
        run_status_pulse(pulse_diag, Duration::from_secs(pulse_secs)).await;
    });

    let status_task = if let Some(addr) = status_addr {
        let diag = Arc::clone(&diagnostics);
        Some(tokio::spawn(async move {
            if let Err(err) = run_status_http(diag, addr).await {
                tracing::error!(error = %err, "status HTTP server stopped");
            }
        }))
    } else {
        tracing::warn!("status HTTP disabled; relying on log pulses only");
        None
    };

    // Initial pulse so status is visible immediately after start.
    diagnostics.log_pulse().await;

    let supervisor = {
        let runtime = Arc::clone(&runtime);
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            // Intentionally no outbound dial loop. Leaves must connect to us.
            run_accept_supervisor(runtime, shutdown_rx).await;
        })
    };

    // Wait for ctrl-c (or equivalent). Never exit the accept path silently.
    shutdown_signal().await;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    diagnostics
        .set_state(GatewayState::ShuttingDown, "shutdown signal received")
        .await;
    diagnostics.log_pulse().await;

    // Give the supervisor a moment to finish; then abort helpers.
    let _ = tokio::time::timeout(Duration::from_secs(5), supervisor).await;
    pulse_task.abort();
    if let Some(task) = status_task {
        task.abort();
    }

    tracing::info!("freeq-gateway stopped");
    Ok(())
}

fn parse_listen_addr(config: &freeq_config::Config) -> Result<SocketAddr> {
    config
        .node
        .listen
        .parse::<SocketAddr>()
        .map_err(|err| anyhow::anyhow!("invalid node.listen '{}': {err}", config.node.listen))
}

fn parse_optional_status_addr(value: &str) -> Result<Option<SocketAddr>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("off") || trimmed == "-" {
        return Ok(None);
    }
    let addr: SocketAddr = trimmed
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid --status-addr '{trimmed}': {err}"))?;
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "gateway status HTTP must bind to loopback for safety; got {addr} \
             (use SSH tunnel or local agent to scrape)"
        );
    }
    Ok(Some(addr))
}

fn build_relay_router(config: &freeq_config::Config) -> Result<freeq_tunnel::router::Router> {
    let mut router = freeq_tunnel::router::Router::new();
    for peer in &config.peer {
        for prefix in &peer.allowed_ips {
            router.insert(prefix.parse()?, peer.name.clone());
        }
    }
    Ok(router)
}

fn build_relay_tunnel() -> Result<freeq_tunnel::TunnelInterface> {
    let keys = freeq_crypto::FreeQKeyPair::generate_ephemeral_test_pair()?;
    freeq_tunnel::TunnelInterface::new(
        freeq_tunnel::TunnelConfig {
            interface_name: "freeq-gateway-relay".into(),
            mtu: freeq_transport::frame::SECURE_QUIC_MTU,
        },
        keys,
    )
    .map_err(Into::into)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to install Ctrl+C handler");
            // Fall through to a never-resolving sleep so supervisor keeps running
            // rather than treating handler failure as shutdown.
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(sig) => sig,
                Err(err) => {
                    tracing::error!(error = %err, "failed to install SIGTERM handler");
                    ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

fn init_identity(
    path: &std::path::Path,
) -> Result<(
    freeq_crypto::sign::IdentityKeypair,
    freeq_crypto::sign::IdentityPublicKey,
)> {
    if path.exists() {
        validate_existing_private_key_permissions(path)?;
        let key_bytes = std::fs::read(path)?;
        let keypair = freeq_crypto::sign::IdentityKeypair::from_bytes(&key_bytes).map_err(|e| {
            anyhow::anyhow!("failed to load identity key '{}': {e}", path.display())
        })?;
        let public_key = keypair.public_key();
        return Ok((keypair, public_key));
    }

    // Production gateways should provision keys explicitly; auto-generate is a
    // lab convenience and is logged loudly so it is never a silent surprise.
    tracing::warn!(
        key_path = %path.display(),
        "gateway identity key missing; generating a new keypair \
         (provision a stable key for production deployments)"
    );

    let mut rng = rand::thread_rng();
    let (keypair, public_key) = freeq_crypto::sign::IdentityKeypair::generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("identity key generation failed: {e}"))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, keypair.to_bytes())?;
    set_private_key_permissions(path)?;
    tracing::warn!(
        key_path = %path.display(),
        "generated new gateway identity keypair (leaves must trust this public key)"
    );

    Ok((keypair, public_key))
}

fn validate_existing_private_key_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "identity key '{}' must not be readable, writable, or executable by group or world; set permissions to 0600",
                path.display()
            );
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

fn set_private_key_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// Production gateway modules must not dial. Connect is allowed only under
/// `#[cfg(test)]` helpers (e.g. session_table local pair setup).
#[cfg(test)]
mod invariant_tests {
    fn code_without_comments_or_tests(src: &str) -> String {
        let mut out = String::new();
        let mut in_test_mod = false;
        let mut brace_depth = 0i32;
        let mut test_mod_base_depth = 0i32;
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            if trimmed.starts_with("#[cfg(test)]") {
                in_test_mod = true;
                test_mod_base_depth = brace_depth;
                continue;
            }
            if in_test_mod {
                brace_depth += trimmed.matches('{').count() as i32;
                brace_depth -= trimmed.matches('}').count() as i32;
                if brace_depth <= test_mod_base_depth {
                    in_test_mod = false;
                }
                continue;
            }
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    #[test]
    fn gateway_production_sources_do_not_call_endpoint_connect() {
        for (name, src) in [
            ("accept.rs", include_str!("accept.rs")),
            ("main.rs", include_str!("main.rs")),
            ("status.rs", include_str!("status.rs")),
            ("session_table.rs", include_str!("session_table.rs")),
        ] {
            let code = code_without_comments_or_tests(src);
            assert!(
                !code.contains("Endpoint::connect") && !code.contains(".connect("),
                "{name} must not dial leaves; found connect usage outside tests/comments"
            );
        }
    }
}
