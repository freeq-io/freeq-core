//! freeqd — the FreeQ post-quantum overlay network daemon.

use anyhow::{Context, Result};
use clap::Parser;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ACCEPT_RATE_LIMIT_BURST: u64 = 64;
const ACCEPT_RATE_LIMIT_PER_SECOND: u64 = 32;
const OUTBOUND_RECONNECT_BASE_DELAY: Duration = Duration::from_millis(250);
const OUTBOUND_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(5);

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

    let key_path = PathBuf::from(&config.node.key_path);
    let (identity, public_key) = init_identity(&key_path)?;
    tracing::info!(
        key_path = %key_path.display(),
        public_key_len = public_key.to_bytes().len(),
        "identity keypair ready"
    );

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

    let runtime = start_runtime(config, identity).await?;
    tracing::info!(
        listen = %runtime.listen_addr,
        tun = %runtime.tun_name,
        active_peers = runtime.active_peers.len(),
        "freeqd runtime initialized"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");

    runtime.endpoint.close().await;
    Ok(())
}

fn collect_startup_blockers(config: &freeq_config::Config) -> Vec<String> {
    let _ = config;
    Vec::new()
}

fn init_identity(
    path: &std::path::Path,
) -> Result<(
    freeq_crypto::sign::IdentityKeypair,
    freeq_crypto::sign::IdentityPublicKey,
)> {
    if path.exists() {
        let key_bytes = std::fs::read(path)?;
        let keypair = freeq_crypto::sign::IdentityKeypair::from_bytes(&key_bytes).map_err(|e| {
            anyhow::anyhow!("failed to load identity key '{}': {e}", path.display())
        })?;
        let public_key = keypair.public_key();
        return Ok((keypair, public_key));
    }

    let mut rng = rand::thread_rng();
    let (keypair, public_key) = freeq_crypto::sign::IdentityKeypair::generate(&mut rng)
        .map_err(|e| anyhow::anyhow!("identity key generation failed: {e}"))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, keypair.to_bytes())?;
    set_private_key_permissions(path)?;
    tracing::info!(key_path = %path.display(), "generated new identity keypair");

    Ok((keypair, public_key))
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

#[cfg(unix)]
#[derive(Debug, Clone)]
struct PrivilegeDropTarget {
    uid: libc::uid_t,
    gid: libc::gid_t,
    label: String,
}

#[cfg(unix)]
fn current_euid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn maybe_drop_privileges() -> Result<Option<PrivilegeDropTarget>> {
    if current_euid() != 0 {
        return Ok(None);
    }

    let target = resolve_privilege_drop_target_from_env()?;
    let Some(target) = target else {
        tracing::warn!("running as root with no privilege drop target configured");
        return Ok(None);
    };

    drop_privileges_to(&target)?;
    Ok(Some(target))
}

#[cfg(not(unix))]
fn maybe_drop_privileges() -> Result<Option<()>> {
    Ok(None)
}

#[cfg(unix)]
fn resolve_privilege_drop_target_from_env() -> Result<Option<PrivilegeDropTarget>> {
    if let (Some(uid), Some(gid)) = (
        parse_env_id("FREEQ_DROP_TO_UID")?,
        parse_env_id("FREEQ_DROP_TO_GID")?,
    ) {
        return Ok(Some(PrivilegeDropTarget {
            uid,
            gid,
            label: format!("uid={uid},gid={gid}"),
        }));
    }

    if let Some(user) = std::env::var_os("FREEQ_DROP_TO_USER") {
        let user = user.to_string_lossy().into_owned();
        let group = std::env::var_os("FREEQ_DROP_TO_GROUP")
            .map(|value| value.to_string_lossy().into_owned());
        return lookup_privilege_target_by_name(&user, group.as_deref()).map(Some);
    }

    if let (Some(uid), Some(gid)) = (parse_env_id("SUDO_UID")?, parse_env_id("SUDO_GID")?) {
        return Ok(Some(PrivilegeDropTarget {
            uid,
            gid,
            label: format!("sudo uid={uid},gid={gid}"),
        }));
    }

    Ok(None)
}

#[cfg(unix)]
fn parse_env_id(key: &str) -> Result<Option<u32>> {
    match std::env::var(key) {
        Ok(value) => {
            Ok(Some(value.parse().with_context(|| {
                format!("{key} must be a valid integer")
            })?))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{key} must be valid unicode");
        }
    }
}

#[cfg(unix)]
fn lookup_privilege_target_by_name(user: &str, group: Option<&str>) -> Result<PrivilegeDropTarget> {
    use std::ffi::CString;

    let user_cstr = CString::new(user).context("drop user contains interior NUL")?;
    let passwd = unsafe { libc::getpwnam(user_cstr.as_ptr()) };
    if passwd.is_null() {
        anyhow::bail!("drop user '{user}' was not found");
    }
    let passwd = unsafe { *passwd };

    let gid = if let Some(group) = group {
        let group_cstr = CString::new(group).context("drop group contains interior NUL")?;
        let group_entry = unsafe { libc::getgrnam(group_cstr.as_ptr()) };
        if group_entry.is_null() {
            anyhow::bail!("drop group '{group}' was not found");
        }
        unsafe { (*group_entry).gr_gid }
    } else {
        passwd.pw_gid
    };

    Ok(PrivilegeDropTarget {
        uid: passwd.pw_uid,
        gid,
        label: match group {
            Some(group) => format!("{user}:{group}"),
            None => user.to_string(),
        },
    })
}

#[cfg(unix)]
fn drop_privileges_to(target: &PrivilegeDropTarget) -> Result<()> {
    let empty_groups: [libc::gid_t; 0] = [];
    if unsafe {
        libc::setgroups(
            empty_groups
                .len()
                .try_into()
                .expect("empty supplementary group list fits in c_int"),
            empty_groups.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to clear supplementary groups");
    }
    if unsafe { libc::setgid(target.gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to drop group privileges");
    }
    if unsafe { libc::setuid(target.uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to drop user privileges");
    }
    Ok(())
}

struct RuntimeHandles {
    endpoint: freeq_transport::endpoint::Endpoint,
    tun_name: String,
    listen_addr: std::net::SocketAddr,
    active_peers: Vec<String>,
    _api_addr: Option<std::net::SocketAddr>,
    _api_state: freeq_api::state::SharedApiState,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn start_runtime(
    config: freeq_config::Config,
    identity: freeq_crypto::sign::IdentityKeypair,
) -> Result<RuntimeHandles> {
    let listen_addr: std::net::SocketAddr = config
        .node
        .listen
        .parse()
        .context("node.listen must be a socket address")?;
    let tun_network = parse_node_network(&config.node.address)?;
    let endpoint = freeq_transport::endpoint::Endpoint::bind(listen_addr).await?;
    let tun = Arc::new(freeq_tunnel::iface::TunInterface::open(None, tun_network).await?);
    let tun_name = tun.name().to_string();
    #[cfg(unix)]
    if let Some(target) = maybe_drop_privileges()? {
        tracing::info!(target = %target.label, "dropped daemon privileges after TUN initialization");
    }
    #[cfg(not(unix))]
    let _ = maybe_drop_privileges()?;
    let api_state = build_api_state(&config).shared();

    let mut registry = freeq_auth::registry::PeerRegistry::new();
    let mut router = freeq_tunnel::router::Router::new();
    for peer in &config.peer {
        registry.add_peer(peer_entry_from_config(peer)?)?;
        for prefix in &peer.allowed_ips {
            router.insert(prefix.parse()?, peer.name.clone());
        }
    }

    let engine = Arc::new(freeq_tunnel::forward::TunnelEngine::new(
        freeq_crypto::agility::detect_bulk_algorithm(),
        router,
    ));
    let registry = Arc::new(registry);
    let identity = Arc::new(identity);
    let mut tasks = Vec::new();
    let mut active_peers = Vec::new();
    let api_addr = if config.node.api_enabled {
        Some(
            config
                .node
                .api_addr
                .parse()
                .context("node.api_addr must be a socket address")?,
        )
    } else {
        None
    };

    for peer in &config.peer {
        let Some(_endpoint_value) = &peer.endpoint else {
            continue;
        };

        let transport_fingerprint =
            parse_transport_fingerprint(peer.transport_cert_fingerprint.as_deref().ok_or_else(
                || anyhow::anyhow!("missing transport fingerprint for {}", peer.name),
            )?)?;

        active_peers.push(peer.name.clone());
        tasks.push(spawn_outbound_peer_supervisor(
            peer.clone(),
            transport_fingerprint,
            endpoint.clone(),
            identity.clone(),
            engine.clone(),
            tun.clone(),
            api_state.clone(),
        ));
    }

    tasks.push(spawn_tun_to_peer_loop(
        engine.clone(),
        tun.clone(),
        api_state.clone(),
    ));
    tasks.push(spawn_accept_loop(
        endpoint.clone(),
        identity,
        registry,
        engine,
        tun,
        api_state.clone(),
    ));

    if let Some(api_addr) = api_addr {
        let server = freeq_api::ApiServer::new(api_addr, api_state.clone());
        tasks.push(tokio::spawn(async move {
            if let Err(err) = server.serve().await {
                tracing::warn!(%err, "API server exited with error");
            }
        }));
    }

    Ok(RuntimeHandles {
        endpoint,
        tun_name,
        listen_addr,
        active_peers,
        _api_addr: api_addr,
        _api_state: api_state,
        _tasks: tasks,
    })
}

fn build_api_state(config: &freeq_config::Config) -> freeq_api::state::ApiState {
    let peers = config
        .peer
        .iter()
        .map(|peer| freeq_api::models::PeerSummary {
            name: peer.name.clone(),
            endpoint: peer.endpoint.clone(),
            allowed_ips: peer.allowed_ips.clone(),
            connected: false,
            last_handshake: None,
        })
        .collect();

    freeq_api::state::ApiState::new(
        config.node.name.clone(),
        env!("CARGO_PKG_VERSION").into(),
        config.node.algorithm.clone(),
        config.node.sign.clone(),
        format!("{:?}", freeq_crypto::agility::detect_bulk_algorithm()).to_lowercase(),
        peers,
    )
}

fn spawn_tun_to_peer_loop(
    engine: Arc<freeq_tunnel::forward::TunnelEngine>,
    tun: Arc<freeq_tunnel::iface::TunInterface>,
    api_state: freeq_api::state::SharedApiState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match tun.read_packet().await {
                Ok(packet) => {
                    let packet_len = packet.len() as u64;
                    match engine.forward_packet(packet).await {
                        Ok(peer_name) => {
                            api_state.add_bytes_sent(&peer_name, packet_len);
                        }
                        Err(err) => {
                            tracing::warn!(%err, "failed to forward packet from TUN");
                            api_state.record_packet_forward_failure();
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(%err, "failed to read from TUN");
                    api_state.record_tun_read_error();
                    break;
                }
            }
        }
    })
}

async fn run_peer_to_tun_loop(
    peer_name: String,
    session_generation: u64,
    engine: Arc<freeq_tunnel::forward::TunnelEngine>,
    tun: Arc<freeq_tunnel::iface::TunInterface>,
    api_state: freeq_api::state::SharedApiState,
) {
    loop {
        let packet = engine
            .receive_packet_timeout(
                &peer_name,
                session_generation,
                freeq_transport::connection::QUIC_RECV_POLL_TIMEOUT,
            )
            .await;

        match packet {
            Ok(packet) => {
                let packet_len = packet.len() as u64;
                if let Err(err) = tun.write_packet(packet).await {
                    tracing::warn!(peer = %peer_name, %err, "failed to write peer packet to TUN");
                    api_state.record_tun_write_error();
                    api_state.mark_peer_disconnected(&peer_name);
                    engine.remove_session_if_current(&peer_name, session_generation);
                    break;
                }
                api_state.add_bytes_received(&peer_name, packet_len);
            }
            Err(freeq_tunnel::TunnelError::Transport(freeq_transport::TransportError::Timeout)) => {
                if let Err(err) = engine.send_heartbeat(&peer_name, session_generation).await {
                    match err {
                        freeq_tunnel::TunnelError::StaleSession(_) => break,
                        other => {
                            tracing::warn!(peer = %peer_name, %other, "failed to send peer heartbeat");
                            api_state.record_heartbeat_failure(&peer_name);
                            api_state.mark_peer_disconnected(&peer_name);
                            engine.remove_session_if_current(&peer_name, session_generation);
                            break;
                        }
                    }
                }
                api_state.record_heartbeat_sent(&peer_name);
                continue;
            }
            Err(freeq_tunnel::TunnelError::StaleSession(_)) => {
                tracing::debug!(peer = %peer_name, generation = session_generation, "stale peer receive loop exiting");
                break;
            }
            Err(err) => {
                tracing::warn!(peer = %peer_name, %err, "failed to receive peer packet");
                api_state.record_peer_receive_error();
                api_state.mark_peer_disconnected(&peer_name);
                engine.remove_session_if_current(&peer_name, session_generation);
                break;
            }
        }
    }
}

fn reconnect_delay(attempt: u32) -> Duration {
    use rand::Rng as _;

    let multiplier = 1u32.checked_shl(attempt.min(5)).unwrap_or(32);
    let base_delay = OUTBOUND_RECONNECT_BASE_DELAY
        .checked_mul(multiplier)
        .unwrap_or(OUTBOUND_RECONNECT_MAX_DELAY)
        .min(OUTBOUND_RECONNECT_MAX_DELAY);
    let base_ms = base_delay.as_millis().min(u128::from(u64::MAX)) as u64;

    if base_ms == 0 {
        return Duration::from_millis(0);
    }

    let jitter_floor = (base_ms / 2).max(1);
    let jitter_ceiling = base_ms;
    Duration::from_millis(rand::thread_rng().gen_range(jitter_floor..=jitter_ceiling))
}

fn spawn_peer_to_tun_loop(
    peer_name: String,
    session_generation: u64,
    engine: Arc<freeq_tunnel::forward::TunnelEngine>,
    tun: Arc<freeq_tunnel::iface::TunInterface>,
    api_state: freeq_api::state::SharedApiState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_peer_to_tun_loop(
        peer_name,
        session_generation,
        engine,
        tun,
        api_state,
    ))
}

fn spawn_outbound_peer_supervisor(
    peer: freeq_config::PeerConfig,
    transport_fingerprint: freeq_transport::endpoint::CertificateFingerprint,
    endpoint: freeq_transport::endpoint::Endpoint,
    identity: Arc<freeq_crypto::sign::IdentityKeypair>,
    engine: Arc<freeq_tunnel::forward::TunnelEngine>,
    tun: Arc<freeq_tunnel::iface::TunInterface>,
    api_state: freeq_api::state::SharedApiState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempt = 0u32;

        loop {
            let endpoint_value = match &peer.endpoint {
                Some(value) => value.as_str(),
                None => return,
            };

            let handshake_started = Instant::now();
            let peer_addr = match resolve_peer_endpoint(endpoint_value).await {
                Ok(peer_addr) => peer_addr,
                Err(err) => {
                    tracing::warn!(peer = %peer.name, %err, "failed to resolve peer endpoint");
                    api_state.record_outbound_connect_failure(&peer.name);
                    let delay = reconnect_delay(attempt);
                    api_state.record_reconnect_scheduled(&peer.name, delay);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            };
            let connection = match endpoint.connect(&transport_fingerprint, peer_addr).await {
                Ok(connection) => Arc::new(connection),
                Err(err) => {
                    tracing::warn!(peer = %peer.name, %err, "failed to connect to peer");
                    api_state.record_outbound_connect_failure(&peer.name);
                    let delay = reconnect_delay(attempt);
                    api_state.record_reconnect_scheduled(&peer.name, delay);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            };
            let session_keys =
                match run_initiator_handshake(&identity, &peer, connection.as_ref()).await {
                    Ok(session_keys) => session_keys,
                    Err(err) => {
                        tracing::warn!(peer = %peer.name, %err, "outbound peer handshake failed");
                        api_state.record_handshake_failure(Some(&peer.name), false);
                        let delay = reconnect_delay(attempt);
                        api_state.record_reconnect_scheduled(&peer.name, delay);
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                };

            let session_generation = engine.add_peer(peer.name.clone(), connection, &session_keys);
            api_state.record_handshake_success(
                &peer.name,
                Some(handshake_started.elapsed().as_secs_f64() * 1000.0),
            );
            attempt = 0;

            run_peer_to_tun_loop(
                peer.name.clone(),
                session_generation,
                engine.clone(),
                tun.clone(),
                api_state.clone(),
            )
            .await;

            tracing::info!(peer = %peer.name, "peer session ended; scheduling reconnect");
            let delay = reconnect_delay(attempt);
            api_state.record_reconnect_scheduled(&peer.name, delay);
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

fn spawn_accept_loop(
    endpoint: freeq_transport::endpoint::Endpoint,
    identity: Arc<freeq_crypto::sign::IdentityKeypair>,
    registry: Arc<freeq_auth::registry::PeerRegistry>,
    engine: Arc<freeq_tunnel::forward::TunnelEngine>,
    tun: Arc<freeq_tunnel::iface::TunInterface>,
    api_state: freeq_api::state::SharedApiState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let accept_limiter = freeq_api::rate_limit::TokenBucket::new(
            ACCEPT_RATE_LIMIT_BURST,
            ACCEPT_RATE_LIMIT_PER_SECOND,
        );

        loop {
            let connection = match endpoint.accept().await {
                Ok(connection) => Arc::new(connection),
                Err(err) => {
                    tracing::warn!(%err, "failed to accept incoming connection");
                    api_state.record_incoming_accept_failure();
                    continue;
                }
            };
            if !accept_limiter.allow() {
                tracing::warn!("dropping inbound connection due to accept rate limit");
                continue;
            }
            let handshake_started = Instant::now();

            match run_responder_handshake(&identity, &registry, connection.as_ref()).await {
                Ok((peer_name, session_keys)) => {
                    let session_generation =
                        engine.add_peer(peer_name.clone(), connection, &session_keys);
                    api_state.record_handshake_success(
                        &peer_name,
                        Some(handshake_started.elapsed().as_secs_f64() * 1000.0),
                    );

                    std::mem::drop(spawn_peer_to_tun_loop(
                        peer_name,
                        session_generation,
                        engine.clone(),
                        tun.clone(),
                        api_state.clone(),
                    ));
                }
                Err(err) => {
                    tracing::warn!(%err, "incoming peer handshake failed");
                    api_state.record_handshake_failure(None, true);
                }
            }
        }
    })
}

async fn run_initiator_handshake(
    identity: &freeq_crypto::sign::IdentityKeypair,
    peer: &freeq_config::PeerConfig,
    connection: &freeq_transport::connection::PeerConnection,
) -> Result<freeq_auth::handshake::SessionKeys> {
    let expected_identity =
        freeq_crypto::sign::IdentityPublicKey::from_bytes(&decode_base64(&peer.public_key)?)?;
    let (state, init_msg) = {
        let mut rng = rand::thread_rng();
        let (_secret, initiator_kem_public) =
            freeq_crypto::kem::HybridSecretKey::generate(&mut rng)?;
        freeq_auth::handshake::InitiatorHandshake::new(
            identity,
            &initiator_kem_public.to_bytes(),
            expected_identity,
        )?
    };
    connection.send(init_msg.into()).await?;
    let response = connection.recv().await?;
    let (state, kem_msg) = {
        let mut rng = rand::thread_rng();
        state.process_response(&response, &mut rng)?
    };
    connection.send(kem_msg.into()).await?;
    Ok(state.finalize()?)
}

async fn run_responder_handshake(
    identity: &freeq_crypto::sign::IdentityKeypair,
    registry: &freeq_auth::registry::PeerRegistry,
    connection: &freeq_transport::connection::PeerConnection,
) -> Result<(String, freeq_auth::handshake::SessionKeys)> {
    let init_msg = connection.recv().await?;
    let (peer_name, state, response) = {
        let mut rng = rand::thread_rng();
        let (responder_kem_secret, _) = freeq_crypto::kem::HybridSecretKey::generate(&mut rng)?;
        freeq_auth::handshake::ResponderHandshake::process_init_with_peer_name(
            identity,
            responder_kem_secret,
            registry,
            &init_msg,
        )?
    };
    connection.send(response.into()).await?;
    let kem_msg = connection.recv().await?;
    Ok((peer_name, state.process_kem(&kem_msg)?))
}

fn peer_entry_from_config(
    peer: &freeq_config::PeerConfig,
) -> Result<freeq_auth::registry::PeerEntry> {
    Ok(freeq_auth::registry::PeerEntry {
        name: peer.name.clone(),
        identity_pubkey: decode_base64(&peer.public_key)?,
        kem_pubkey: decode_base64(&peer.kem_key)?,
        endpoint: peer.endpoint.clone(),
        allowed_ips: peer
            .allowed_ips
            .iter()
            .map(|prefix| prefix.parse())
            .collect::<std::result::Result<Vec<ipnetwork::IpNetwork>, _>>()?,
    })
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    Ok(base64::engine::general_purpose::STANDARD.decode(value)?)
}

fn parse_transport_fingerprint(
    value: &str,
) -> Result<freeq_transport::endpoint::CertificateFingerprint> {
    let bytes = hex::decode(value.trim())?;
    Ok(bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("transport fingerprint must be 32 bytes"))?)
}

fn parse_node_network(value: &str) -> Result<ipnetwork::IpNetwork> {
    Ok(value
        .parse()
        .map_err(|e| anyhow::anyhow!("node.address must be a valid IP network: {e}"))?)
}

async fn resolve_peer_endpoint(value: &str) -> Result<std::net::SocketAddr> {
    if let Ok(addr) = value.parse() {
        return Ok(addr);
    }

    tokio::net::lookup_host(value)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses resolved for peer endpoint {value}"))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::parse_env_id;
    use super::{
        build_api_state, collect_startup_blockers, init_identity, parse_transport_fingerprint,
    };

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

            [[peer]]
            name = "lon-01"
            endpoint = "127.0.0.1:51820"
            transport_cert_fingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            public_key = "AQIDBA=="
            kem_key = "BQYHCA=="
            allowed_ips = ["10.0.0.2/32"]
            "#,
        )
        .expect("sample config should deserialize")
    }

    #[test]
    fn startup_blockers_cover_stubbed_subsystems() {
        let blockers = collect_startup_blockers(&sample_config());

        assert!(blockers.is_empty());
    }

    #[test]
    fn init_identity_persists_and_reloads_seed_bytes() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let key_path = tempdir.path().join("identity.key");

        let (generated_keypair, generated_public_key) =
            init_identity(&key_path).expect("initial key generation");
        let (loaded_keypair, loaded_public_key) =
            init_identity(&key_path).expect("reload from disk");

        assert_eq!(generated_keypair.to_bytes(), loaded_keypair.to_bytes());
        assert_eq!(
            generated_public_key.to_bytes(),
            loaded_public_key.to_bytes()
        );
    }

    #[test]
    fn transport_fingerprint_parser_accepts_32_byte_hex() {
        let fingerprint = parse_transport_fingerprint(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .expect("fingerprint");

        assert_eq!(fingerprint.len(), 32);
        assert_eq!(fingerprint[0], 0x00);
        assert_eq!(fingerprint[31], 0xff);
    }

    #[test]
    fn api_state_builds_from_config() {
        let state = build_api_state(&sample_config());
        let status = state.status_response();
        let peers = state.peer_summaries();

        assert_eq!(status.name, "nyc-01");
        assert_eq!(status.peer_count, 1);
        assert_eq!(peers[0].name, "lon-01");
        assert!(!peers[0].connected);
    }

    #[cfg(unix)]
    #[test]
    fn parse_env_id_accepts_integer_values() {
        unsafe {
            std::env::set_var("FREEQ_TEST_DROP_ID", "1234");
        }
        let parsed = parse_env_id("FREEQ_TEST_DROP_ID").expect("env should parse");
        assert_eq!(parsed, Some(1234));
        unsafe {
            std::env::remove_var("FREEQ_TEST_DROP_ID");
        }
    }
}
