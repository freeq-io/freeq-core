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
use base64::Engine as _;
use bytes::Bytes;
use clap::Parser;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

const API_STATE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DATAPLANE_CHANNEL_CAPACITY: usize = 256;
const HANDSHAKE_INIT_PACKET_ID: u64 = 0;
const HANDSHAKE_RESPONSE_PACKET_ID: u64 = 1;
const HANDSHAKE_KEM_PACKET_ID: u64 = 2;
const HANDSHAKE_CONFIRM_PACKET_ID: u64 = 3;

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

    let tunnel_service = Arc::new(init_tunnel_service(&config)?);
    let api_state = init_api_state(&config, tunnel_service.as_ref()).await;
    tracing::info!(
        interface = %tunnel_service.interface_config().interface_name,
        mtu = tunnel_service.interface_config().mtu,
        configured_peers = config.peer.len(),
        "tunnel service initialized"
    );
    let _api_state_refresh =
        spawn_api_state_refresh(api_state.clone(), Arc::clone(&tunnel_service));

    let api_server = if config.node.api_enabled {
        Some(build_api_server(&config, api_state.clone())?)
    } else {
        None
    };

    let startup_blockers = collect_startup_blockers();
    api_state
        .set_startup_blockers(startup_blockers.clone())
        .await;
    for blocker in &startup_blockers {
        tracing::warn!(%blocker, "startup blocked by unimplemented subsystem");
    }

    if !startup_blockers.is_empty() {
        if let Some(api_server) = api_server {
            tracing::info!(
                addr = %config.node.api_addr,
                refresh_secs = API_STATE_REFRESH_INTERVAL.as_secs(),
                "entering status-only API mode while dataplane startup blockers remain"
            );
            return serve_status_only_api(api_server).await;
        }

        anyhow::bail!(
            "freeqd cannot start yet; unimplemented startup subsystems: {}",
            startup_blockers.join(", ")
        );
    }

    let endpoint = freeq_transport::endpoint::Endpoint::bind(parse_listen_addr(&config)?).await?;
    let peer_addrs = parse_peer_socket_addrs(&config)?;
    let peer_registry = Arc::new(build_peer_registry(&config)?);
    let tun = Arc::new(open_tun_interface(&config).await?);
    let (packet_ingress_tx, packet_ingress_rx) = mpsc::channel(DATAPLANE_CHANNEL_CAPACITY);
    let (packet_egress_tx, packet_egress_rx) = mpsc::channel(DATAPLANE_CHANNEL_CAPACITY);
    let _packet_io_runtime = spawn_packet_io_runtime(
        PacketIo::Tun(Arc::clone(&tun)),
        packet_ingress_tx,
        packet_egress_rx,
        api_state.clone(),
    );
    let dataplane_shared = DataplaneShared {
        endpoint: endpoint.clone(),
        tunnel_service: Arc::clone(&tunnel_service),
        peer_addrs: Arc::new(peer_addrs),
        active_sessions: Arc::new(Mutex::new(HashMap::new())),
        identity: Arc::new(identity),
        peer_registry,
        api_state: api_state.clone(),
    };
    let _dataplane_runtime =
        spawn_dataplane_runtime(dataplane_shared, packet_ingress_rx, packet_egress_tx);

    if let Some(api_server) = api_server {
        tokio::spawn(async move {
            if let Err(err) = api_server.serve().await {
                tracing::error!(error = %err, "FreeQ API server stopped unexpectedly");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received; stopping freeqd");
    endpoint.close().await;
    Ok(())
}

async fn init_api_state(
    config: &freeq_config::Config,
    tunnel_service: &freeq_tunnel::TunnelService,
) -> freeq_api::ApiState {
    let stats = tunnel_service.stats();
    let state = freeq_api::ApiState::new(
        config.node.name.clone(),
        env!("CARGO_PKG_VERSION").into(),
        config.node.algorithm.clone(),
        config.node.sign.clone(),
        format!(
            "{:?}",
            freeq_crypto::agility::AlgorithmSuite::default().bulk
        ),
        config.peer.len(),
    );
    state.set_peer_count(config.peer.len()).await;
    state
        .update_runtime_counters(
            freeq_api::TunnelRuntimeSnapshot {
                interface_name: Some(tunnel_service.interface_config().interface_name.clone()),
                interface_mtu: Some(tunnel_service.interface_config().mtu),
                packets_ingested: stats.packets_ingested,
                encrypted_bytes: stats.bytes_encrypted,
                transport_frames: stats.frames_emitted,
                route_misses: stats.route_misses,
            },
            freeq_api::state::ErrorCounters {
                malformed_packet_errors: stats.malformed_packet_errors,
                crypto_errors: stats.crypto_errors,
                transport_errors: stats.transport_errors,
            },
        )
        .await;
    state
}

fn collect_startup_blockers() -> Vec<String> {
    Vec::new()
}

#[allow(dead_code)]
type PacketIngress = mpsc::Receiver<Bytes>;
#[allow(dead_code)]
type PacketEgress = mpsc::Sender<Bytes>;

#[derive(Clone)]
enum PacketIo {
    Tun(Arc<freeq_tunnel::TunInterface>),
    #[cfg(test)]
    InMemory {
        ingress: Arc<Mutex<mpsc::Receiver<Bytes>>>,
        egress: PacketEgress,
    },
}

impl PacketIo {
    async fn read_packet(&self) -> freeq_tunnel::Result<Bytes> {
        match self {
            Self::Tun(tun) => tun.read_packet().await,
            #[cfg(test)]
            Self::InMemory { ingress, .. } => {
                ingress.lock().await.recv().await.ok_or_else(|| {
                    freeq_tunnel::TunnelError::Interface("packet source closed".into())
                })
            }
        }
    }

    async fn write_packet(&self, packet: Bytes) -> freeq_tunnel::Result<()> {
        match self {
            Self::Tun(tun) => tun.write_packet(packet).await,
            #[cfg(test)]
            Self::InMemory { egress, .. } => egress
                .send(packet)
                .await
                .map_err(|_| freeq_tunnel::TunnelError::Interface("packet sink closed".into())),
        }
    }
}

#[allow(dead_code)]
struct DataplaneRuntime {
    _accept_task: tokio::task::JoinHandle<()>,
    _egress_task: tokio::task::JoinHandle<()>,
}

struct PacketIoRuntime {
    _ingress_task: tokio::task::JoinHandle<()>,
    _egress_task: tokio::task::JoinHandle<()>,
}

struct ActivePeerSession {
    connection: freeq_transport::connection::PeerConnection,
    outbound_key: [u8; 32],
    inbound_key: [u8; 32],
    outbound_counter: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
struct DataplaneShared {
    endpoint: freeq_transport::endpoint::Endpoint,
    tunnel_service: Arc<freeq_tunnel::TunnelService>,
    peer_addrs: Arc<HashMap<String, SocketAddr>>,
    active_sessions: Arc<Mutex<HashMap<String, Arc<ActivePeerSession>>>>,
    identity: Arc<freeq_crypto::sign::IdentityKeypair>,
    peer_registry: Arc<freeq_auth::registry::PeerRegistry>,
    api_state: freeq_api::ApiState,
}

#[allow(dead_code)]
fn parse_peer_socket_addrs(config: &freeq_config::Config) -> Result<HashMap<String, SocketAddr>> {
    let mut peers = HashMap::with_capacity(config.peer.len());
    for peer in &config.peer {
        let endpoint = peer.endpoint.as_ref().ok_or_else(|| {
            anyhow::anyhow!("peer '{}' is missing a transport endpoint", peer.name)
        })?;
        let addr = endpoint.parse::<SocketAddr>().map_err(|_| {
            anyhow::anyhow!(
                "peer '{}' endpoint '{}' must resolve to a concrete socket address until DNS resolution is implemented",
                peer.name,
                endpoint
            )
        })?;
        peers.insert(peer.name.clone(), addr);
    }

    Ok(peers)
}

fn build_peer_registry(
    config: &freeq_config::Config,
) -> Result<freeq_auth::registry::PeerRegistry> {
    let mut registry = freeq_auth::registry::PeerRegistry::new();
    for peer in &config.peer {
        let identity_pubkey = base64::engine::general_purpose::STANDARD
            .decode(&peer.public_key)
            .map_err(|err| {
                anyhow::anyhow!("invalid base64 public key for '{}': {err}", peer.name)
            })?;
        let kem_pubkey = base64::engine::general_purpose::STANDARD
            .decode(&peer.kem_key)
            .map_err(|err| anyhow::anyhow!("invalid base64 KEM key for '{}': {err}", peer.name))?;
        let allowed_ips = peer
            .allowed_ips
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNetwork>().map_err(|err| {
                    anyhow::anyhow!(
                        "invalid allowed_ips entry '{}' for '{}': {err}",
                        cidr,
                        peer.name
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;

        registry.add_peer(freeq_auth::registry::PeerEntry {
            name: peer.name.clone(),
            identity_pubkey,
            kem_pubkey,
            endpoint: peer.endpoint.clone(),
            allowed_ips,
        })?;
    }

    Ok(registry)
}

fn parse_listen_addr(config: &freeq_config::Config) -> Result<SocketAddr> {
    config
        .node
        .listen
        .parse::<SocketAddr>()
        .map_err(|err| anyhow::anyhow!("invalid node.listen '{}': {err}", config.node.listen))
}

async fn open_tun_interface(config: &freeq_config::Config) -> Result<freeq_tunnel::TunInterface> {
    let network =
        config.node.address.parse::<IpNetwork>().map_err(|err| {
            anyhow::anyhow!("invalid node.address '{}': {err}", config.node.address)
        })?;
    let tun = freeq_tunnel::TunInterface::open(None, network.ip()).await?;
    tracing::info!(
        interface = %tun.name(),
        address = %config.node.address,
        "host TUN interface opened"
    );
    Ok(tun)
}

fn build_api_server(
    config: &freeq_config::Config,
    api_state: freeq_api::ApiState,
) -> Result<freeq_api::ApiServer> {
    let addr = config.node.api_addr.parse().map_err(|err| {
        anyhow::anyhow!(
            "invalid API listen address '{}': {err}",
            config.node.api_addr
        )
    })?;
    Ok(freeq_api::ApiServer::new(addr, api_state))
}

fn spawn_api_state_refresh(
    api_state: freeq_api::ApiState,
    tunnel_service: Arc<freeq_tunnel::TunnelService>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(API_STATE_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            refresh_api_state(&api_state, tunnel_service.as_ref()).await;
        }
    })
}

fn spawn_packet_io_runtime(
    packet_io: PacketIo,
    packet_ingress: PacketEgress,
    mut packet_egress: PacketIngress,
    api_state: freeq_api::ApiState,
) -> PacketIoRuntime {
    let ingress_io = packet_io.clone();
    let ingress_api_state = api_state.clone();
    let ingress_task = tokio::spawn(async move {
        loop {
            match ingress_io.read_packet().await {
                Ok(packet) => {
                    if packet_ingress.send(packet).await.is_err() {
                        tracing::warn!("packet ingress receiver dropped");
                        return;
                    }
                }
                Err(err) => {
                    record_tunnel_error(&ingress_api_state, &err).await;
                    tracing::error!(error = %err, "packet ingress loop stopped");
                    return;
                }
            }
        }
    });
    let egress_task = tokio::spawn(async move {
        while let Some(packet) = packet_egress.recv().await {
            if let Err(err) = packet_io.write_packet(packet).await {
                record_tunnel_error(&api_state, &err).await;
                tracing::error!(error = %err, "packet egress loop stopped");
                return;
            }
        }
    });

    PacketIoRuntime {
        _ingress_task: ingress_task,
        _egress_task: egress_task,
    }
}

#[allow(dead_code)]
fn spawn_dataplane_runtime(
    shared: DataplaneShared,
    packet_ingress: PacketIngress,
    packet_egress: PacketEgress,
) -> DataplaneRuntime {
    let accept_task = tokio::spawn(run_accept_loop(shared.clone(), packet_egress));
    let egress_task = tokio::spawn(run_egress_loop(shared, packet_ingress));

    DataplaneRuntime {
        _accept_task: accept_task,
        _egress_task: egress_task,
    }
}

#[allow(dead_code)]
async fn run_accept_loop(shared: DataplaneShared, packet_egress: PacketEgress) {
    loop {
        match shared.endpoint.accept().await {
            Ok(connection) => {
                let (peer_name, session) = match accept_inbound_session(
                    connection,
                    shared.identity.as_ref(),
                    shared.peer_registry.as_ref(),
                )
                .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        if is_silent_inbound_probe(&err) {
                            tracing::trace!("silently dropped unauthenticated inbound probe");
                            continue;
                        }
                        shared
                            .api_state
                            .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                            .await;
                        tracing::warn!(error = %err, "inbound session negotiation failed");
                        continue;
                    }
                };
                shared
                    .active_sessions
                    .lock()
                    .await
                    .insert(peer_name.clone(), Arc::clone(&session));
                tokio::spawn(run_connection_receiver(
                    session,
                    Arc::clone(&shared.tunnel_service),
                    packet_egress.clone(),
                    shared.api_state.clone(),
                    peer_name,
                ));
            }
            Err(err) => {
                shared
                    .api_state
                    .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                    .await;
                tracing::error!(error = %err, "transport accept loop stopped");
                return;
            }
        }
    }
}

fn is_silent_inbound_probe(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<freeq_auth::AuthError>(),
        Some(freeq_auth::AuthError::Cloaked)
    ) || matches!(
        err.downcast_ref::<freeq_transport::TransportError>(),
        Some(
            freeq_transport::TransportError::Timeout
                | freeq_transport::TransportError::ConnectionLost(_)
        )
    )
}

#[allow(dead_code)]
async fn run_egress_loop(shared: DataplaneShared, mut packet_ingress: PacketIngress) {
    while let Some(packet) = packet_ingress.recv().await {
        let routed_packet = match route_packet_for_peer(&shared.tunnel_service, packet) {
            Ok(routed_packet) => routed_packet,
            Err(err) => {
                record_tunnel_error(&shared.api_state, &err).await;
                continue;
            }
        };

        let Some(&peer_addr) = shared.peer_addrs.get(&routed_packet.peer_id) else {
            shared
                .api_state
                .record_error(
                    freeq_api::ErrorKind::Transport,
                    format!(
                        "missing transport address for peer '{}'",
                        routed_packet.peer_id
                    ),
                )
                .await;
            continue;
        };

        let session = match get_or_create_outbound_session(
            &shared.active_sessions,
            shared.endpoint.clone(),
            shared.identity.as_ref(),
            shared.peer_registry.as_ref(),
            &routed_packet.peer_id,
            peer_addr,
        )
        .await
        {
            Ok(session) => session,
            Err(err) => {
                shared
                    .api_state
                    .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                    .await;
                continue;
            }
        };

        let packet_id = session
            .outbound_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let prepared = match shared.tunnel_service.prepare_peer_packet_with_session(
            routed_packet.packet,
            &session.outbound_key,
            packet_id,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                record_tunnel_error(&shared.api_state, &err).await;
                continue;
            }
        };

        let mut send_failed = false;
        for frame in prepared.frames {
            if let Err(err) = session.connection.send(frame).await {
                shared
                    .api_state
                    .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                    .await;
                send_failed = true;
                break;
            }
        }

        if send_failed {
            shared
                .active_sessions
                .lock()
                .await
                .remove(&prepared.peer_id);
        }
    }
}

#[allow(dead_code)]
async fn run_connection_receiver(
    session: Arc<ActivePeerSession>,
    tunnel_service: Arc<freeq_tunnel::TunnelService>,
    packet_egress: PacketEgress,
    api_state: freeq_api::ApiState,
    peer_name: String,
) {
    let mut reassembler = freeq_transport::frame::FrameReassembler::default();

    loop {
        match session.connection.recv().await {
            Ok(frame) => {
                let rebuilt_packet = match reassembler.push_frame(&frame) {
                    Ok(packet) => packet,
                    Err(err) => {
                        api_state
                            .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                            .await;
                        continue;
                    }
                };

                let Some(rebuilt_packet) = rebuilt_packet else {
                    continue;
                };

                let plaintext = match tunnel_service
                    .receive_transport_packet_with_session(rebuilt_packet, &session.inbound_key)
                {
                    Ok(plaintext) => plaintext,
                    Err(err) => {
                        record_tunnel_error(&api_state, &err).await;
                        continue;
                    }
                };

                if packet_egress.send(plaintext).await.is_err() {
                    tracing::warn!(peer = %peer_name, "packet egress receiver dropped");
                    return;
                }
            }
            Err(freeq_transport::TransportError::Timeout) => continue,
            Err(err) => {
                api_state
                    .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                    .await;
                tracing::warn!(peer = %peer_name, error = %err, "transport receive loop stopped");
                return;
            }
        }
    }
}

struct RoutedPacket {
    peer_id: String,
    packet: Bytes,
}

fn route_packet_for_peer(
    tunnel_service: &freeq_tunnel::TunnelService,
    packet: Bytes,
) -> freeq_tunnel::Result<RoutedPacket> {
    let header = freeq_tunnel::packet::parse_ipv4_header(packet.as_ref())?;
    let destination = std::net::IpAddr::V4(header.destination);
    let peer_id = tunnel_service
        .resolve_peer(destination)
        .ok_or(freeq_tunnel::TunnelError::NoRoute { dest: destination })?;
    Ok(RoutedPacket {
        peer_id: peer_id.to_string(),
        packet,
    })
}

async fn get_or_create_outbound_session(
    active_sessions: &Arc<Mutex<HashMap<String, Arc<ActivePeerSession>>>>,
    endpoint: freeq_transport::endpoint::Endpoint,
    identity: &freeq_crypto::sign::IdentityKeypair,
    peer_registry: &freeq_auth::registry::PeerRegistry,
    peer_name: &str,
    peer_addr: SocketAddr,
) -> Result<Arc<ActivePeerSession>> {
    if let Some(session) = active_sessions.lock().await.get(peer_name).cloned() {
        return Ok(session);
    }

    let session = Arc::new(
        establish_outbound_session(endpoint, identity, peer_registry, peer_name, peer_addr).await?,
    );
    active_sessions
        .lock()
        .await
        .insert(peer_name.to_string(), Arc::clone(&session));
    Ok(session)
}

async fn establish_outbound_session(
    endpoint: freeq_transport::endpoint::Endpoint,
    identity: &freeq_crypto::sign::IdentityKeypair,
    peer_registry: &freeq_auth::registry::PeerRegistry,
    peer_name: &str,
    peer_addr: SocketAddr,
) -> Result<ActivePeerSession> {
    let connection = endpoint.connect(peer_addr).await?;
    let peer_entry = peer_registry
        .get_peer(peer_name)
        .ok_or_else(|| anyhow::anyhow!("missing peer registry entry for '{peer_name}'"))?;
    let expected_remote_identity = freeq_crypto::sign::IdentityPublicKey::from_bytes(
        &peer_entry.identity_pubkey,
    )
    .map_err(|err| anyhow::anyhow!("invalid identity public key for '{peer_name}': {err}"))?;
    let (handshake, init_msg) = {
        let mut rng = rand::thread_rng();
        let (_initiator_kem_secret, initiator_kem_public) =
            freeq_crypto::kem::HybridSecretKey::generate(&mut rng)?;
        freeq_auth::handshake::InitiatorHandshake::new(
            identity,
            &initiator_kem_public.to_bytes(),
            expected_remote_identity,
        )?
    };
    send_handshake_message(&connection, HANDSHAKE_INIT_PACKET_ID, init_msg).await?;
    let response = recv_handshake_message(&connection).await?;
    let (handshake, kem_msg) = {
        let mut rng = rand::thread_rng();
        handshake.process_response(response.as_ref(), &mut rng)?
    };
    send_handshake_message(&connection, HANDSHAKE_KEM_PACKET_ID, kem_msg).await?;
    let keys = handshake.finalize()?;
    send_handshake_message(
        &connection,
        HANDSHAKE_CONFIRM_PACKET_ID,
        freeq_auth::handshake::encode_key_confirmation(&keys),
    )
    .await?;
    let responder_confirmation = recv_handshake_message(&connection).await?;
    freeq_auth::handshake::verify_key_confirmation(&keys, responder_confirmation.as_ref())?;

    Ok(ActivePeerSession {
        connection,
        outbound_key: keys.outbound,
        inbound_key: keys.inbound,
        outbound_counter: std::sync::atomic::AtomicU64::new(0),
    })
}

async fn accept_inbound_session(
    connection: freeq_transport::connection::PeerConnection,
    identity: &freeq_crypto::sign::IdentityKeypair,
    peer_registry: &freeq_auth::registry::PeerRegistry,
) -> Result<(String, Arc<ActivePeerSession>)> {
    let init_msg = recv_handshake_message(&connection).await?;
    let responder_kem_secret = {
        let mut rng = rand::thread_rng();
        let (responder_kem_secret, _) = freeq_crypto::kem::HybridSecretKey::generate(&mut rng)?;
        responder_kem_secret
    };
    let (responder_state, response) = freeq_auth::handshake::ResponderHandshake::process_init(
        identity,
        responder_kem_secret,
        peer_registry,
        init_msg.as_ref(),
    )?;
    let peer_name = responder_state.peer_name().to_string();
    send_handshake_message(&connection, HANDSHAKE_RESPONSE_PACKET_ID, response).await?;
    let kem_msg = recv_handshake_message(&connection).await?;
    let keys = responder_state.process_kem(kem_msg.as_ref())?;
    let initiator_confirmation = recv_handshake_message(&connection).await?;
    freeq_auth::handshake::verify_key_confirmation(&keys, initiator_confirmation.as_ref())?;
    send_handshake_message(
        &connection,
        HANDSHAKE_CONFIRM_PACKET_ID,
        freeq_auth::handshake::encode_key_confirmation(&keys),
    )
    .await?;

    Ok((
        peer_name,
        Arc::new(ActivePeerSession {
            connection,
            outbound_key: keys.outbound,
            inbound_key: keys.inbound,
            outbound_counter: std::sync::atomic::AtomicU64::new(0),
        }),
    ))
}

async fn send_handshake_message(
    connection: &freeq_transport::connection::PeerConnection,
    packet_id: u64,
    message: Vec<u8>,
) -> Result<()> {
    let frames = freeq_transport::frame::chunk_packet_with_id(
        packet_id,
        &message,
        freeq_transport::frame::SECURE_QUIC_MTU,
    )?;
    for frame in frames {
        connection.send(frame).await?;
    }
    Ok(())
}

async fn recv_handshake_message(
    connection: &freeq_transport::connection::PeerConnection,
) -> Result<Bytes> {
    let mut reassembler = freeq_transport::frame::FrameReassembler::default();
    loop {
        let frame = connection.recv().await?;
        if let Some(message) = reassembler.push_frame(frame.as_ref())? {
            return Ok(message);
        }
    }
}

#[allow(dead_code)]
async fn record_tunnel_error(api_state: &freeq_api::ApiState, err: &freeq_tunnel::TunnelError) {
    let kind = match err {
        freeq_tunnel::TunnelError::BufferUnderflow
        | freeq_tunnel::TunnelError::MalformedPacket(_) => freeq_api::ErrorKind::MalformedPacket,
        freeq_tunnel::TunnelError::Crypto(_) => freeq_api::ErrorKind::Crypto,
        freeq_tunnel::TunnelError::Transport(_) => freeq_api::ErrorKind::Transport,
        freeq_tunnel::TunnelError::Interface(_)
        | freeq_tunnel::TunnelError::Io(_)
        | freeq_tunnel::TunnelError::NoRoute { .. } => freeq_api::ErrorKind::Transport,
    };
    api_state.record_error(kind, err.to_string()).await;
}

async fn refresh_api_state(
    api_state: &freeq_api::ApiState,
    tunnel_service: &freeq_tunnel::TunnelService,
) {
    let stats = tunnel_service.stats();
    api_state
        .update_runtime_counters(
            freeq_api::TunnelRuntimeSnapshot {
                interface_name: Some(tunnel_service.interface_config().interface_name.clone()),
                interface_mtu: Some(tunnel_service.interface_config().mtu),
                packets_ingested: stats.packets_ingested,
                encrypted_bytes: stats.bytes_encrypted,
                transport_frames: stats.frames_emitted,
                route_misses: stats.route_misses,
            },
            freeq_api::state::ErrorCounters {
                malformed_packet_errors: stats.malformed_packet_errors,
                crypto_errors: stats.crypto_errors,
                transport_errors: stats.transport_errors,
            },
        )
        .await;
}

async fn serve_status_only_api(api_server: freeq_api::ApiServer) -> Result<()> {
    tokio::select! {
        result = api_server.serve() => result.map_err(anyhow::Error::from),
        signal = tokio::signal::ctrl_c() => {
            signal?;
            tracing::info!("shutdown signal received; stopping status-only API mode");
            Ok(())
        }
    }
}

fn init_tunnel_service(config: &freeq_config::Config) -> Result<freeq_tunnel::TunnelService> {
    init_tunnel_service_with_keys(
        config,
        freeq_crypto::FreeQKeyPair::generate_ephemeral_test_pair()?,
    )
}

fn init_tunnel_service_with_keys(
    config: &freeq_config::Config,
    keys: freeq_crypto::FreeQKeyPair,
) -> Result<freeq_tunnel::TunnelService> {
    let mtu = 1200;
    let tunnel = freeq_tunnel::TunnelInterface::new(
        freeq_tunnel::TunnelConfig {
            interface_name: config.node.name.clone(),
            mtu,
        },
        keys,
    )?;

    let mut router = freeq_tunnel::router::Router::new();
    for peer in &config.peer {
        for prefix in &peer.allowed_ips {
            router.insert(prefix.parse()?, peer.name.clone());
        }
    }

    Ok(freeq_tunnel::TunnelService::new(tunnel, router))
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

#[cfg(test)]
mod tests {
    use super::{
        build_api_server, build_peer_registry, collect_startup_blockers, init_api_state,
        init_identity, init_tunnel_service, init_tunnel_service_with_keys, is_silent_inbound_probe,
        parse_listen_addr, parse_peer_socket_addrs, refresh_api_state, spawn_dataplane_runtime,
        spawn_packet_io_runtime, DataplaneShared, PacketIo, DATAPLANE_CHANNEL_CAPACITY,
    };
    use base64::Engine as _;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{mpsc, Mutex};

    fn sample_config() -> freeq_config::Config {
        let peer_identity = generate_identity_bytes();
        toml::from_str(&format!(
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
            endpoint = "lon-01.example.com:51820"
            public_key = "{public_key}"
            kem_key = "{kem_key}"
            allowed_ips = ["10.0.0.2/32"]
            key_rotation_secs = 3600
            "#,
            public_key = peer_identity.public_key_b64,
            kem_key = peer_identity.kem_key_b64,
        ))
        .expect("sample config should deserialize")
    }

    #[test]
    fn startup_blockers_cover_stubbed_subsystems() {
        let blockers = collect_startup_blockers();

        assert!(blockers.is_empty());
    }

    #[test]
    fn silent_inbound_probe_classifier_covers_cloaked_and_probe_timeouts() {
        assert!(is_silent_inbound_probe(
            &freeq_auth::AuthError::Cloaked.into()
        ));
        assert!(is_silent_inbound_probe(
            &freeq_transport::TransportError::Timeout.into()
        ));
        assert!(is_silent_inbound_probe(
            &freeq_transport::TransportError::ConnectionLost("probe closed".into()).into()
        ));
        assert!(!is_silent_inbound_probe(
            &freeq_auth::AuthError::HandshakeFailed {
                step: 8,
                reason: "confirmation failed".into(),
            }
            .into()
        ));
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

    #[tokio::test]
    async fn init_tunnel_service_routes_configured_peer_prefixes() {
        let service = init_tunnel_service(&sample_config()).expect("tunnel service");
        let packet = Bytes::from(test_ipv4_packet(1180, [10, 0, 0, 2]));

        let report = service.ingest_packet(packet).await.expect("ingest packet");

        assert_eq!(report.peer_id, "lon-01");
        assert_eq!(service.stats().packets_ingested, 1);
    }

    #[tokio::test]
    async fn init_api_state_captures_service_snapshot() {
        let config = sample_config();
        let service = init_tunnel_service(&config).expect("tunnel service");
        let state = init_api_state(&config, &service).await;
        let snapshot = state.snapshot().await;

        assert_eq!(snapshot.name, "nyc-01");
        assert_eq!(snapshot.peer_count, 1);
        assert_eq!(snapshot.tunnel.interface_mtu, Some(1200));
    }

    #[tokio::test]
    async fn refresh_api_state_captures_live_service_counters() {
        let config = sample_config();
        let service = init_tunnel_service(&config).expect("tunnel service");
        let state = init_api_state(&config, &service).await;
        let packet = Bytes::from(test_ipv4_packet(1180, [10, 0, 0, 2]));
        service.ingest_packet(packet).await.expect("ingest packet");

        refresh_api_state(&state, &service).await;
        let snapshot = state.snapshot().await;

        assert_eq!(snapshot.tunnel.packets_ingested, 1);
        assert!(snapshot.tunnel.transport_frames >= 2);
        assert_eq!(snapshot.errors.malformed_packet_errors, 0);
    }

    #[test]
    fn build_api_server_accepts_configured_listen_addr() {
        let config = sample_config();
        let state = freeq_api::ApiState::new(
            "nyc-01".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            1,
        );

        build_api_server(&config, state).expect("api server");
    }

    #[test]
    fn parse_peer_socket_addrs_rejects_hostnames_until_resolution_exists() {
        let err = parse_peer_socket_addrs(&sample_config()).expect_err("hostname should fail");

        assert!(err.to_string().contains("concrete socket address"));
    }

    #[test]
    fn parse_listen_addr_accepts_socket_addr() {
        let config = sample_config();
        let addr = parse_listen_addr(&config).expect("listen addr");

        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 51820)
        );
    }

    #[test]
    fn build_peer_registry_loads_peer_identities_from_config() {
        let config = sample_config();

        let registry = build_peer_registry(&config).expect("peer registry");
        let peer = registry.get_peer("lon-01").expect("peer lookup");

        assert_eq!(peer.name, "lon-01");
        assert_eq!(peer.allowed_ips.len(), 1);
    }

    #[tokio::test]
    async fn packet_io_runtime_bridges_in_memory_device() {
        let state = freeq_api::ApiState::new(
            "bridge-test".into(),
            "0.1.0".into(),
            "ml-kem-768".into(),
            "ml-dsa-65".into(),
            "aes-256-gcm".into(),
            0,
        );
        let (device_in_tx, device_in_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (device_out_tx, mut device_out_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (to_transport_tx, mut to_transport_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (from_transport_tx, from_transport_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);

        let _runtime = spawn_packet_io_runtime(
            PacketIo::InMemory {
                ingress: Arc::new(Mutex::new(device_in_rx)),
                egress: device_out_tx,
            },
            to_transport_tx,
            from_transport_rx,
            state.clone(),
        );

        let inbound = Bytes::from_static(b"inbound-packet");
        device_in_tx
            .send(inbound.clone())
            .await
            .expect("device ingress");
        let bridged_inbound = tokio::time::timeout(Duration::from_secs(1), to_transport_rx.recv())
            .await
            .expect("ingress timeout")
            .expect("ingress packet");
        assert_eq!(bridged_inbound, inbound);

        let outbound = Bytes::from_static(b"outbound-packet");
        from_transport_tx
            .send(outbound.clone())
            .await
            .expect("transport egress");
        let bridged_outbound = tokio::time::timeout(Duration::from_secs(1), device_out_rx.recv())
            .await
            .expect("egress timeout")
            .expect("egress packet");
        assert_eq!(bridged_outbound, outbound);
        assert!(state.snapshot().await.last_error.is_none());
    }

    #[tokio::test]
    async fn dataplane_runtime_forwards_packet_over_real_quic_transport() {
        let server_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr().expect("server addr");
        let client_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind client endpoint");

        let sender_identity = generate_identity_bytes();
        let receiver_identity = generate_identity_bytes();
        let sender_config = config_with_socket_peer(
            server_addr,
            "sender",
            "receiver",
            &receiver_identity.public_key_b64,
            &receiver_identity.kem_key_b64,
        );
        let receiver_config = config_with_socket_peer(
            client_endpoint.local_addr().expect("client addr"),
            "receiver",
            "sender",
            &sender_identity.public_key_b64,
            &sender_identity.kem_key_b64,
        );

        let shared_keys =
            freeq_crypto::FreeQKeyPair::generate_ephemeral_test_pair().expect("shared tunnel keys");
        let sender_service = Arc::new(
            init_tunnel_service_with_keys(&sender_config, shared_keys.clone())
                .expect("sender tunnel"),
        );
        let receiver_service = Arc::new(
            init_tunnel_service_with_keys(&receiver_config, shared_keys).expect("receiver tunnel"),
        );
        let sender_state = init_api_state(&sender_config, sender_service.as_ref()).await;
        let receiver_state = init_api_state(&receiver_config, receiver_service.as_ref()).await;

        let (sender_tun_tx, sender_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (_sender_out_tx, _sender_out_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (_receiver_in_tx, receiver_in_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (receiver_tun_tx, mut receiver_tun_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);

        let _sender_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: client_endpoint.clone(),
                tunnel_service: Arc::clone(&sender_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&sender_config).expect("sender peers"),
                ),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                identity: Arc::new(sender_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&sender_config).expect("sender registry"),
                ),
                api_state: sender_state.clone(),
            },
            sender_tun_rx,
            _sender_out_tx.clone(),
        );
        let _receiver_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: server_endpoint.clone(),
                tunnel_service: Arc::clone(&receiver_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&receiver_config).expect("receiver peers"),
                ),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                identity: Arc::new(receiver_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&receiver_config).expect("receiver registry"),
                ),
                api_state: receiver_state.clone(),
            },
            receiver_in_rx,
            receiver_tun_tx,
        );

        let packet = Bytes::from(test_ipv4_packet(1180, [10, 0, 0, 2]));
        sender_tun_tx
            .send(packet.clone())
            .await
            .expect("send into virtual tun");

        let received = match tokio::time::timeout(Duration::from_secs(5), receiver_tun_rx.recv())
            .await
        {
            Ok(Some(packet)) => packet,
            Ok(None) => panic!("receiver packet channel closed"),
            Err(_) => {
                refresh_api_state(&sender_state, sender_service.as_ref()).await;
                refresh_api_state(&receiver_state, receiver_service.as_ref()).await;
                let sender_snapshot = sender_state.snapshot().await;
                let receiver_snapshot = receiver_state.snapshot().await;
                panic!(
                    "receive timeout: sender packets={}, frames={}, last_error={:?}; receiver packets={}, frames={}, last_error={:?}",
                    sender_snapshot.tunnel.packets_ingested,
                    sender_snapshot.tunnel.transport_frames,
                    sender_snapshot.last_error,
                    receiver_snapshot.tunnel.packets_ingested,
                    receiver_snapshot.tunnel.transport_frames,
                    receiver_snapshot.last_error,
                );
            }
        };

        assert_eq!(received, packet);

        refresh_api_state(&sender_state, sender_service.as_ref()).await;
        let sender_snapshot = sender_state.snapshot().await;
        assert_eq!(sender_snapshot.tunnel.packets_ingested, 1);
        assert!(sender_snapshot.tunnel.transport_frames >= 1);

        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    fn test_ipv4_packet(len: usize, destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn config_with_socket_peer(
        peer_addr: SocketAddr,
        node_name: &str,
        peer_name: &str,
        peer_public_key_b64: &str,
        peer_kem_key_b64: &str,
    ) -> freeq_config::Config {
        toml::from_str(&format!(
            r#"
            [node]
            name = "{node_name}"
            listen = "127.0.0.1:0"
            address = "10.0.0.1/24"
            key_path = "/tmp/{node_name}.key"
            algorithm = "ml-kem-768"
            sign = "ml-dsa-65"
            api_enabled = false
            api_addr = "127.0.0.1:6789"

            [[peer]]
            name = "{peer_name}"
            endpoint = "{peer_addr}"
            public_key = "{peer_public_key_b64}"
            kem_key = "{peer_kem_key_b64}"
            allowed_ips = ["10.0.0.2/32"]
            key_rotation_secs = 3600
            "#
        ))
        .expect("socket config should deserialize")
    }

    struct GeneratedIdentity {
        keypair: freeq_crypto::sign::IdentityKeypair,
        public_key_b64: String,
        kem_key_b64: String,
    }

    fn generate_identity_bytes() -> GeneratedIdentity {
        let mut rng = rand::thread_rng();
        let (keypair, public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("identity generation");
        let (_kem_secret, kem_public) =
            freeq_crypto::kem::HybridSecretKey::generate(&mut rng).expect("kem generation");

        GeneratedIdentity {
            keypair,
            public_key_b64: base64::engine::general_purpose::STANDARD.encode(public_key.to_bytes()),
            kem_key_b64: base64::engine::general_purpose::STANDARD.encode(kem_public.to_bytes()),
        }
    }
}
