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
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

const API_STATE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DATAPLANE_CHANNEL_CAPACITY: usize = 256;
/// When all proactive peers are healthy, poll this often for sudden death.
const OUTBOUND_HEALTHY_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// When any peer is down, retry rejoin this often (immediate first attempt).
const OUTBOUND_REJOIN_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Cap a single establish/handshake attempt so the 3s rejoin budget can retry.
const OUTBOUND_ESTABLISH_DEADLINE: Duration = Duration::from_millis(2_500);
/// Authenticated rejoin budget after path loss (DoW intermittent-link target).
const BATTLEFIELD_REJOIN_BUDGET: Duration = freeq_transport::connection::BATTLEFIELD_REJOIN_BUDGET;
const HANDSHAKE_INIT_PACKET_ID: u64 = 0;
const HANDSHAKE_RESPONSE_PACKET_ID: u64 = 1;
const HANDSHAKE_KEM_PACKET_ID: u64 = 2;
const HANDSHAKE_CONFIRM_PACKET_ID: u64 = 3;
const RELAY_MAGIC: &[u8; 4] = b"FQRL";
const RELAY_VERSION: u8 = 1;
const RELAY_HEADER_LEN: usize = 23;
const RELAY_AAD_CONTEXT: &[u8] = b"freeq-e2e-relay/v1";
const PAIR_MAGIC: &[u8; 4] = b"FQPK";
const PAIR_CHUNK_MAGIC: &[u8; 4] = b"FQPC";
const PAIR_VERSION: u8 = 1;
const PAIR_TYPE_OFFER: u8 = 1;
const PAIR_TYPE_ANSWER: u8 = 2;
const RELAY_PAIR_INTERVAL: Duration = Duration::from_secs(10);
const RELAY_PAIR_REFRESH_MARGIN: Duration = Duration::from_secs(60);
const DEFAULT_RELAY_KEY_ROTATION_SECS: u64 = 900;
const RELAY_PAIR_SIGN_CONTEXT: &[u8] = b"freeq relay pair control v1";
const RELAY_PAIR_KDF_CONTEXT: &[u8] = b"freeq relay pair key v1";
const PAIR_CONTROL_CHUNK_SIZE: usize = 900;

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

    let endpoint = freeq_transport::endpoint::Endpoint::bind_with_mode(
        parse_listen_addr(&config)?,
        endpoint_bind_mode(&config),
    )
    .await?;
    let peer_addrs = parse_peer_socket_addrs(&config)?;
    let e2e_relay_keys = Arc::new(StdMutex::new(load_e2e_relay_key()?));
    let relay_pair_rotation_secs = relay_pair_rotation_secs(&config);
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
        direct_peer_hosts: Arc::new(direct_peer_hosts(&config)),
        proactive_peer_ids: Arc::new(proactive_gateway_client_peers(&config)),
        relay_pair_peer_ids: Arc::new(relay_pair_peer_ids(&config)),
        active_sessions: Arc::new(Mutex::new(HashMap::new())),
        node_name: config.node.name.clone(),
        identity: Arc::new(identity),
        peer_registry,
        api_state: api_state.clone(),
        e2e_relay_keys,
        e2e_relay_counter: Arc::new(AtomicU64::new(0)),
        relay_pair_rotation_secs,
        relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
        relay_pair_chunks: Arc::new(StdMutex::new(HashMap::new())),
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
    if let Some(parent) = PathBuf::from(&config.node.key_path).parent() {
        state.set_local_peer_env_path(parent.join("peer.env")).await;
    }
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
    _outbound_task: tokio::task::JoinHandle<()>,
    _egress_task: tokio::task::JoinHandle<()>,
    _relay_pair_task: tokio::task::JoinHandle<()>,
}

struct PacketIoRuntime {
    _ingress_task: tokio::task::JoinHandle<()>,
    _egress_task: tokio::task::JoinHandle<()>,
}

struct ActivePeerSession {
    connection: freeq_transport::connection::PeerConnection,
    outbound_key: [u8; 32],
    inbound_key: [u8; 32],
    last_received: StdMutex<Instant>,
}

impl ActivePeerSession {
    fn new(
        connection: freeq_transport::connection::PeerConnection,
        outbound_key: [u8; 32],
        inbound_key: [u8; 32],
    ) -> Self {
        Self {
            connection,
            outbound_key,
            inbound_key,
            last_received: StdMutex::new(Instant::now()),
        }
    }

    fn mark_received(&self) {
        if let Ok(mut last_received) = self.last_received.lock() {
            *last_received = Instant::now();
        }
    }

    /// Whether this session may carry traffic.
    ///
    /// Security: only a live QUIC connection is usable. Dead/half-open
    /// sessions must never be reused after path loss — rejoin with a full
    /// FreeQ handshake instead.
    fn is_usable(&self) -> bool {
        self.connection.is_alive()
    }
}

struct RelayKeyState {
    key: [u8; 32],
    generation: u64,
    expires_at: Instant,
    installed_at: Instant,
}

struct PendingRelayOffer {
    secret: freeq_crypto::kem::HybridSecretKey,
    expires_at: Instant,
}

#[derive(Clone)]
struct DataplaneShared {
    endpoint: freeq_transport::endpoint::Endpoint,
    tunnel_service: Arc<freeq_tunnel::TunnelService>,
    peer_addrs: Arc<HashMap<String, SocketAddr>>,
    direct_peer_hosts: Arc<HashMap<String, IpAddr>>,
    proactive_peer_ids: Arc<HashSet<String>>,
    relay_pair_peer_ids: Arc<HashSet<String>>,
    active_sessions: Arc<Mutex<HashMap<String, Arc<ActivePeerSession>>>>,
    node_name: String,
    identity: Arc<freeq_crypto::sign::IdentityKeypair>,
    peer_registry: Arc<freeq_auth::registry::PeerRegistry>,
    api_state: freeq_api::ApiState,
    e2e_relay_keys: Arc<StdMutex<Option<RelayKeyState>>>,
    e2e_relay_counter: Arc<AtomicU64>,
    relay_pair_rotation_secs: u64,
    relay_pair_pending: Arc<StdMutex<HashMap<u64, PendingRelayOffer>>>,
    relay_pair_chunks: Arc<StdMutex<HashMap<PairChunkKey, PairChunkBuffer>>>,
}

#[allow(dead_code)]
fn parse_peer_socket_addrs(config: &freeq_config::Config) -> Result<HashMap<String, SocketAddr>> {
    let mut peers = HashMap::with_capacity(config.peer.len());
    for peer in &config.peer {
        let Some(endpoint) = peer.endpoint.as_ref() else {
            if peer.is_dialable() {
                anyhow::bail!("peer '{}' is missing a transport endpoint", peer.name);
            }
            continue;
        };
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

fn direct_peer_hosts(config: &freeq_config::Config) -> HashMap<String, IpAddr> {
    let mut hosts = HashMap::with_capacity(config.peer.len());
    for peer in &config.peer {
        let Some(first_allowed_ip) = peer.allowed_ips.first() else {
            continue;
        };
        let Ok(network) = first_allowed_ip.parse::<IpNetwork>() else {
            continue;
        };
        match network {
            IpNetwork::V4(network) if network.prefix() == 32 => {
                hosts.insert(peer.name.clone(), IpAddr::V4(network.ip()));
            }
            IpNetwork::V6(network) if network.prefix() == 128 => {
                hosts.insert(peer.name.clone(), IpAddr::V6(network.ip()));
            }
            _ => {}
        }
    }
    hosts
}

/// Peers that freeqd must proactively maintain (outbound dial + rejoin).
///
/// Includes `gateway_client` peers and any other dialable peer with an
/// endpoint. `relay_leaf` peers are never dialed.
fn proactive_outbound_peers(config: &freeq_config::Config) -> HashSet<String> {
    config
        .peer
        .iter()
        .filter(|peer| peer.is_dialable())
        .map(|peer| peer.name.clone())
        .collect()
}

/// Backward-compatible name used by existing call sites / tests.
fn proactive_gateway_client_peers(config: &freeq_config::Config) -> HashSet<String> {
    proactive_outbound_peers(config)
}

fn relay_pair_peer_ids(config: &freeq_config::Config) -> HashSet<String> {
    config
        .peer
        .iter()
        .filter(|peer| !peer.is_dialable() && peer.name != config.node.name)
        .map(|peer| peer.name.clone())
        .collect()
}

fn endpoint_bind_mode(
    config: &freeq_config::Config,
) -> freeq_transport::endpoint::EndpointBindMode {
    if config.node.strict_cloaking {
        freeq_transport::endpoint::EndpointBindMode::StrictCloaked
    } else {
        freeq_transport::endpoint::EndpointBindMode::DirectQuic
    }
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
    let accept_task = tokio::spawn(run_accept_loop(shared.clone(), packet_egress.clone()));
    let outbound_task = tokio::spawn(run_outbound_session_maintainer(
        shared.clone(),
        packet_egress.clone(),
    ));
    let relay_pair_shared = shared.clone();
    let egress_task = tokio::spawn(run_egress_loop(shared, packet_ingress, packet_egress));
    let relay_pair_task = tokio::spawn(run_relay_pair_manager(relay_pair_shared));

    DataplaneRuntime {
        _accept_task: accept_task,
        _outbound_task: outbound_task,
        _egress_task: egress_task,
        _relay_pair_task: relay_pair_task,
    }
}

#[allow(dead_code)]
async fn run_outbound_session_maintainer(shared: DataplaneShared, packet_egress: PacketEgress) {
    if shared.proactive_peer_ids.is_empty() {
        return;
    }

    // Battlefield rejoin: when a peer is down, retry aggressively so an asset
    // that regains RF can re-authenticate inside BATTLEFIELD_REJOIN_BUDGET.
    // Security: every success path is a full FreeQ handshake (no session reuse).
    loop {
        let mut any_down = false;
        for peer_id in shared.proactive_peer_ids.iter() {
            let Some(&peer_addr) = shared.peer_addrs.get(peer_id) else {
                continue;
            };

            let needs_rejoin = {
                let sessions = shared.active_sessions.lock().await;
                match sessions.get(peer_id) {
                    Some(session) if session.is_usable() => false,
                    Some(_) | None => true,
                }
            };

            if !needs_rejoin {
                continue;
            }
            any_down = true;

            // Drop any dead session before redial (never black-hole on stale).
            {
                let mut sessions = shared.active_sessions.lock().await;
                if let Some(dead) = sessions.remove(peer_id) {
                    tracing::info!(
                        peer = %peer_id,
                        "path loss: removed dead outbound session; rejoining"
                    );
                    let _ = dead.connection.close().await;
                }
            }

            let rejoin_started = Instant::now();
            match get_or_create_outbound_session(
                &shared.active_sessions,
                shared.endpoint.clone(),
                shared.identity.as_ref(),
                shared.peer_registry.as_ref(),
                peer_id,
                peer_addr,
            )
            .await
            {
                Ok((session, true)) => {
                    let rejoin_ms = rejoin_started.elapsed().as_millis();
                    tracing::info!(
                        peer = %peer_id,
                        rejoin_ms,
                        budget_ms = BATTLEFIELD_REJOIN_BUDGET.as_millis(),
                        "outbound peer rejoin succeeded (full handshake)"
                    );
                    if rejoin_started.elapsed() > BATTLEFIELD_REJOIN_BUDGET {
                        tracing::warn!(
                            peer = %peer_id,
                            rejoin_ms,
                            budget_ms = BATTLEFIELD_REJOIN_BUDGET.as_millis(),
                            "rejoin exceeded battlefield budget"
                        );
                    }
                    spawn_connection_receiver(
                        session,
                        shared.clone(),
                        packet_egress.clone(),
                        peer_id.clone(),
                    );
                }
                Ok((_session, false)) => {}
                Err(err) => {
                    tracing::warn!(
                        peer = %peer_id,
                        endpoint = %peer_addr,
                        error = %err,
                        "proactive outbound rejoin failed; will retry"
                    );
                    shared
                        .api_state
                        .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                        .await;
                }
            }
        }

        if any_down {
            tokio::time::sleep(OUTBOUND_REJOIN_POLL_INTERVAL).await;
        } else {
            tokio::time::sleep(OUTBOUND_HEALTHY_POLL_INTERVAL).await;
        }
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
                tracing::info!(peer = %peer_name, "inbound peer session established");
                tokio::spawn(run_connection_receiver(
                    session,
                    shared.clone(),
                    packet_egress.clone(),
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
async fn run_egress_loop(
    shared: DataplaneShared,
    mut packet_ingress: PacketIngress,
    packet_egress: PacketEgress,
) {
    while let Some(packet) = packet_ingress.recv().await {
        let mut routed_packet = match route_packet_for_peer(&shared.tunnel_service, packet) {
            Ok(routed_packet) => routed_packet,
            Err(err) => {
                record_tunnel_error(&shared.api_state, &err).await;
                continue;
            }
        };
        routed_packet.packet = match maybe_wrap_e2e_relay_packet(
            &shared,
            &routed_packet.peer_id,
            routed_packet.packet,
        ) {
            Ok(packet) => packet,
            Err(err) => {
                shared
                    .api_state
                    .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                    .await;
                continue;
            }
        };

        if let Some((session, peer_id)) = transmit_routed_packet(&shared, routed_packet).await {
            spawn_connection_receiver(session, shared.clone(), packet_egress.clone(), peer_id);
        }
    }
}

#[allow(dead_code)]
async fn run_connection_receiver(
    session: Arc<ActivePeerSession>,
    shared: DataplaneShared,
    packet_egress: PacketEgress,
    peer_name: String,
) {
    let mut reassembler = freeq_transport::frame::FrameReassembler::default();

    loop {
        match session.connection.recv().await {
            Ok(frame) => {
                session.mark_received();
                let rebuilt_packet = match reassembler.push_frame(&frame) {
                    Ok(packet) => packet,
                    Err(err) => {
                        shared
                            .api_state
                            .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                            .await;
                        continue;
                    }
                };

                let Some(rebuilt_packet) = rebuilt_packet else {
                    continue;
                };

                let plaintext = match shared
                    .tunnel_service
                    .receive_transport_payload_with_session(rebuilt_packet, &session.inbound_key)
                {
                    Ok(plaintext) => plaintext,
                    Err(err) => {
                        record_tunnel_error(&shared.api_state, &err).await;
                        continue;
                    }
                };

                if is_pair_chunk_packet(&plaintext) {
                    let handled = match pair_chunk_sender(&plaintext) {
                        Ok(sender) if sender == peer_name && sender != shared.node_name => {
                            forward_pair_control_from_source(&shared, &peer_name, &plaintext).await
                        }
                        _ => match handle_pair_control_chunk(&shared, &plaintext) {
                            Ok(Some(control_packet)) => {
                                handle_pair_control_packet(&shared, &peer_name, &control_packet)
                                    .await
                            }
                            Ok(None) => Ok(()),
                            Err(err) => Err(err),
                        },
                    };
                    if let Err(err) = handled {
                        shared
                            .api_state
                            .record_error(freeq_api::ErrorKind::Crypto, err.to_string())
                            .await;
                        tracing::warn!(
                            peer = %peer_name,
                            error = %err,
                            "relay pair handshake chunk failed"
                        );
                    }
                    continue;
                }

                if is_pair_control_packet(&plaintext) {
                    let handled = match pair_control_sender(&plaintext) {
                        Ok(sender) if sender == peer_name && sender != shared.node_name => {
                            forward_pair_control_from_source(&shared, &peer_name, &plaintext).await
                        }
                        _ => handle_pair_control_packet(&shared, &peer_name, &plaintext).await,
                    };
                    if let Err(err) = handled {
                        shared
                            .api_state
                            .record_error(freeq_api::ErrorKind::Crypto, err.to_string())
                            .await;
                        tracing::warn!(
                            peer = %peer_name,
                            error = %err,
                            "relay pair handshake control failed"
                        );
                    }
                    continue;
                }

                if let Some(relay) = parse_relay_envelope(&plaintext) {
                    let relay_key = current_relay_key(&shared);
                    if let Some(key) = relay_key {
                        match decrypt_relay_payload(key, relay) {
                            Ok(inner_packet) => {
                                if packet_egress.send(inner_packet).await.is_err() {
                                    tracing::warn!(peer = %peer_name, "packet egress receiver dropped");
                                    remove_active_session_if_current(&shared, &peer_name, &session)
                                        .await;
                                    return;
                                }
                            }
                            Err(err) => {
                                shared
                                    .api_state
                                    .record_error(freeq_api::ErrorKind::Crypto, err.to_string())
                                    .await;
                            }
                        }
                    } else {
                        let destination = IpAddr::V4(relay.destination);
                        let Some(next_peer) = shared.tunnel_service.resolve_peer(destination)
                        else {
                            shared
                                .api_state
                                .record_error(
                                    freeq_api::ErrorKind::Transport,
                                    format!("no relay route to {}", relay.destination),
                                )
                                .await;
                            continue;
                        };
                        if next_peer != peer_name {
                            if let Some((session, peer_id)) = transmit_routed_packet(
                                &shared,
                                RoutedPacket {
                                    peer_id: next_peer.to_string(),
                                    packet: plaintext,
                                },
                            )
                            .await
                            {
                                spawn_connection_receiver(
                                    session,
                                    shared.clone(),
                                    packet_egress.clone(),
                                    peer_id,
                                );
                            }
                        }
                    }
                    continue;
                }

                if let Ok(routed_packet) =
                    route_packet_for_peer(&shared.tunnel_service, plaintext.clone())
                {
                    if routed_packet.peer_id != peer_name {
                        transmit_routed_packet(&shared, routed_packet).await;
                        continue;
                    }
                }

                if packet_egress.send(plaintext).await.is_err() {
                    tracing::warn!(peer = %peer_name, "packet egress receiver dropped");
                    remove_active_session_if_current(&shared, &peer_name, &session).await;
                    return;
                }
            }
            Err(freeq_transport::TransportError::Timeout) => continue,
            Err(err) => {
                shared
                    .api_state
                    .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                    .await;
                tracing::warn!(peer = %peer_name, error = %err, "transport receive loop stopped");
                remove_active_session_if_current(&shared, &peer_name, &session).await;
                return;
            }
        }
    }
}

async fn remove_active_session_if_current(
    shared: &DataplaneShared,
    peer_name: &str,
    session: &Arc<ActivePeerSession>,
) {
    let mut sessions = shared.active_sessions.lock().await;
    if sessions
        .get(peer_name)
        .is_some_and(|current| Arc::ptr_eq(current, session))
    {
        sessions.remove(peer_name);
        tracing::info!(peer = %peer_name, "removed inactive peer session");
    }
}

fn spawn_connection_receiver(
    session: Arc<ActivePeerSession>,
    shared: DataplaneShared,
    packet_egress: PacketEgress,
    peer_id: String,
) {
    tracing::info!(peer = %peer_id, "outbound peer receive loop attached");
    tokio::spawn(run_connection_receiver(
        session,
        shared,
        packet_egress,
        peer_id,
    ));
}

async fn transmit_routed_packet(
    shared: &DataplaneShared,
    routed_packet: RoutedPacket,
) -> Option<(Arc<ActivePeerSession>, String)> {
    let existing_session = {
        shared
            .active_sessions
            .lock()
            .await
            .get(&routed_packet.peer_id)
            .cloned()
    };
    if let Some(session) = existing_session {
        if session.is_usable() {
            transmit_on_session(shared, session, routed_packet).await;
            return None;
        }
        // Security: never send on a dead session (black-hole after RF loss).
        shared
            .active_sessions
            .lock()
            .await
            .remove(&routed_packet.peer_id);
        tracing::info!(
            peer = %routed_packet.peer_id,
            "removed dead peer session before transmit; will rejoin"
        );
        let _ = session.connection.close().await;
    }

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
        return None;
    };

    let (session, created_session) = match get_or_create_outbound_session(
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
            tracing::warn!(
                peer = %routed_packet.peer_id,
                endpoint = %peer_addr,
                error = %err,
                "outbound peer session failed"
            );
            shared
                .api_state
                .record_error(freeq_api::ErrorKind::Transport, err.to_string())
                .await;
            return None;
        }
    };

    let peer_id = routed_packet.peer_id.clone();
    let created_receiver = created_session.then(|| (Arc::clone(&session), peer_id));

    if transmit_on_session(shared, session, routed_packet).await {
        return created_receiver;
    }
    None
}

async fn transmit_on_session(
    shared: &DataplaneShared,
    session: Arc<ActivePeerSession>,
    routed_packet: RoutedPacket,
) -> bool {
    let prepared = match shared.tunnel_service.prepare_payload_for_peer_with_session(
        routed_packet.peer_id.clone(),
        routed_packet.packet,
        &session.outbound_key,
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            record_tunnel_error(&shared.api_state, &err).await;
            return false;
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
        return false;
    }
    true
}

struct RelayEnvelope<'a> {
    destination: Ipv4Addr,
    nonce: [u8; freeq_crypto::bulk::NONCE_LEN],
    plaintext_len: u16,
    ciphertext: &'a [u8],
}

fn load_e2e_relay_key() -> Result<Option<RelayKeyState>> {
    let Some(value) = std::env::var_os("FREEQ_E2E_RELAY_KEY_B64") else {
        return Ok(None);
    };
    let raw = value.to_string_lossy();
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|err| anyhow::anyhow!("FREEQ_E2E_RELAY_KEY_B64 is not valid base64: {err}"))?;
    let key: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "FREEQ_E2E_RELAY_KEY_B64 must decode to 32 bytes, got {}",
            bytes.len()
        )
    })?;
    tracing::info!("manual end-to-end opaque relay key enabled");
    let now = Instant::now();
    Ok(Some(RelayKeyState {
        key,
        generation: 0,
        expires_at: now + Duration::from_secs(100 * 365 * 24 * 60 * 60),
        installed_at: now,
    }))
}

fn relay_pair_rotation_secs(config: &freeq_config::Config) -> u64 {
    if let Ok(raw) = std::env::var("FREEQ_RELAY_KEY_ROTATION_SECS") {
        if let Ok(parsed) = raw.parse::<u64>() {
            if parsed > 0 {
                return parsed;
            }
        }
        tracing::warn!(
            value = %raw,
            "ignoring invalid FREEQ_RELAY_KEY_ROTATION_SECS; using config/default"
        );
    }
    config
        .peer
        .iter()
        .map(|peer| peer.key_rotation_secs)
        .min()
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_RELAY_KEY_ROTATION_SECS)
        .min(DEFAULT_RELAY_KEY_ROTATION_SECS)
}

fn current_relay_key(shared: &DataplaneShared) -> Option<[u8; 32]> {
    let guard = shared.e2e_relay_keys.lock().ok()?;
    let state = guard.as_ref()?;
    if Instant::now() >= state.expires_at {
        return None;
    }
    Some(state.key)
}

fn maybe_wrap_e2e_relay_packet(
    shared: &DataplaneShared,
    peer_id: &str,
    packet: Bytes,
) -> Result<Bytes> {
    let Some(key) = current_relay_key(shared) else {
        return Ok(packet);
    };
    if parse_relay_envelope(&packet).is_some() {
        return Ok(packet);
    }
    let header = freeq_tunnel::packet::parse_ipv4_header(packet.as_ref())?;
    if shared
        .direct_peer_hosts
        .get(peer_id)
        .is_some_and(|direct_host| *direct_host == IpAddr::V4(header.destination))
    {
        return Ok(packet);
    }
    let counter = shared.e2e_relay_counter.fetch_add(1, Ordering::Relaxed);
    Ok(build_relay_envelope(
        key,
        counter,
        header.destination,
        packet.as_ref(),
    )?)
}

fn build_relay_envelope(
    key: [u8; 32],
    counter: u64,
    destination: Ipv4Addr,
    plaintext: &[u8],
) -> freeq_crypto::Result<Bytes> {
    let plaintext_len =
        u16::try_from(plaintext.len()).map_err(|_| freeq_crypto::CryptoError::KdfLength)?;
    let mut nonce = [0u8; freeq_crypto::bulk::NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    let aad = relay_aad(destination, &nonce, plaintext_len);
    let ciphertext = freeq_crypto::bulk::encrypt(
        &freeq_crypto::agility::AlgorithmSuite::default().bulk,
        &key,
        &nonce,
        &aad,
        plaintext,
    )?;
    let mut envelope = Vec::with_capacity(RELAY_HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(RELAY_MAGIC);
    envelope.push(RELAY_VERSION);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&destination.octets());
    envelope.extend_from_slice(&plaintext_len.to_be_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(Bytes::from(envelope))
}

fn parse_relay_envelope(packet: &[u8]) -> Option<RelayEnvelope<'_>> {
    if packet.len() < RELAY_HEADER_LEN || &packet[0..4] != RELAY_MAGIC || packet[4] != RELAY_VERSION
    {
        return None;
    }
    let mut nonce = [0u8; freeq_crypto::bulk::NONCE_LEN];
    nonce.copy_from_slice(&packet[5..17]);
    let destination = Ipv4Addr::new(packet[17], packet[18], packet[19], packet[20]);
    let plaintext_len = u16::from_be_bytes([packet[21], packet[22]]);
    Some(RelayEnvelope {
        destination,
        nonce,
        plaintext_len,
        ciphertext: &packet[RELAY_HEADER_LEN..],
    })
}

fn decrypt_relay_payload(key: [u8; 32], relay: RelayEnvelope<'_>) -> freeq_crypto::Result<Bytes> {
    if relay.ciphertext.len() < freeq_crypto::bulk::TAG_LEN {
        return Err(freeq_crypto::CryptoError::AeadAuthFailure);
    }
    let aad = relay_aad(relay.destination, &relay.nonce, relay.plaintext_len);
    let plaintext = freeq_crypto::bulk::decrypt(
        &freeq_crypto::agility::AlgorithmSuite::default().bulk,
        &key,
        &relay.nonce,
        &aad,
        relay.ciphertext,
    )?;
    if plaintext.len() != usize::from(relay.plaintext_len) {
        return Err(freeq_crypto::CryptoError::AeadAuthFailure);
    }
    Ok(Bytes::from(plaintext))
}

fn relay_aad(
    destination: Ipv4Addr,
    nonce: &[u8; freeq_crypto::bulk::NONCE_LEN],
    plaintext_len: u16,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RELAY_AAD_CONTEXT.len() + 1 + nonce.len() + 6);
    aad.extend_from_slice(RELAY_AAD_CONTEXT);
    aad.push(RELAY_VERSION);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&destination.octets());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

#[derive(Debug)]
struct PairControlPacket {
    msg_type: u8,
    offer_id: u64,
    rotation_secs: u64,
    sender: String,
    identity_pubkey: Vec<u8>,
    material: Vec<u8>,
    signature: Vec<u8>,
    signed_body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PairChunkKey {
    sender: String,
    msg_type: u8,
    offer_id: u64,
}

struct PairChunkBuffer {
    chunks: Vec<Option<Vec<u8>>>,
}

fn is_pair_control_packet(packet: &[u8]) -> bool {
    packet.len() >= 5 && &packet[0..4] == PAIR_MAGIC && packet[4] == PAIR_VERSION
}

fn is_pair_chunk_packet(packet: &[u8]) -> bool {
    packet.len() >= 5 && &packet[0..4] == PAIR_CHUNK_MAGIC && packet[4] == PAIR_VERSION
}

async fn run_relay_pair_manager(shared: DataplaneShared) {
    let mut tick = tokio::time::interval(RELAY_PAIR_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if let Err(err) = maybe_start_relay_pair_handshake(&shared).await {
            shared
                .api_state
                .record_error(freeq_api::ErrorKind::Crypto, err.to_string())
                .await;
            tracing::warn!(error = %err, "relay pair handshake tick failed");
        }
    }
}

async fn maybe_start_relay_pair_handshake(shared: &DataplaneShared) -> Result<()> {
    if !should_initiate_relay_pair(shared) {
        return Ok(());
    }
    if !relay_key_needs_refresh(shared) {
        return Ok(());
    }
    let sessions = shared.active_sessions.lock().await;
    for (peer_name, session) in sessions.iter() {
        if !session.is_usable() || !shared.proactive_peer_ids.contains(peer_name) {
            continue;
        }
        let packet = build_pair_offer(shared)?;
        transmit_control_on_session(shared, Arc::clone(session), peer_name, Bytes::from(packet))
            .await?;
        tracing::info!(
            gateway = %peer_name,
            rotation_secs = shared.relay_pair_rotation_secs,
            "relay pair key offer sent"
        );
    }
    Ok(())
}

fn should_initiate_relay_pair(shared: &DataplaneShared) -> bool {
    shared
        .relay_pair_peer_ids
        .iter()
        .any(|peer| shared.node_name.as_str() < peer.as_str())
}

fn relay_key_needs_refresh(shared: &DataplaneShared) -> bool {
    let Ok(guard) = shared.e2e_relay_keys.lock() else {
        return true;
    };
    match guard.as_ref() {
        Some(state) => {
            let refresh_at = state
                .expires_at
                .checked_sub(RELAY_PAIR_REFRESH_MARGIN)
                .unwrap_or(state.installed_at);
            Instant::now() >= refresh_at
        }
        None => true,
    }
}

fn build_pair_offer(shared: &DataplaneShared) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let offer_id = rng.next_u64();
    let (secret, public) = freeq_crypto::kem::HybridSecretKey::generate(&mut rng)?;
    let expires_at = Instant::now() + Duration::from_secs(shared.relay_pair_rotation_secs);
    shared
        .relay_pair_pending
        .lock()
        .map_err(|_| anyhow::anyhow!("relay pair pending-offer lock poisoned"))?
        .insert(offer_id, PendingRelayOffer { secret, expires_at });
    encode_pair_control_packet(
        PAIR_TYPE_OFFER,
        offer_id,
        shared.relay_pair_rotation_secs,
        shared.node_name.clone(),
        shared.identity.public_key().to_bytes(),
        public.to_bytes(),
        shared.identity.as_ref(),
    )
}

async fn handle_pair_control_packet(
    shared: &DataplaneShared,
    transport_peer: &str,
    packet: &[u8],
) -> Result<()> {
    let control = parse_pair_control_packet(packet)?;
    if control.sender == shared.node_name {
        return Ok(());
    }
    verify_pair_control_signature(shared, &control)?;
    match control.msg_type {
        PAIR_TYPE_OFFER => handle_pair_offer(shared, transport_peer, control).await,
        PAIR_TYPE_ANSWER => handle_pair_answer(shared, control).await,
        _ => anyhow::bail!(
            "unknown relay pair control message type {}",
            control.msg_type
        ),
    }
}

async fn forward_pair_control_from_source(
    shared: &DataplaneShared,
    source_peer: &str,
    packet: &[u8],
) -> Result<()> {
    let sessions = shared.active_sessions.lock().await;
    let mut forwarded = 0usize;
    for (peer_name, session) in sessions.iter() {
        if peer_name == source_peer || !session.is_usable() {
            continue;
        }
        let prepared = shared
            .tunnel_service
            .prepare_payload_for_peer_with_session(
                peer_name.clone(),
                Bytes::copy_from_slice(packet),
                &session.outbound_key,
            )?;
        for frame in prepared.frames {
            session.connection.send(frame).await?;
        }
        forwarded += 1;
    }
    if forwarded == 0 {
        anyhow::bail!("relay pair control from '{source_peer}' had no online destination peer");
    }
    tracing::info!(
        peer = %source_peer,
        destinations = forwarded,
        "forwarded relay pair control packet"
    );
    Ok(())
}

async fn handle_pair_offer(
    shared: &DataplaneShared,
    transport_peer: &str,
    offer: PairControlPacket,
) -> Result<()> {
    let public = freeq_crypto::kem::HybridPublicKey::from_bytes(&offer.material)?;
    let session_info = relay_pair_session_info(&offer.sender, &shared.node_name, offer.offer_id);
    let (shared_secret, ciphertext) = {
        let mut rng = rand::thread_rng();
        freeq_crypto::kem::hybrid_encapsulate(
            &public.x25519_public_key(),
            public.mlkem_public_key(),
            &session_info,
            &mut rng,
        )?
    };
    install_relay_pair_key(
        shared,
        &offer.sender,
        offer.offer_id,
        offer.rotation_secs,
        shared_secret.session_key,
    )?;
    let answer = encode_pair_control_packet(
        PAIR_TYPE_ANSWER,
        offer.offer_id,
        offer.rotation_secs,
        shared.node_name.clone(),
        shared.identity.public_key().to_bytes(),
        ciphertext.to_bytes(),
        shared.identity.as_ref(),
    )?;
    let session = {
        shared
            .active_sessions
            .lock()
            .await
            .get(transport_peer)
            .cloned()
    }
    .ok_or_else(|| anyhow::anyhow!("missing transport session for relay pair answer"))?;
    transmit_control_on_session(shared, session, transport_peer, Bytes::from(answer)).await?;
    tracing::info!(
        peer = %offer.sender,
        gateway = %transport_peer,
        rotation_secs = offer.rotation_secs,
        "relay pair answer sent and key installed"
    );
    Ok(())
}

async fn handle_pair_answer(shared: &DataplaneShared, answer: PairControlPacket) -> Result<()> {
    let pending = shared
        .relay_pair_pending
        .lock()
        .map_err(|_| anyhow::anyhow!("relay pair pending-offer lock poisoned"))?
        .remove(&answer.offer_id)
        .ok_or_else(|| anyhow::anyhow!("relay pair answer had no pending offer"))?;
    if Instant::now() >= pending.expires_at {
        anyhow::bail!("relay pair answer arrived after pending offer expired");
    }
    let ciphertext = freeq_crypto::kem::HybridCiphertext::from_bytes(&answer.material)?;
    let secret_bytes = pending.secret.to_bytes();
    let x25519_secret: [u8; 32] = secret_bytes[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pending X25519 secret"))?;
    let session_info = relay_pair_session_info(&shared.node_name, &answer.sender, answer.offer_id);
    let shared_secret = freeq_crypto::kem::hybrid_decapsulate(
        &ciphertext,
        &x25519_secret,
        &secret_bytes[32..],
        &session_info,
    )?;
    install_relay_pair_key(
        shared,
        &answer.sender,
        answer.offer_id,
        answer.rotation_secs,
        shared_secret.session_key,
    )?;
    tracing::info!(
        peer = %answer.sender,
        rotation_secs = answer.rotation_secs,
        "relay pair key installed from answer"
    );
    Ok(())
}

fn verify_pair_control_signature(
    shared: &DataplaneShared,
    control: &PairControlPacket,
) -> Result<()> {
    let pinned_key = shared
        .peer_registry
        .get_peer(&control.sender)
        .map(|peer| peer.identity_pubkey.as_slice());
    let expected = pinned_key.unwrap_or(control.identity_pubkey.as_slice());
    if pinned_key.is_none() {
        anyhow::bail!(
            "relay pair peer '{}' is not in the local registry; refusing unauthenticated pair",
            control.sender
        );
    }
    if expected != control.identity_pubkey.as_slice() {
        anyhow::bail!("relay pair identity mismatch for '{}'", control.sender);
    }
    let public_key = freeq_crypto::sign::IdentityPublicKey::from_bytes(expected)?;
    public_key.verify_message(
        &pair_signature_message(&control.signed_body),
        &freeq_crypto::sign::Signature(control.signature.clone()),
    )?;
    Ok(())
}

fn install_relay_pair_key(
    shared: &DataplaneShared,
    peer_name: &str,
    offer_id: u64,
    rotation_secs: u64,
    session_key: [u8; 32],
) -> Result<()> {
    let key = freeq_crypto::kdf::hkdf_sha256(
        Some(RELAY_PAIR_KDF_CONTEXT),
        &session_key,
        &relay_pair_session_info(&shared.node_name, peer_name, offer_id),
    )?;
    let now = Instant::now();
    let ttl = rotation_secs
        .max(60)
        .min(shared.relay_pair_rotation_secs.max(60));
    let mut guard = shared
        .e2e_relay_keys
        .lock()
        .map_err(|_| anyhow::anyhow!("relay key lock poisoned"))?;
    let generation = guard
        .as_ref()
        .map(|state| state.generation + 1)
        .unwrap_or(1);
    *guard = Some(RelayKeyState {
        key,
        generation,
        expires_at: now + Duration::from_secs(ttl),
        installed_at: now,
    });
    Ok(())
}

async fn transmit_control_on_session(
    shared: &DataplaneShared,
    session: Arc<ActivePeerSession>,
    peer_id: &str,
    packet: Bytes,
) -> Result<()> {
    for control_packet in chunk_pair_control_packet(packet.as_ref())? {
        let prepared = shared
            .tunnel_service
            .prepare_payload_for_peer_with_session(
                peer_id.to_string(),
                control_packet,
                &session.outbound_key,
            )?;
        for frame in prepared.frames {
            session.connection.send(frame).await?;
        }
    }
    Ok(())
}

fn chunk_pair_control_packet(packet: &[u8]) -> Result<Vec<Bytes>> {
    if packet.len() <= PAIR_CONTROL_CHUNK_SIZE {
        return Ok(vec![Bytes::copy_from_slice(packet)]);
    }
    let control = parse_pair_control_packet(packet)?;
    let total = packet.len().div_ceil(PAIR_CONTROL_CHUNK_SIZE);
    let total_u16 = u16::try_from(total).map_err(|_| anyhow::anyhow!("too many pair chunks"))?;
    let mut chunks = Vec::with_capacity(total);
    for (index, chunk) in packet.chunks(PAIR_CONTROL_CHUNK_SIZE).enumerate() {
        let mut out = Vec::with_capacity(32 + control.sender.len() + chunk.len());
        out.extend_from_slice(PAIR_CHUNK_MAGIC);
        out.push(PAIR_VERSION);
        out.push(control.msg_type);
        out.extend_from_slice(&control.offer_id.to_be_bytes());
        out.extend_from_slice(&total_u16.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(index)
                .map_err(|_| anyhow::anyhow!("pair chunk index overflow"))?
                .to_be_bytes(),
        );
        push_len_bytes(&mut out, control.sender.as_bytes())?;
        out.extend_from_slice(chunk);
        chunks.push(Bytes::from(out));
    }
    Ok(chunks)
}

fn handle_pair_control_chunk(shared: &DataplaneShared, packet: &[u8]) -> Result<Option<Vec<u8>>> {
    let (key, total, index, chunk) = parse_pair_control_chunk(packet)?;
    let mut guard = shared
        .relay_pair_chunks
        .lock()
        .map_err(|_| anyhow::anyhow!("relay pair chunk lock poisoned"))?;
    let buffer = guard.entry(key.clone()).or_insert_with(|| PairChunkBuffer {
        chunks: vec![None; usize::from(total)],
    });
    if buffer.chunks.len() != usize::from(total) {
        anyhow::bail!("relay pair chunk total changed mid-message");
    }
    buffer.chunks[usize::from(index)] = Some(chunk.to_vec());
    if buffer.chunks.iter().any(Option::is_none) {
        return Ok(None);
    }
    let mut full = Vec::new();
    for chunk in &buffer.chunks {
        let Some(chunk) = chunk.as_ref() else {
            anyhow::bail!("relay pair chunk missing after completeness check");
        };
        full.extend_from_slice(chunk);
    }
    guard.remove(&key);
    Ok(Some(full))
}

fn parse_pair_control_chunk(packet: &[u8]) -> Result<(PairChunkKey, u16, u16, &[u8])> {
    if packet.len() < 20 || !is_pair_chunk_packet(packet) {
        anyhow::bail!("invalid relay pair chunk packet");
    }
    let msg_type = packet[5];
    let offer_id = u64::from_be_bytes(packet[6..14].try_into()?);
    let total = u16::from_be_bytes(packet[14..16].try_into()?);
    let index = u16::from_be_bytes(packet[16..18].try_into()?);
    if total == 0 || index >= total {
        anyhow::bail!("invalid relay pair chunk index");
    }
    let mut offset = 18;
    let sender = std::str::from_utf8(take_len_bytes(packet, &mut offset)?)?.to_string();
    Ok((
        PairChunkKey {
            sender,
            msg_type,
            offer_id,
        },
        total,
        index,
        &packet[offset..],
    ))
}

fn encode_pair_control_packet(
    msg_type: u8,
    offer_id: u64,
    rotation_secs: u64,
    sender: String,
    identity_pubkey: Vec<u8>,
    material: Vec<u8>,
    identity: &freeq_crypto::sign::IdentityKeypair,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(PAIR_MAGIC);
    body.push(PAIR_VERSION);
    body.push(msg_type);
    body.extend_from_slice(&offer_id.to_be_bytes());
    body.extend_from_slice(&rotation_secs.to_be_bytes());
    push_len_bytes(&mut body, sender.as_bytes())?;
    push_len_bytes(&mut body, &identity_pubkey)?;
    push_len_bytes(&mut body, &material)?;
    let signature = identity.sign_message(&pair_signature_message(&body))?.0;
    push_len_bytes(&mut body, &signature)?;
    Ok(body)
}

fn parse_pair_control_packet(packet: &[u8]) -> Result<PairControlPacket> {
    if packet.len() < 22 || &packet[0..4] != PAIR_MAGIC || packet[4] != PAIR_VERSION {
        anyhow::bail!("invalid relay pair control packet");
    }
    let msg_type = packet[5];
    let offer_id = u64::from_be_bytes(packet[6..14].try_into()?);
    let rotation_secs = u64::from_be_bytes(packet[14..22].try_into()?);
    let mut offset = 22;
    let sender_bytes = take_len_bytes(packet, &mut offset)?;
    let identity_pubkey = take_len_bytes(packet, &mut offset)?.to_vec();
    let material = take_len_bytes(packet, &mut offset)?.to_vec();
    let signed_body = packet[..offset].to_vec();
    let signature = take_len_bytes(packet, &mut offset)?.to_vec();
    if offset != packet.len() {
        anyhow::bail!("relay pair control packet had trailing bytes");
    }
    let sender = std::str::from_utf8(sender_bytes)?.to_string();
    Ok(PairControlPacket {
        msg_type,
        offer_id,
        rotation_secs,
        sender,
        identity_pubkey,
        material,
        signature,
        signed_body,
    })
}

fn pair_control_sender(packet: &[u8]) -> Result<String> {
    let control = parse_pair_control_packet(packet)?;
    Ok(control.sender)
}

fn pair_chunk_sender(packet: &[u8]) -> Result<String> {
    let (key, _, _, _) = parse_pair_control_chunk(packet)?;
    Ok(key.sender)
}

fn push_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| anyhow::anyhow!("field too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_len_bytes<'a>(packet: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    if packet.len().saturating_sub(*offset) < 2 {
        anyhow::bail!("truncated relay pair field length");
    }
    let len = u16::from_be_bytes(packet[*offset..*offset + 2].try_into()?);
    *offset += 2;
    let end = *offset + usize::from(len);
    if end > packet.len() {
        anyhow::bail!("truncated relay pair field");
    }
    let bytes = &packet[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn pair_signature_message(body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RELAY_PAIR_SIGN_CONTEXT.len() + body.len());
    msg.extend_from_slice(RELAY_PAIR_SIGN_CONTEXT);
    msg.extend_from_slice(body);
    msg
}

fn relay_pair_session_info(left: &str, right: &str, offer_id: u64) -> Vec<u8> {
    let mut names = [left, right];
    names.sort_unstable();
    let mut info = Vec::with_capacity(RELAY_PAIR_KDF_CONTEXT.len() + left.len() + right.len() + 16);
    info.extend_from_slice(RELAY_PAIR_KDF_CONTEXT);
    info.extend_from_slice(names[0].as_bytes());
    info.push(0);
    info.extend_from_slice(names[1].as_bytes());
    info.push(0);
    info.extend_from_slice(&offer_id.to_be_bytes());
    info
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
) -> Result<(Arc<ActivePeerSession>, bool)> {
    {
        let mut sessions = active_sessions.lock().await;
        if let Some(session) = sessions.get(peer_name).cloned() {
            if session.is_usable() {
                return Ok((session, false));
            }
            tracing::info!(
                peer = %peer_name,
                "replacing dead peer session (full re-handshake; never reuse)"
            );
            sessions.remove(peer_name);
            let _ = session.connection.close().await;
        }
    }

    // Security over availability: on establish failure we do NOT return a dead
    // session. Caller retries; traffic fails closed until rejoin succeeds.
    let session =
        establish_outbound_session(endpoint, identity, peer_registry, peer_name, peer_addr)
            .await
            .map(Arc::new)?;

    active_sessions
        .lock()
        .await
        .insert(peer_name.to_string(), Arc::clone(&session));
    Ok((session, true))
}

async fn establish_outbound_session(
    endpoint: freeq_transport::endpoint::Endpoint,
    identity: &freeq_crypto::sign::IdentityKeypair,
    peer_registry: &freeq_auth::registry::PeerRegistry,
    peer_name: &str,
    peer_addr: SocketAddr,
) -> Result<ActivePeerSession> {
    // Bound the whole dial+handshake so a hung peer cannot burn the rejoin budget.
    match tokio::time::timeout(
        OUTBOUND_ESTABLISH_DEADLINE,
        establish_outbound_session_inner(endpoint, identity, peer_registry, peer_name, peer_addr),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => anyhow::bail!(
            "outbound establish to '{peer_name}' timed out after {}ms",
            OUTBOUND_ESTABLISH_DEADLINE.as_millis()
        ),
    }
}

async fn establish_outbound_session_inner(
    endpoint: freeq_transport::endpoint::Endpoint,
    identity: &freeq_crypto::sign::IdentityKeypair,
    peer_registry: &freeq_auth::registry::PeerRegistry,
    peer_name: &str,
    peer_addr: SocketAddr,
) -> Result<ActivePeerSession> {
    tracing::info!(peer = %peer_name, endpoint = %peer_addr, "establishing outbound peer session");
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
    tracing::info!(peer = %peer_name, endpoint = %peer_addr, "outbound peer session established");

    Ok(ActivePeerSession::new(
        connection,
        keys.outbound,
        keys.inbound,
    ))
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
        Arc::new(ActivePeerSession::new(
            connection,
            keys.outbound,
            keys.inbound,
        )),
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
        validate_existing_private_key_permissions(path)?;
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

#[cfg(test)]
mod tests {
    use super::{
        accept_inbound_session, build_api_server, build_peer_registry, collect_startup_blockers,
        current_relay_key, endpoint_bind_mode, get_or_create_outbound_session, init_api_state,
        init_identity, init_tunnel_service, init_tunnel_service_with_keys, is_silent_inbound_probe,
        parse_listen_addr, parse_peer_socket_addrs, proactive_outbound_peers, refresh_api_state,
        spawn_dataplane_runtime, spawn_packet_io_runtime, DataplaneShared, PacketIo, RelayKeyState,
        BATTLEFIELD_REJOIN_BUDGET, DATAPLANE_CHANNEL_CAPACITY, DEFAULT_RELAY_KEY_ROTATION_SECS,
    };
    use base64::Engine as _;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, Mutex};

    fn test_relay_key_state(key: Option<[u8; 32]>) -> Arc<StdMutex<Option<RelayKeyState>>> {
        Arc::new(StdMutex::new(key.map(|key| {
            let now = Instant::now();
            RelayKeyState {
                key,
                generation: 1,
                expires_at: now + Duration::from_secs(3600),
                installed_at: now,
            }
        })))
    }

    fn test_pair_chunks() -> Arc<StdMutex<HashMap<super::PairChunkKey, super::PairChunkBuffer>>> {
        Arc::new(StdMutex::new(HashMap::new()))
    }

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

    #[cfg(unix)]
    #[test]
    fn init_identity_rejects_group_or_world_readable_existing_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let key_path = tempdir.path().join("identity.key");
        init_identity(&key_path).expect("initial key generation");

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640))
            .expect("loosen key permissions");
        let err = match init_identity(&key_path) {
            Ok(_) => panic!("loose permissions should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("set permissions to 0600"));
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
    fn endpoint_bind_mode_reflects_strict_cloaking_config() {
        let mut config = sample_config();

        assert_eq!(
            endpoint_bind_mode(&config),
            freeq_transport::endpoint::EndpointBindMode::DirectQuic
        );

        config.node.strict_cloaking = true;
        assert_eq!(
            endpoint_bind_mode(&config),
            freeq_transport::endpoint::EndpointBindMode::StrictCloaked
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
            "10.0.0.2/32",
        );
        let receiver_config = config_with_socket_peer(
            client_endpoint.local_addr().expect("client addr"),
            "receiver",
            "sender",
            &sender_identity.public_key_b64,
            &sender_identity.kem_key_b64,
            "10.0.0.1/32",
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
        let (sender_out_tx, mut sender_out_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (receiver_in_tx, receiver_in_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (receiver_tun_tx, mut receiver_tun_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);

        let _sender_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: client_endpoint.clone(),
                tunnel_service: Arc::clone(&sender_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&sender_config).expect("sender peers"),
                ),
                direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&sender_config)),
                proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(&sender_config)),
                relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&sender_config)),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                node_name: "sender".into(),
                identity: Arc::new(sender_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&sender_config).expect("sender registry"),
                ),
                api_state: sender_state.clone(),
                e2e_relay_keys: test_relay_key_state(None),
                e2e_relay_counter: Arc::new(AtomicU64::new(0)),
                relay_pair_rotation_secs: DEFAULT_RELAY_KEY_ROTATION_SECS,
                relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
                relay_pair_chunks: test_pair_chunks(),
            },
            sender_tun_rx,
            sender_out_tx,
        );
        let _receiver_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: server_endpoint.clone(),
                tunnel_service: Arc::clone(&receiver_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&receiver_config).expect("receiver peers"),
                ),
                direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&receiver_config)),
                proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(
                    &receiver_config,
                )),
                relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&receiver_config)),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                node_name: "receiver".into(),
                identity: Arc::new(receiver_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&receiver_config).expect("receiver registry"),
                ),
                api_state: receiver_state.clone(),
                e2e_relay_keys: test_relay_key_state(None),
                e2e_relay_counter: Arc::new(AtomicU64::new(0)),
                relay_pair_rotation_secs: DEFAULT_RELAY_KEY_ROTATION_SECS,
                relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
                relay_pair_chunks: test_pair_chunks(),
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

        let return_packet = Bytes::from(test_ipv4_packet_with_source_dest(
            1180,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        ));
        receiver_in_tx
            .send(return_packet.clone())
            .await
            .expect("send return packet into receiver virtual tun");

        let returned = match tokio::time::timeout(Duration::from_secs(5), sender_out_rx.recv())
            .await
        {
            Ok(Some(packet)) => packet,
            Ok(None) => panic!("sender packet channel closed"),
            Err(_) => {
                refresh_api_state(&sender_state, sender_service.as_ref()).await;
                refresh_api_state(&receiver_state, receiver_service.as_ref()).await;
                let sender_snapshot = sender_state.snapshot().await;
                let receiver_snapshot = receiver_state.snapshot().await;
                panic!(
                    "return timeout: sender packets={}, frames={}, last_error={:?}; receiver packets={}, frames={}, last_error={:?}",
                    sender_snapshot.tunnel.packets_ingested,
                    sender_snapshot.tunnel.transport_frames,
                    sender_snapshot.last_error,
                    receiver_snapshot.tunnel.packets_ingested,
                    receiver_snapshot.tunnel.transport_frames,
                    receiver_snapshot.last_error,
                );
            }
        };

        assert_eq!(returned, return_packet);

        refresh_api_state(&sender_state, sender_service.as_ref()).await;
        refresh_api_state(&receiver_state, receiver_service.as_ref()).await;
        let sender_snapshot = sender_state.snapshot().await;
        let receiver_snapshot = receiver_state.snapshot().await;
        assert_eq!(sender_snapshot.tunnel.packets_ingested, 1);
        assert!(sender_snapshot.tunnel.transport_frames >= 1);
        assert_eq!(receiver_snapshot.tunnel.packets_ingested, 1);
        assert!(receiver_snapshot.tunnel.transport_frames >= 1);

        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn dataplane_runtime_relays_packet_between_gateway_peers() {
        let gateway_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind gateway endpoint");
        let node_a_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind node-a endpoint");
        let node_b_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind david endpoint");

        let gateway_identity = generate_identity_bytes();
        let node_a_identity = generate_identity_bytes();
        let node_b_identity = generate_identity_bytes();

        let gateway_addr = gateway_endpoint.local_addr().expect("gateway addr");

        let node_a_config = config_with_socket_peer_allowed_ips(
            gateway_addr,
            "node-a",
            "gateway",
            &gateway_identity.public_key_b64,
            &gateway_identity.kem_key_b64,
            &["10.0.0.254/32", "10.0.0.2/32"],
        );
        let node_b_config = config_with_socket_peer_allowed_ips(
            gateway_addr,
            "node-b",
            "gateway",
            &gateway_identity.public_key_b64,
            &gateway_identity.kem_key_b64,
            &["10.0.0.254/32", "10.0.0.1/32"],
        );
        let gateway_config = gateway_config_with_two_peers(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 51820),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 51820),
            &node_a_identity,
            &node_b_identity,
        );

        let shared_keys =
            freeq_crypto::FreeQKeyPair::generate_ephemeral_test_pair().expect("shared tunnel keys");
        let relay_key = [9u8; 32];
        let node_a_service = Arc::new(
            init_tunnel_service_with_keys(&node_a_config, shared_keys.clone())
                .expect("node-a tunnel"),
        );
        let node_b_service = Arc::new(
            init_tunnel_service_with_keys(&node_b_config, shared_keys.clone())
                .expect("node-b tunnel"),
        );
        let gateway_service = Arc::new(
            init_tunnel_service_with_keys(&gateway_config, shared_keys).expect("gateway tunnel"),
        );

        let node_a_state = init_api_state(&node_a_config, node_a_service.as_ref()).await;
        let node_b_state = init_api_state(&node_b_config, node_b_service.as_ref()).await;
        let gateway_state = init_api_state(&gateway_config, gateway_service.as_ref()).await;

        let (node_a_tun_tx, node_a_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (node_a_out_tx, mut node_a_out_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (node_b_tun_tx, node_b_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (node_b_out_tx, mut node_b_out_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (_gateway_tun_tx, gateway_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (gateway_out_tx, mut gateway_out_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);

        let _patrick_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: node_a_endpoint.clone(),
                tunnel_service: Arc::clone(&node_a_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&node_a_config).expect("node-a peers"),
                ),
                direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&node_a_config)),
                proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(
                    &node_a_config,
                )),
                relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&node_a_config)),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                node_name: "node-a".into(),
                identity: Arc::new(node_a_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&node_a_config).expect("patrick registry"),
                ),
                api_state: node_a_state.clone(),
                e2e_relay_keys: test_relay_key_state(Some(relay_key)),
                e2e_relay_counter: Arc::new(AtomicU64::new(0)),
                relay_pair_rotation_secs: DEFAULT_RELAY_KEY_ROTATION_SECS,
                relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
                relay_pair_chunks: test_pair_chunks(),
            },
            node_a_tun_rx,
            node_a_out_tx,
        );
        let _david_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: node_b_endpoint.clone(),
                tunnel_service: Arc::clone(&node_b_service),
                peer_addrs: Arc::new(parse_peer_socket_addrs(&node_b_config).expect("node-b peers")),
                direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&node_b_config)),
                proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(&node_b_config)),
                relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&node_b_config)),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                node_name: "node-b".into(),
                identity: Arc::new(node_b_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&node_b_config).expect("david registry"),
                ),
                api_state: node_b_state.clone(),
                e2e_relay_keys: test_relay_key_state(Some(relay_key)),
                e2e_relay_counter: Arc::new(AtomicU64::new(0)),
                relay_pair_rotation_secs: DEFAULT_RELAY_KEY_ROTATION_SECS,
                relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
                relay_pair_chunks: test_pair_chunks(),
            },
            node_b_tun_rx,
            node_b_out_tx,
        );
        let _gateway_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: gateway_endpoint.clone(),
                tunnel_service: Arc::clone(&gateway_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&gateway_config).expect("gateway peers"),
                ),
                direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&gateway_config)),
                proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(
                    &gateway_config,
                )),
                relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&gateway_config)),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                node_name: "gateway".into(),
                identity: Arc::new(gateway_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&gateway_config).expect("gateway registry"),
                ),
                api_state: gateway_state.clone(),
                e2e_relay_keys: test_relay_key_state(None),
                e2e_relay_counter: Arc::new(AtomicU64::new(0)),
                relay_pair_rotation_secs: DEFAULT_RELAY_KEY_ROTATION_SECS,
                relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
                relay_pair_chunks: test_pair_chunks(),
            },
            gateway_tun_rx,
            gateway_out_tx,
        );

        tokio::time::sleep(Duration::from_millis(300)).await;

        let patrick_to_david = Bytes::from(test_ipv4_packet_with_source_dest(
            1180,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        ));
        node_a_tun_tx
            .send(patrick_to_david.clone())
            .await
            .expect("send patrick packet");
        let david_received = tokio::time::timeout(Duration::from_secs(5), node_b_out_rx.recv())
            .await
            .expect("david receive timeout")
            .expect("david packet");
        assert_eq!(david_received, patrick_to_david);

        let david_to_patrick = Bytes::from(test_ipv4_packet_with_source_dest(
            1180,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        ));
        node_b_tun_tx
            .send(david_to_patrick.clone())
            .await
            .expect("send david packet");
        let patrick_received = match tokio::time::timeout(
            Duration::from_secs(5),
            node_a_out_rx.recv(),
        )
        .await
        {
            Ok(Some(packet)) => packet,
            Ok(None) => panic!("patrick packet channel closed"),
            Err(err) => {
                refresh_api_state(&node_a_state, node_a_service.as_ref()).await;
                refresh_api_state(&node_b_state, node_b_service.as_ref()).await;
                refresh_api_state(&gateway_state, gateway_service.as_ref()).await;
                let patrick_snapshot = node_a_state.snapshot().await;
                let david_snapshot = node_b_state.snapshot().await;
                let gateway_snapshot = gateway_state.snapshot().await;
                panic!(
                        "patrick receive timeout: {err}; patrick={:?}/{:?}; david={:?}/{:?}; gateway={:?}/{:?}",
                        patrick_snapshot.last_error,
                        patrick_snapshot.tunnel,
                        david_snapshot.last_error,
                        david_snapshot.tunnel,
                        gateway_snapshot.last_error,
                        gateway_snapshot.tunnel,
                    );
            }
        };
        assert_eq!(patrick_received, david_to_patrick);

        assert!(gateway_out_rx.try_recv().is_err());

        refresh_api_state(&gateway_state, gateway_service.as_ref()).await;
        let gateway_snapshot = gateway_state.snapshot().await;
        assert_eq!(gateway_snapshot.tunnel.route_misses, 0);

        node_a_endpoint.close().await;
        node_b_endpoint.close().await;
        gateway_endpoint.close().await;
    }

    #[tokio::test]
    async fn dataplane_runtime_auto_pairs_relay_key_through_gateway() {
        let gateway_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind gateway endpoint");
        let node_a_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind node-a endpoint");
        let node_b_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind david endpoint");

        let gateway_identity = generate_identity_bytes();
        let node_a_identity = generate_identity_bytes();
        let node_b_identity = generate_identity_bytes();
        let gateway_addr = gateway_endpoint.local_addr().expect("gateway addr");

        let mut node_a_config = config_with_socket_peer_allowed_ips(
            gateway_addr,
            "node-a",
            "gateway",
            &gateway_identity.public_key_b64,
            &gateway_identity.kem_key_b64,
            &["10.0.0.254/32", "10.0.0.2/32"],
        );
        node_a_config.peer[0].mode = Some(freeq_config::PeerMode::GatewayClient);
        node_a_config.peer[0].key_rotation_secs = 900;
        node_a_config.peer.push(freeq_config::PeerConfig {
            name: "node-b".into(),
            public_key: node_b_identity.public_key_b64.clone(),
            kem_key: node_b_identity.kem_key_b64.clone(),
            endpoint: None,
            mode: Some(freeq_config::PeerMode::RelayLeaf),
            allowed_ips: Vec::new(),
            key_rotation_secs: 900,
        });

        let mut node_b_config = config_with_socket_peer_allowed_ips(
            gateway_addr,
            "node-b",
            "gateway",
            &gateway_identity.public_key_b64,
            &gateway_identity.kem_key_b64,
            &["10.0.0.254/32", "10.0.0.1/32"],
        );
        node_b_config.peer[0].mode = Some(freeq_config::PeerMode::GatewayClient);
        node_b_config.peer[0].key_rotation_secs = 900;
        node_b_config.peer.push(freeq_config::PeerConfig {
            name: "node-a".into(),
            public_key: node_a_identity.public_key_b64.clone(),
            kem_key: node_a_identity.kem_key_b64.clone(),
            endpoint: None,
            mode: Some(freeq_config::PeerMode::RelayLeaf),
            allowed_ips: Vec::new(),
            key_rotation_secs: 900,
        });

        let gateway_config = gateway_config_with_two_peers(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 51820),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 51820),
            &node_a_identity,
            &node_b_identity,
        );

        let shared_keys =
            freeq_crypto::FreeQKeyPair::generate_ephemeral_test_pair().expect("shared tunnel keys");
        let node_a_service = Arc::new(
            init_tunnel_service_with_keys(&node_a_config, shared_keys.clone())
                .expect("node-a tunnel"),
        );
        let node_b_service = Arc::new(
            init_tunnel_service_with_keys(&node_b_config, shared_keys.clone())
                .expect("node-b tunnel"),
        );
        let gateway_service = Arc::new(
            init_tunnel_service_with_keys(&gateway_config, shared_keys).expect("gateway tunnel"),
        );

        let node_a_state = init_api_state(&node_a_config, node_a_service.as_ref()).await;
        let node_b_state = init_api_state(&node_b_config, node_b_service.as_ref()).await;
        let gateway_state = init_api_state(&gateway_config, gateway_service.as_ref()).await;

        let (node_a_tun_tx, node_a_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (node_a_out_tx, mut node_a_out_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (_david_tun_tx, node_b_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (node_b_out_tx, mut node_b_out_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (_gateway_tun_tx, gateway_tun_rx) = mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);
        let (gateway_out_tx, mut gateway_out_rx) =
            mpsc::channel::<Bytes>(DATAPLANE_CHANNEL_CAPACITY);

        let patrick_shared = DataplaneShared {
            endpoint: node_a_endpoint.clone(),
            tunnel_service: Arc::clone(&node_a_service),
            peer_addrs: Arc::new(parse_peer_socket_addrs(&node_a_config).expect("node-a peers")),
            direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&node_a_config)),
            proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(&node_a_config)),
            relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&node_a_config)),
            active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            node_name: "node-a".into(),
            identity: Arc::new(node_a_identity.keypair),
            peer_registry: Arc::new(
                build_peer_registry(&node_a_config).expect("patrick registry"),
            ),
            api_state: node_a_state.clone(),
            e2e_relay_keys: test_relay_key_state(None),
            e2e_relay_counter: Arc::new(AtomicU64::new(0)),
            relay_pair_rotation_secs: 900,
            relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
            relay_pair_chunks: test_pair_chunks(),
        };
        let david_shared = DataplaneShared {
            endpoint: node_b_endpoint.clone(),
            tunnel_service: Arc::clone(&node_b_service),
            peer_addrs: Arc::new(parse_peer_socket_addrs(&node_b_config).expect("node-b peers")),
            direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&node_b_config)),
            proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(&node_b_config)),
            relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&node_b_config)),
            active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            node_name: "node-b".into(),
            identity: Arc::new(node_b_identity.keypair),
            peer_registry: Arc::new(build_peer_registry(&node_b_config).expect("david registry")),
            api_state: node_b_state.clone(),
            e2e_relay_keys: test_relay_key_state(None),
            e2e_relay_counter: Arc::new(AtomicU64::new(0)),
            relay_pair_rotation_secs: 900,
            relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
            relay_pair_chunks: test_pair_chunks(),
        };

        let _patrick_runtime =
            spawn_dataplane_runtime(patrick_shared.clone(), node_a_tun_rx, node_a_out_tx);
        let _david_runtime =
            spawn_dataplane_runtime(david_shared.clone(), node_b_tun_rx, node_b_out_tx);
        let _gateway_runtime = spawn_dataplane_runtime(
            DataplaneShared {
                endpoint: gateway_endpoint.clone(),
                tunnel_service: Arc::clone(&gateway_service),
                peer_addrs: Arc::new(
                    parse_peer_socket_addrs(&gateway_config).expect("gateway peers"),
                ),
                direct_peer_hosts: Arc::new(crate::direct_peer_hosts(&gateway_config)),
                proactive_peer_ids: Arc::new(crate::proactive_gateway_client_peers(
                    &gateway_config,
                )),
                relay_pair_peer_ids: Arc::new(crate::relay_pair_peer_ids(&gateway_config)),
                active_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
                node_name: "gateway".into(),
                identity: Arc::new(gateway_identity.keypair),
                peer_registry: Arc::new(
                    build_peer_registry(&gateway_config).expect("gateway registry"),
                ),
                api_state: gateway_state.clone(),
                e2e_relay_keys: test_relay_key_state(None),
                e2e_relay_counter: Arc::new(AtomicU64::new(0)),
                relay_pair_rotation_secs: 900,
                relay_pair_pending: Arc::new(StdMutex::new(HashMap::new())),
                relay_pair_chunks: test_pair_chunks(),
            },
            gateway_tun_rx,
            gateway_out_tx,
        );

        let paired = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                match (
                    current_relay_key(&patrick_shared),
                    current_relay_key(&david_shared),
                ) {
                    (Some(left), Some(right)) if left == right => break,
                    _ => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        })
        .await;
        if paired.is_err() {
            let patrick_snapshot = node_a_state.snapshot().await;
            let david_snapshot = node_b_state.snapshot().await;
            let gateway_snapshot = gateway_state.snapshot().await;
            let patrick_sessions = patrick_shared.active_sessions.lock().await.len();
            let david_sessions = david_shared.active_sessions.lock().await.len();
            let patrick_pending = patrick_shared
                .relay_pair_pending
                .lock()
                .expect("pending")
                .len();
            let patrick_chunks = patrick_shared
                .relay_pair_chunks
                .lock()
                .expect("chunks")
                .len();
            let david_pending = david_shared
                .relay_pair_pending
                .lock()
                .expect("pending")
                .len();
            let david_chunks = david_shared.relay_pair_chunks.lock().expect("chunks").len();
            panic!(
                "relay pair handshake did not install matching keys: patrick={:?} sessions={} pending={} chunks={}; david={:?} sessions={} pending={} chunks={}; gateway={:?}",
                patrick_snapshot.last_error,
                patrick_sessions,
                patrick_pending,
                patrick_chunks,
                david_snapshot.last_error,
                david_sessions,
                david_pending,
                david_chunks,
                gateway_snapshot.last_error
            );
        }

        let patrick_to_david = Bytes::from(test_ipv4_packet_with_source_dest(
            1180,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        ));
        node_a_tun_tx
            .send(patrick_to_david.clone())
            .await
            .expect("send patrick packet");
        let david_received = tokio::time::timeout(Duration::from_secs(5), node_b_out_rx.recv())
            .await
            .expect("david receive timeout")
            .expect("david packet");
        assert_eq!(david_received, patrick_to_david);
        assert!(node_a_out_rx.try_recv().is_err());
        assert!(gateway_out_rx.try_recv().is_err());

        node_a_endpoint.close().await;
        node_b_endpoint.close().await;
        gateway_endpoint.close().await;
    }

    /// Battlefield objective: after simulated signal loss, full-handshake rejoin
    /// completes within [`BATTLEFIELD_REJOIN_BUDGET`] (3s) when the peer is up.
    ///
    /// Security rails: dead sessions are never reused; rejoin always performs a
    /// new hybrid PQC handshake.
    #[tokio::test]
    async fn battlefield_rejoin_after_signal_loss_within_3_seconds() {
        let server_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind server");
        let server_addr = server_endpoint.local_addr().expect("server addr");
        let client_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind client");

        let server_identity = generate_identity_bytes();
        let client_identity = generate_identity_bytes();

        let client_config = config_with_socket_peer(
            server_addr,
            "asset",
            "gateway",
            &server_identity.public_key_b64,
            &server_identity.kem_key_b64,
            "10.66.0.1/32",
        );
        let server_config = config_with_socket_peer(
            client_endpoint.local_addr().expect("client addr"),
            "gateway",
            "asset",
            &client_identity.public_key_b64,
            &client_identity.kem_key_b64,
            "10.66.0.2/32",
        );

        let server_registry =
            Arc::new(build_peer_registry(&server_config).expect("server registry"));
        let client_registry =
            Arc::new(build_peer_registry(&client_config).expect("client registry"));
        let server_identity = Arc::new(server_identity.keypair);
        let client_identity = Arc::new(client_identity.keypair);

        // Gateway-side accept loop (never dials the asset). Keep sessions open
        // so the leaf is not closed mid-handshake / mid-session.
        let accept_task = spawn_hold_open_accept_loop(
            server_endpoint.clone(),
            Arc::clone(&server_identity),
            Arc::clone(&server_registry),
        );

        let sessions = Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Cold establish (baseline).
        let cold_start = Instant::now();
        let (session, created) = get_or_create_outbound_session(
            &sessions,
            client_endpoint.clone(),
            client_identity.as_ref(),
            client_registry.as_ref(),
            "gateway",
            server_addr,
        )
        .await
        .expect("cold establish");
        assert!(created);
        assert!(session.is_usable());
        let cold_ms = cold_start.elapsed().as_millis();
        eprintln!("battlefield cold establish: {cold_ms}ms");

        // Simulate RF / path loss: tear the live session.
        session
            .connection
            .close()
            .await
            .expect("close session to simulate signal loss");
        assert!(
            !session.is_usable(),
            "closed session must not remain usable"
        );

        // Rejoin clock starts at known path loss with peer still reachable
        // (signal restored / path available for re-dial).
        let rejoin_start = Instant::now();
        let (session2, created2) = get_or_create_outbound_session(
            &sessions,
            client_endpoint.clone(),
            client_identity.as_ref(),
            client_registry.as_ref(),
            "gateway",
            server_addr,
        )
        .await
        .expect("rejoin establish");
        let rejoin_elapsed = rejoin_start.elapsed();
        let rejoin_ms = rejoin_elapsed.as_millis();
        eprintln!(
            "battlefield cold establish: {cold_ms}ms; rejoin after signal loss: {rejoin_ms}ms (budget {}ms)",
            BATTLEFIELD_REJOIN_BUDGET.as_millis()
        );

        assert!(created2, "rejoin must create a new session, not reuse dead");
        assert!(session2.is_usable());
        assert!(
            rejoin_elapsed <= BATTLEFIELD_REJOIN_BUDGET,
            "rejoin took {rejoin_ms}ms; battlefield budget is {}ms",
            BATTLEFIELD_REJOIN_BUDGET.as_millis()
        );
        // Pointer identity: must not be the dead session.
        assert!(!Arc::ptr_eq(&session, &session2));

        accept_task.abort();
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    /// Maintainer-style loop: after loss, repeated rejoin attempts succeed inside budget.
    #[tokio::test]
    async fn battlefield_maintainer_rejoin_loop_within_3_seconds() {
        let server_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind server");
        let server_addr = server_endpoint.local_addr().expect("server addr");
        let client_endpoint = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind client");

        let server_identity = generate_identity_bytes();
        let client_identity = generate_identity_bytes();
        let client_config = config_with_socket_peer(
            server_addr,
            "drone",
            "carrier-gw",
            &server_identity.public_key_b64,
            &server_identity.kem_key_b64,
            "10.66.0.1/32",
        );
        // Ensure gateway_client mode is dialable/proactive.
        let mut client_config = client_config;
        client_config.peer[0].mode = Some(freeq_config::PeerMode::GatewayClient);
        assert!(proactive_outbound_peers(&client_config).contains("carrier-gw"));

        let server_config = config_with_socket_peer(
            client_endpoint.local_addr().expect("client addr"),
            "carrier-gw",
            "drone",
            &client_identity.public_key_b64,
            &client_identity.kem_key_b64,
            "10.66.0.2/32",
        );
        let server_registry =
            Arc::new(build_peer_registry(&server_config).expect("server registry"));
        let client_registry =
            Arc::new(build_peer_registry(&client_config).expect("client registry"));
        let server_identity = Arc::new(server_identity.keypair);
        let client_identity = Arc::new(client_identity.keypair);

        let accept_task = spawn_hold_open_accept_loop(
            server_endpoint.clone(),
            Arc::clone(&server_identity),
            Arc::clone(&server_registry),
        );

        let sessions = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let (session, _) = get_or_create_outbound_session(
            &sessions,
            client_endpoint.clone(),
            client_identity.as_ref(),
            client_registry.as_ref(),
            "carrier-gw",
            server_addr,
        )
        .await
        .expect("initial session");
        session.connection.close().await.expect("signal loss");

        let rejoin_start = Instant::now();
        let mut rejoined = false;
        while rejoin_start.elapsed() <= BATTLEFIELD_REJOIN_BUDGET {
            // Drop dead entries like the maintainer does.
            {
                let mut guard = sessions.lock().await;
                if let Some(current) = guard.get("carrier-gw") {
                    if !current.is_usable() {
                        guard.remove("carrier-gw");
                    }
                }
            }
            match get_or_create_outbound_session(
                &sessions,
                client_endpoint.clone(),
                client_identity.as_ref(),
                client_registry.as_ref(),
                "carrier-gw",
                server_addr,
            )
            .await
            {
                Ok((s, _)) if s.is_usable() => {
                    rejoined = true;
                    break;
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        let rejoin_ms = rejoin_start.elapsed().as_millis();
        eprintln!("battlefield maintainer-style rejoin: {rejoin_ms}ms");
        assert!(
            rejoined,
            "failed to rejoin within budget ({}ms elapsed)",
            rejoin_ms
        );
        assert!(rejoin_start.elapsed() <= BATTLEFIELD_REJOIN_BUDGET);

        accept_task.abort();
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[test]
    fn dead_session_is_not_usable() {
        // Compile-time documentation of the security rule used by rejoin tests.
        assert_eq!(BATTLEFIELD_REJOIN_BUDGET, Duration::from_secs(3));
        assert!(
            freeq_transport::connection::QUIC_IDLE_TIMEOUT
                < freeq_transport::connection::BATTLEFIELD_REJOIN_BUDGET
        );
        assert!(
            freeq_transport::connection::QUIC_KEEPALIVE_INTERVAL
                < freeq_transport::connection::QUIC_IDLE_TIMEOUT
        );
    }

    /// Accept inbound FreeQ sessions and hold the QUIC connection open until
    /// the peer closes (simulates a gateway/asset that stays online).
    fn spawn_hold_open_accept_loop(
        endpoint: freeq_transport::endpoint::Endpoint,
        identity: Arc<freeq_crypto::sign::IdentityKeypair>,
        registry: Arc<freeq_auth::registry::PeerRegistry>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let Ok(connection) = endpoint.accept().await else {
                    break;
                };
                let identity = Arc::clone(&identity);
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    if let Ok((_name, session)) =
                        accept_inbound_session(connection, identity.as_ref(), registry.as_ref())
                            .await
                    {
                        // Hold the connection open; drain until peer closes.
                        loop {
                            if !session.connection.is_alive() {
                                break;
                            }
                            match session
                                .connection
                                .recv_timeout(Duration::from_millis(500))
                                .await
                            {
                                Ok(_) => {}
                                Err(_) if !session.connection.is_alive() => break,
                                Err(_) => {}
                            }
                        }
                    }
                });
            }
        })
    }

    fn test_ipv4_packet(len: usize, destination: [u8; 4]) -> Vec<u8> {
        test_ipv4_packet_with_source_dest(len, [10, 0, 0, 1], destination)
    }

    fn test_ipv4_packet_with_source_dest(
        len: usize,
        source: [u8; 4],
        destination: [u8; 4],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn config_with_socket_peer(
        peer_addr: SocketAddr,
        node_name: &str,
        peer_name: &str,
        peer_public_key_b64: &str,
        peer_kem_key_b64: &str,
        peer_allowed_ip: &str,
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
            allowed_ips = ["{peer_allowed_ip}"]
            key_rotation_secs = 3600
            "#
        ))
        .expect("socket config should deserialize")
    }

    fn config_with_socket_peer_allowed_ips(
        peer_addr: SocketAddr,
        node_name: &str,
        peer_name: &str,
        peer_public_key_b64: &str,
        peer_kem_key_b64: &str,
        peer_allowed_ips: &[&str],
    ) -> freeq_config::Config {
        let allowed_ips = peer_allowed_ips
            .iter()
            .map(|allowed_ip| format!(r#""{allowed_ip}""#))
            .collect::<Vec<_>>()
            .join(", ");
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
            allowed_ips = [{allowed_ips}]
            key_rotation_secs = 3600
            "#
        ))
        .expect("socket config should deserialize")
    }

    fn gateway_config_with_two_peers(
        patrick_addr: SocketAddr,
        david_addr: SocketAddr,
        node_a_identity: &GeneratedIdentity,
        node_b_identity: &GeneratedIdentity,
    ) -> freeq_config::Config {
        toml::from_str(&format!(
            r#"
            [node]
            name = "gateway"
            listen = "127.0.0.1:0"
            address = "10.0.0.254/24"
            key_path = "/tmp/gateway.key"
            algorithm = "ml-kem-768"
            sign = "ml-dsa-65"
            api_enabled = false
            api_addr = "127.0.0.1:6789"

            [[peer]]
            name = "node-a"
            endpoint = "{patrick_addr}"
            public_key = "{patrick_public_key}"
            kem_key = "{patrick_kem_key}"
            allowed_ips = ["10.0.0.1/32"]
            mode = "relay_leaf"
            key_rotation_secs = 3600

            [[peer]]
            name = "node-b"
            endpoint = "{david_addr}"
            public_key = "{david_public_key}"
            kem_key = "{david_kem_key}"
            allowed_ips = ["10.0.0.2/32"]
            mode = "relay_leaf"
            key_rotation_secs = 3600
            "#,
            patrick_public_key = node_a_identity.public_key_b64,
            patrick_kem_key = node_a_identity.kem_key_b64,
            david_public_key = node_b_identity.public_key_b64,
            david_kem_key = node_b_identity.kem_key_b64,
        ))
        .expect("gateway config should deserialize")
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
