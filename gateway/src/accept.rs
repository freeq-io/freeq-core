//! Inbound leaf acceptance for the FreeQ gateway.
//!
//! # Outbound-only invariant
//!
//! This module only **accepts** connections. It never dials a leaf endpoint.
//! There is no call to [`freeq_transport::endpoint::Endpoint::connect`] in the
//! gateway production path. After a successful hybrid PQC handshake, the
//! authenticated peer name is registered in the session table. Session teardown
//! removes that entry (by generation) so subsequent forward attempts report the
//! leaf offline rather than dialing.
//!
//! # Self-healing
//!
//! The accept path must not die silently:
//! - transient `accept()` errors → log, mark `ACCEPT_DEGRADED`, backoff, retry
//! - sustained accept failures → rebind the listen socket and continue
//! - individual handshake failures → counted + logged; accept loop continues
//! - process only stops on explicit shutdown
//!
//! # Security
//!
//! - Handshakes are deadline-bounded (resource exhaustion defense).
//! - Concurrent handshakes are limited by a semaphore.
//! - Unauthenticated probes are cloaked (counted, not detailed at info).
//! - Peer registry endpoints are stripped so dial metadata cannot leak into
//!   future code paths accidentally.

use crate::session_table::{ActiveSession, NodeId, SessionTable};
use crate::status::{GatewayDiagnostics, GatewayState};
use anyhow::Result;
use base64::Engine as _;
use bytes::Bytes;
use freeq_auth::registry::PeerRegistry;
use freeq_crypto::sign::IdentityKeypair;
use freeq_transport::connection::PeerConnection;
use freeq_transport::endpoint::Endpoint;
use freeq_transport::frame::{chunk_packet_with_id, FrameReassembler, SECURE_QUIC_MTU};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Semaphore};
use tokio::time::{interval, sleep};

const HANDSHAKE_RESPONSE_PACKET_ID: u64 = 1;
const HANDSHAKE_CONFIRM_PACKET_ID: u64 = 3;
const RELAY_MAGIC: &[u8; 4] = b"FQRL";
const RELAY_VERSION: u8 = 1;
const RELAY_HEADER_LEN: usize = 23;

/// Bound hybrid handshake so half-open clients cannot pin tasks forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap concurrent handshake tasks (DoS / resource control).
const MAX_CONCURRENT_HANDSHAKES: usize = 256;

/// How often to reap dead sessions and refresh online node diagnostics.
const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(5);

/// Initial backoff after an accept() error.
const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
/// Maximum backoff between accept retries.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(5);
/// Rebind the listen socket after this many consecutive accept errors.
const REBIND_AFTER_CONSECUTIVE_ACCEPT_ERRORS: u64 = 20;

/// Shared runtime state for the gateway accept path.
pub struct GatewayRuntime {
    /// UDP address we bind for inbound leaf sessions only.
    pub listen_addr: SocketAddr,
    /// Long-term gateway identity used as the handshake responder.
    pub identity: Arc<IdentityKeypair>,
    /// Trusted leaf registry (relay_leaf peers; endpoints stripped).
    pub peer_registry: Arc<PeerRegistry>,
    /// Routes relay-envelope destination IPs to authenticated leaf node IDs.
    pub relay_router: Arc<freeq_tunnel::router::Router>,
    /// Transport envelope helper; never opens a TUN device in this binary.
    pub relay_tunnel: Arc<freeq_tunnel::TunnelInterface>,
    /// Monotonic packet id for gateway-to-leaf transport envelopes.
    pub relay_packet_counter: Arc<AtomicU64>,
    /// Active inbound sessions keyed by authenticated node identity.
    pub sessions: SessionTable,
    /// Process diagnostics and counters.
    pub diagnostics: Arc<GatewayDiagnostics>,
    /// Limits concurrent handshake work.
    pub handshake_limiter: Arc<Semaphore>,
}

/// Run the self-healing accept supervisor until shutdown is signaled.
///
/// Never returns `Ok` after a silent failure: bind/accept problems are logged,
/// reflected in status, and retried (including rebind). Returns only when
/// `shutdown` becomes true.
pub async fn run_accept_supervisor(
    runtime: Arc<GatewayRuntime>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut bind_backoff = ACCEPT_BACKOFF_INITIAL;

    loop {
        if *shutdown.borrow() {
            runtime
                .diagnostics
                .set_state(GatewayState::ShuttingDown, "shutdown signal")
                .await;
            return;
        }

        let endpoint = match Endpoint::bind(runtime.listen_addr).await {
            Ok(endpoint) => {
                bind_backoff = ACCEPT_BACKOFF_INITIAL;
                match endpoint.local_addr() {
                    Ok(addr) => {
                        tracing::info!(
                            %addr,
                            "QUIC endpoint bound (accept-only; never dials leaves)"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "bound endpoint but could not read local_addr");
                    }
                }
                runtime
                    .diagnostics
                    .set_state(
                        GatewayState::Listening,
                        "endpoint bound; accept loop starting",
                    )
                    .await;
                endpoint
            }
            Err(err) => {
                let reason = format!("bind failed on {}: {err}", runtime.listen_addr);
                tracing::error!(
                    listen = %runtime.listen_addr,
                    error = %err,
                    backoff_ms = bind_backoff.as_millis() as u64,
                    "gateway bind failed; will retry (not silent)"
                );
                runtime.diagnostics.record_error(reason.clone()).await;
                runtime
                    .diagnostics
                    .set_state(GatewayState::BindFailed, reason)
                    .await;
                tokio::select! {
                    _ = sleep(bind_backoff) => {}
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            runtime.diagnostics
                                .set_state(GatewayState::ShuttingDown, "shutdown during bind backoff")
                                .await;
                            return;
                        }
                    }
                }
                bind_backoff = (bind_backoff * 2).min(ACCEPT_BACKOFF_MAX);
                continue;
            }
        };

        // Run accept until sustained failure or shutdown. On return we rebind.
        let should_exit = run_accept_loop(Arc::clone(&runtime), endpoint, shutdown.clone()).await;
        if should_exit || *shutdown.borrow() {
            runtime
                .diagnostics
                .set_state(GatewayState::ShuttingDown, "accept supervisor exiting")
                .await;
            return;
        }

        runtime.diagnostics.inc_rebind();
        runtime
            .diagnostics
            .set_state(
                GatewayState::AcceptDegraded,
                "accept path required rebind; self-heal continuing",
            )
            .await;
        let rebinds = runtime.diagnostics.snapshot().await.counters.rebinds;
        tracing::error!(
            rebinds,
            "accept loop ended; rebinding listen socket (self-heal, not silent exit)"
        );
        sleep(ACCEPT_BACKOFF_INITIAL).await;
    }
}

/// Returns `true` if the process should shut down; `false` to rebind and continue.
async fn run_accept_loop(
    runtime: Arc<GatewayRuntime>,
    endpoint: Endpoint,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    let reaper = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            run_session_reaper(runtime, shutdown).await;
        })
    };

    let mut accept_backoff = ACCEPT_BACKOFF_INITIAL;

    loop {
        if *shutdown.borrow() {
            reaper.abort();
            let _ = endpoint.close().await;
            return true;
        }

        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    reaper.abort();
                    let _ = endpoint.close().await;
                    return true;
                }
            }
            accept_result = endpoint.accept() => {
                match accept_result {
                    Ok(connection) => {
                        runtime.diagnostics.inc_accepts_total();
                        accept_backoff = ACCEPT_BACKOFF_INITIAL;
                        if runtime.diagnostics.state().await == GatewayState::AcceptDegraded {
                            runtime.diagnostics
                                .set_state(GatewayState::Listening, "accept recovered")
                                .await;
                        }

                        let permit = match runtime.handshake_limiter.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                let reason = format!(
                                    "handshake concurrency limit reached ({MAX_CONCURRENT_HANDSHAKES}); dropping inbound"
                                );
                                tracing::warn!("{reason}");
                                runtime.diagnostics.inc_handshake_failed();
                                runtime.diagnostics.record_error(reason).await;
                                let _ = connection.close().await;
                                continue;
                            }
                        };

                        let runtime = Arc::clone(&runtime);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(err) = handle_inbound(runtime, connection).await {
                                // handle_inbound records metrics itself
                                let _ = err;
                            }
                        });
                    }
                    Err(err) => {
                        let consecutive = runtime.diagnostics.inc_accept_error();
                        let reason = format!("accept error: {err}");
                        tracing::error!(
                            error = %err,
                            consecutive,
                            backoff_ms = accept_backoff.as_millis() as u64,
                            "gateway accept failed; retrying (not silent, not exiting)"
                        );
                        runtime.diagnostics.record_error(reason.clone()).await;
                        runtime.diagnostics
                            .set_state(GatewayState::AcceptDegraded, reason)
                            .await;

                        if consecutive >= REBIND_AFTER_CONSECUTIVE_ACCEPT_ERRORS {
                            tracing::error!(
                                consecutive,
                                threshold = REBIND_AFTER_CONSECUTIVE_ACCEPT_ERRORS,
                                "sustained accept failures; closing endpoint for rebind"
                            );
                            reaper.abort();
                            let _ = endpoint.close().await;
                            return false; // rebind
                        }

                        tokio::select! {
                            _ = sleep(accept_backoff) => {}
                            _ = shutdown.changed() => {
                                if *shutdown.borrow() {
                                    reaper.abort();
                                    let _ = endpoint.close().await;
                                    return true;
                                }
                            }
                        }
                        accept_backoff = (accept_backoff * 2).min(ACCEPT_BACKOFF_MAX);
                    }
                }
            }
        }
    }
}

async fn handle_inbound(runtime: Arc<GatewayRuntime>, connection: PeerConnection) -> Result<()> {
    // Do not log remote socket address at info for failed probes (metadata minimization).
    let remote = connection.remote_addr();

    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        accept_inbound_session(
            connection,
            runtime.identity.as_ref(),
            runtime.peer_registry.as_ref(),
        ),
    )
    .await;

    let (node_id, session) = match handshake {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => {
            if is_silent_inbound_probe(&err) {
                runtime.diagnostics.inc_cloaked_probe();
                tracing::trace!(error = %err, "cloaked unauthenticated inbound probe");
            } else {
                runtime.diagnostics.inc_handshake_failed();
                let reason = format!("handshake failed: {err}");
                runtime.diagnostics.record_error(reason.clone()).await;
                tracing::warn!(error = %err, "inbound leaf session negotiation failed");
            }
            return Err(err);
        }
        Err(_elapsed) => {
            runtime.diagnostics.inc_handshake_failed();
            let reason = format!("handshake timed out after {}s", HANDSHAKE_TIMEOUT.as_secs());
            runtime.diagnostics.record_error(reason.clone()).await;
            tracing::warn!(
                timeout_secs = HANDSHAKE_TIMEOUT.as_secs(),
                "inbound handshake timed out"
            );
            anyhow::bail!(reason);
        }
    };

    runtime.diagnostics.inc_handshake_ok();
    let generation = session.generation;

    if let Some(previous) = runtime.sessions.insert(node_id.clone(), session).await {
        runtime.diagnostics.inc_session_replaced();
        tracing::info!(
            peer = %node_id,
            previous_generation = previous.generation,
            generation,
            "replaced previous inbound session for leaf"
        );
        let _ = previous.connection.close().await;
    }

    runtime.diagnostics.inc_session_established();
    runtime
        .diagnostics
        .set_online_nodes(runtime.sessions.online_nodes().await)
        .await;

    let online = runtime.sessions.len().await;
    tracing::info!(
        peer = %node_id,
        generation,
        remote = %remote,
        online,
        "inbound leaf session established"
    );

    let Some(session) = runtime.sessions.get(&node_id).await else {
        let reason = format!("session disappeared immediately after insert for {node_id}");
        runtime.diagnostics.record_error(reason.clone()).await;
        tracing::error!("{reason}");
        anyhow::bail!(reason);
    };

    // Ensure we still watch the generation we just installed.
    if session.generation != generation {
        tracing::info!(
            peer = %node_id,
            expected = generation,
            actual = session.generation,
            "newer session already replaced this one; watcher exiting"
        );
        return Ok(());
    }

    watch_session(runtime, node_id, session).await;
    Ok(())
}

/// Wait until the leaf connection ends, then remove it from the session table.
async fn watch_session(runtime: Arc<GatewayRuntime>, node_id: NodeId, session: Arc<ActiveSession>) {
    let generation = session.generation;

    let mut reassembler = FrameReassembler::default();
    loop {
        if !session.is_alive() {
            break;
        }
        match session
            .connection
            .recv_timeout(Duration::from_secs(30))
            .await
        {
            Ok(_datagram) => {
                session.touch();
                runtime.diagnostics.inc_datagram_received();
                let packet = match reassembler.push_frame(&_datagram) {
                    Ok(Some(packet)) => packet,
                    Ok(None) => continue,
                    Err(err) => {
                        runtime
                            .diagnostics
                            .record_error(format!("failed to reassemble relay frame: {err}"))
                            .await;
                        tracing::warn!(error = %err, "failed to reassemble relay frame");
                        continue;
                    }
                };
                forward_leaf_payload(&runtime, &node_id, generation, &session, packet).await;
            }
            Err(err) => {
                if !session.is_alive() {
                    break;
                }
                // TransportError::Timeout displays as "transport operation timed out"
                if matches!(err, freeq_transport::TransportError::Timeout)
                    || err.to_string().contains("timed out")
                {
                    continue;
                }
                tracing::info!(
                    peer = %node_id,
                    generation,
                    error = %err,
                    "leaf session receive ended"
                );
                break;
            }
        }
    }

    if let Some(removed) = runtime
        .sessions
        .remove_if_generation(&node_id, generation)
        .await
    {
        let _ = removed.connection.close().await;
        runtime.diagnostics.inc_session_removed();
        runtime
            .diagnostics
            .set_online_nodes(runtime.sessions.online_nodes().await)
            .await;
        let online = runtime.sessions.len().await;
        tracing::info!(
            peer = %node_id,
            generation,
            online,
            "leaf session removed (closed or timed out)"
        );
    } else {
        tracing::debug!(
            peer = %node_id,
            generation,
            "session already replaced or removed; stale watcher done"
        );
    }
}

async fn forward_leaf_payload(
    runtime: &GatewayRuntime,
    source_node: &str,
    source_generation: u64,
    source_session: &ActiveSession,
    transport_payload: Bytes,
) {
    let relay_payload = match runtime.relay_tunnel.receive_transport_payload_with_session(
        transport_payload.as_ref(),
        &source_session.inbound_key,
    ) {
        Ok(payload) => payload,
        Err(err) => {
            runtime
                .diagnostics
                .record_error(format!(
                    "failed to decrypt inbound relay payload from {source_node}: {err}"
                ))
                .await;
            tracing::warn!(
                peer = %source_node,
                generation = source_generation,
                error = %err,
                "failed to decrypt inbound relay payload"
            );
            return;
        }
    };

    let Some(envelope) = parse_relay_envelope(&relay_payload) else {
        runtime
            .diagnostics
            .record_error(format!(
                "non-relay payload received from {source_node}; dropped"
            ))
            .await;
        tracing::warn!(
            peer = %source_node,
            generation = source_generation,
            "dropped non-relay payload on gateway leaf session"
        );
        return;
    };

    let Some(destination_node) = runtime
        .relay_router
        .lookup(IpAddr::V4(envelope.destination))
        .map(str::to_string)
    else {
        runtime.diagnostics.inc_remote_leaf_offline_drop();
        runtime
            .diagnostics
            .record_error(format!(
                "remote leaf offline: no configured route to {}",
                envelope.destination
            ))
            .await;
        tracing::warn!(
            peer = %source_node,
            destination = %envelope.destination,
            "remote leaf offline: no configured route"
        );
        return;
    };

    if destination_node == source_node {
        runtime
            .diagnostics
            .record_error(format!(
                "dropping relay loop from {source_node} to {}",
                envelope.destination
            ))
            .await;
        tracing::warn!(
            peer = %source_node,
            destination = %envelope.destination,
            "dropped relay loop back to source leaf"
        );
        return;
    }

    let Some(destination_session) = runtime.sessions.get(&destination_node).await else {
        runtime.diagnostics.inc_remote_leaf_offline_drop();
        runtime
            .diagnostics
            .record_error(format!(
                "remote leaf offline: {destination_node} not connected"
            ))
            .await;
        tracing::warn!(
            peer = %source_node,
            destination_peer = %destination_node,
            destination = %envelope.destination,
            "remote leaf offline"
        );
        return;
    };

    if !destination_session.is_alive() {
        runtime.diagnostics.inc_remote_leaf_offline_drop();
        runtime
            .diagnostics
            .record_error(format!(
                "remote leaf offline: {destination_node} session not alive"
            ))
            .await;
        tracing::warn!(
            peer = %source_node,
            destination_peer = %destination_node,
            destination = %envelope.destination,
            "remote leaf session not alive"
        );
        return;
    }

    let prepared = match runtime.relay_tunnel.prepare_transport_payload_with_session(
        relay_payload.as_ref(),
        &destination_session.outbound_key,
        runtime.relay_packet_counter.fetch_add(1, Ordering::Relaxed),
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            runtime
                .diagnostics
                .record_error(format!(
                    "failed to prepare relay payload for {destination_node}: {err}"
                ))
                .await;
            tracing::warn!(
                peer = %source_node,
                destination_peer = %destination_node,
                error = %err,
                "failed to prepare outbound relay payload"
            );
            return;
        }
    };

    for frame in prepared.frames {
        if let Err(err) = destination_session.connection.send(frame).await {
            runtime
                .diagnostics
                .record_error(format!(
                    "failed to forward relay payload to {destination_node}: {err}"
                ))
                .await;
            tracing::warn!(
                peer = %source_node,
                destination_peer = %destination_node,
                error = %err,
                "failed to forward relay payload"
            );
            return;
        }
    }

    tracing::trace!(
        peer = %source_node,
        destination_peer = %destination_node,
        destination = %envelope.destination,
        "forwarded opaque relay payload"
    );
}

struct RelayEnvelope {
    destination: Ipv4Addr,
}

fn parse_relay_envelope(packet: &[u8]) -> Option<RelayEnvelope> {
    if packet.len() < RELAY_HEADER_LEN || &packet[0..4] != RELAY_MAGIC || packet[4] != RELAY_VERSION
    {
        return None;
    }
    Some(RelayEnvelope {
        destination: Ipv4Addr::new(packet[17], packet[18], packet[19], packet[20]),
    })
}

async fn run_session_reaper(runtime: Arc<GatewayRuntime>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = interval(SESSION_REAP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = tick.tick() => {
                let dead = runtime.sessions.reap_dead().await;
                if !dead.is_empty() {
                    for (node_id, generation) in &dead {
                        runtime.diagnostics.inc_session_reaped();
                        runtime.diagnostics.inc_session_removed();
                        tracing::info!(
                            peer = %node_id,
                            generation,
                            "reaped dead leaf session"
                        );
                    }
                    runtime
                        .diagnostics
                        .set_online_nodes(runtime.sessions.online_nodes().await)
                        .await;
                } else {
                    // Keep status online_nodes fresh even when no reaps.
                    runtime
                        .diagnostics
                        .set_online_nodes(runtime.sessions.online_nodes().await)
                        .await;
                }
            }
        }
    }
}

async fn accept_inbound_session(
    connection: PeerConnection,
    identity: &IdentityKeypair,
    peer_registry: &PeerRegistry,
) -> Result<(NodeId, ActiveSession)> {
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
        peer_name.clone(),
        ActiveSession::new(peer_name, connection, keys.outbound, keys.inbound),
    ))
}

async fn send_handshake_message(
    connection: &PeerConnection,
    packet_id: u64,
    message: Vec<u8>,
) -> Result<()> {
    let frames = chunk_packet_with_id(packet_id, &message, SECURE_QUIC_MTU)?;
    for frame in frames {
        connection.send(frame).await?;
    }
    Ok(())
}

async fn recv_handshake_message(connection: &PeerConnection) -> Result<Bytes> {
    let mut reassembler = FrameReassembler::default();
    loop {
        let frame = connection.recv().await?;
        if let Some(message) = reassembler.push_frame(frame.as_ref())? {
            return Ok(message);
        }
    }
}

fn is_silent_inbound_probe(err: &anyhow::Error) -> bool {
    // freeq-auth cloaking errors — do not treat as operational failures.
    if err
        .downcast_ref::<freeq_auth::AuthError>()
        .is_some_and(|e| {
            matches!(
                e,
                freeq_auth::AuthError::Cloaked | freeq_auth::AuthError::UnknownPeer(_)
            )
        })
    {
        return true;
    }
    let msg = err.to_string();
    msg.contains("cloaking active")
        || msg.contains("unauthenticated packet dropped")
        || msg.contains("unknown peer")
}

/// Build a peer registry from gateway config (all peers are trusted leaves).
///
/// **Endpoints are deliberately stripped.** The gateway must never dial leaves;
/// keeping dial targets out of the registry reduces the chance of accidental
/// misuse in future code.
pub fn build_peer_registry(config: &freeq_config::Config) -> Result<PeerRegistry> {
    let mut registry = PeerRegistry::new();
    for peer in &config.peer {
        // Defense in depth: refuse dialable peers even if validate_for_gateway was skipped.
        if peer.is_dialable() {
            anyhow::bail!(
                "gateway peer '{}' is dialable (mode={:?}); gateway must never dial leaves",
                peer.name,
                peer.effective_mode()
            );
        }
        if peer.effective_mode() != freeq_config::PeerMode::RelayLeaf {
            anyhow::bail!(
                "gateway peer '{}' must be mode=relay_leaf, got {:?}",
                peer.name,
                peer.effective_mode()
            );
        }

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
                cidr.parse::<ipnetwork::IpNetwork>().map_err(|err| {
                    anyhow::anyhow!(
                        "invalid allowed_ips entry '{}' for '{}': {err}",
                        cidr,
                        peer.name
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;

        if peer.endpoint.is_some() {
            tracing::debug!(
                peer = %peer.name,
                "ignoring documentation-only endpoint on relay_leaf (gateway never dials)"
            );
        }

        registry.add_peer(freeq_auth::registry::PeerEntry {
            name: peer.name.clone(),
            identity_pubkey,
            kem_pubkey,
            // STRIPPED: never store leaf endpoints on the gateway.
            endpoint: None,
            allowed_ips,
        })?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::{
        build_peer_registry, parse_relay_envelope, RELAY_HEADER_LEN, RELAY_MAGIC, RELAY_VERSION,
    };
    use base64::Engine as _;
    use freeq_config::{Config, PeerMode};

    fn sample_gateway_config(mode: PeerMode, endpoint: Option<&str>) -> Config {
        let mut rng = rand::thread_rng();
        let (identity, public_key) =
            freeq_crypto::sign::IdentityKeypair::generate(&mut rng).expect("identity");
        let _ = identity;
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(public_key.to_bytes());
        // KEM bytes are stored opaquely in the registry for later encapsulation.
        let kem_key_b64 = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let endpoint_line = match endpoint {
            Some(ep) => format!("endpoint = \"{ep}\""),
            None => String::new(),
        };
        let mode_str = match mode {
            PeerMode::Direct => "direct",
            PeerMode::GatewayClient => "gateway_client",
            PeerMode::RelayLeaf => "relay_leaf",
        };
        let raw = format!(
            r#"
            [node]
            name = "gw-1"
            listen = "127.0.0.1:0"
            address = "10.66.0.1/24"
            key_path = "/tmp/freeq-gateway-test.key"
            algorithm = "ml-kem-768"
            sign = "ml-dsa-65"
            api_enabled = false
            api_addr = "127.0.0.1:6790"

            [[peer]]
            name = "leaf-a"
            public_key = "{public_key_b64}"
            kem_key = "{kem_key_b64}"
            mode = "{mode_str}"
            allowed_ips = ["10.66.0.2/32"]
            {endpoint_line}
            "#
        );
        toml::from_str(&raw).expect("parse")
    }

    #[test]
    fn registry_strips_endpoints_for_relay_leaves() {
        let config = sample_gateway_config(PeerMode::RelayLeaf, Some("203.0.113.9:51820"));
        config.validate_for_gateway().expect("gateway validate");
        let registry = build_peer_registry(&config).expect("registry");
        let peer = registry.get_peer("leaf-a").expect("peer");
        assert!(peer.endpoint.is_none(), "gateway must strip leaf endpoints");
    }

    #[test]
    fn registry_rejects_direct_peers() {
        let mut config = sample_gateway_config(PeerMode::Direct, Some("203.0.113.9:51820"));
        config.peer[0].mode = Some(PeerMode::Direct);
        match build_peer_registry(&config) {
            Ok(_) => panic!("must reject direct peers"),
            Err(err) => {
                assert!(
                    err.to_string().contains("relay_leaf") || err.to_string().contains("dialable")
                );
            }
        }
    }

    #[test]
    fn relay_envelope_destination_routes_to_relay_leaf() {
        let config = sample_gateway_config(PeerMode::RelayLeaf, Some("203.0.113.9:51820"));
        config.validate_for_gateway().expect("gateway validate");

        let mut router = freeq_tunnel::router::Router::new();
        for peer in &config.peer {
            for prefix in &peer.allowed_ips {
                router.insert(prefix.parse().expect("prefix"), peer.name.clone());
            }
        }

        let mut envelope = vec![0u8; RELAY_HEADER_LEN + freeq_crypto::bulk::TAG_LEN];
        envelope[0..4].copy_from_slice(RELAY_MAGIC);
        envelope[4] = RELAY_VERSION;
        envelope[17..21].copy_from_slice(&[10, 66, 0, 2]);
        envelope[21..23].copy_from_slice(&1180u16.to_be_bytes());

        let parsed = parse_relay_envelope(&envelope).expect("relay envelope");
        assert_eq!(parsed.destination, std::net::Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(
            router.lookup(std::net::IpAddr::V4(parsed.destination)),
            Some("leaf-a")
        );
    }

    #[test]
    fn relay_envelope_parser_rejects_non_relay_payloads() {
        assert!(parse_relay_envelope(b"not a relay envelope").is_none());

        let mut bad_version = vec![0u8; RELAY_HEADER_LEN + freeq_crypto::bulk::TAG_LEN];
        bad_version[0..4].copy_from_slice(RELAY_MAGIC);
        bad_version[4] = RELAY_VERSION + 1;
        assert!(parse_relay_envelope(&bad_version).is_none());
    }
}
