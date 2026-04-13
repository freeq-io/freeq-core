//! Packet forwarding between routed IP packets and encrypted peer tunnels.

use crate::{Result, TunnelError};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const NONCE_COUNTER_LEN: usize = 8;

/// Forwards packets using the configured router, transport connection, and session keys.
pub struct TunnelEngine {
    algorithm: freeq_crypto::agility::BulkAlgorithm,
    router: RwLock<crate::router::Router>,
    peers: RwLock<HashMap<String, Arc<PeerSession>>>,
    next_generation: AtomicU64,
}

struct PeerSession {
    generation: u64,
    connection: Arc<freeq_transport::connection::PeerConnection>,
    outbound_key: [u8; 32],
    inbound_key: [u8; 32],
    outbound_nonce: AtomicU64,
}

impl TunnelEngine {
    /// Create a new forwarding engine.
    pub fn new(
        algorithm: freeq_crypto::agility::BulkAlgorithm,
        router: crate::router::Router,
    ) -> Self {
        Self {
            algorithm,
            router: RwLock::new(router),
            peers: RwLock::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
        }
    }

    /// Register or replace a peer session used for routing and encryption.
    pub fn add_peer(
        &self,
        peer_id: String,
        connection: Arc<freeq_transport::connection::PeerConnection>,
        session_keys: &freeq_auth::handshake::SessionKeys,
    ) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.peers
            .write()
            .expect("peer registry lock poisoned")
            .insert(
                peer_id,
                Arc::new(PeerSession {
                    generation,
                    connection,
                    outbound_key: session_keys.outbound,
                    inbound_key: session_keys.inbound,
                    outbound_nonce: AtomicU64::new(0),
                }),
            );
        generation
    }

    /// Remove an active peer session.
    pub fn remove_session(&self, peer_id: &str) {
        self.peers
            .write()
            .expect("peer registry lock poisoned")
            .remove(peer_id);
    }

    /// Remove a session only if it still matches the expected generation.
    pub fn remove_session_if_current(&self, peer_id: &str, generation: u64) {
        let mut peers = self.peers.write().expect("peer registry lock poisoned");
        let should_remove = peers
            .get(peer_id)
            .map(|peer| peer.generation == generation)
            .unwrap_or(false);
        if should_remove {
            peers.remove(peer_id);
        }
    }

    /// Remove an active peer session and all routes for that peer.
    pub fn remove_peer(&self, peer_id: &str) {
        self.remove_session(peer_id);
        self.router
            .write()
            .expect("router lock poisoned")
            .remove_peer(peer_id);
    }

    /// Add a routing prefix for a peer.
    pub fn add_route(&self, prefix: ipnetwork::IpNetwork, peer_id: String) {
        self.router
            .write()
            .expect("router lock poisoned")
            .insert(prefix, peer_id);
    }

    /// Encrypt and forward a raw IP packet to its routed peer.
    pub async fn forward_packet(&self, packet: Bytes) -> Result<String> {
        let dest = destination_ip(&packet)?;
        let peer_id = self
            .router
            .read()
            .expect("router lock poisoned")
            .lookup(dest)
            .map(str::to_owned)
            .ok_or(TunnelError::NoRoute { dest })?;
        let peer = self
            .peers
            .read()
            .expect("peer registry lock poisoned")
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| TunnelError::UnknownPeer(peer_id.clone()))?;

        let nonce = next_nonce(&peer.outbound_nonce);
        let ciphertext =
            freeq_crypto::bulk::encrypt(&self.algorithm, &peer.outbound_key, &nonce, &[], &packet)?;
        let mut frame = Vec::with_capacity(freeq_crypto::bulk::NONCE_LEN + ciphertext.len());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        if let Err(err) = peer.connection.send(Bytes::from(frame)).await {
            self.remove_session_if_current(&peer_id, peer.generation);
            return Err(err.into());
        }

        Ok(peer_id)
    }

    /// Receive and decrypt the next packet from `peer_id`.
    pub async fn receive_packet(&self, peer_id: &str, expected_generation: u64) -> Result<Bytes> {
        let peer = self
            .peers
            .read()
            .expect("peer registry lock poisoned")
            .get(peer_id)
            .cloned()
            .ok_or_else(|| TunnelError::UnknownPeer(peer_id.to_string()))?;
        if peer.generation != expected_generation {
            return Err(TunnelError::StaleSession(peer_id.to_string()));
        }
        let frame = peer.connection.recv().await?;
        if !self.is_current_generation(peer_id, expected_generation) {
            return Err(TunnelError::StaleSession(peer_id.to_string()));
        }

        if frame.len() <= freeq_crypto::bulk::NONCE_LEN {
            return Err(TunnelError::InvalidPacket(
                "encrypted frame is missing a ciphertext body".into(),
            ));
        }

        let nonce: [u8; freeq_crypto::bulk::NONCE_LEN] = frame[..freeq_crypto::bulk::NONCE_LEN]
            .try_into()
            .map_err(|_| TunnelError::InvalidPacket("invalid AEAD nonce".into()))?;
        let plaintext = freeq_crypto::bulk::decrypt(
            &self.algorithm,
            &peer.inbound_key,
            &nonce,
            &[],
            &frame[freeq_crypto::bulk::NONCE_LEN..],
        )?;
        Ok(Bytes::from(plaintext))
    }

    fn is_current_generation(&self, peer_id: &str, expected_generation: u64) -> bool {
        self.peers
            .read()
            .expect("peer registry lock poisoned")
            .get(peer_id)
            .map(|peer| peer.generation == expected_generation)
            .unwrap_or(false)
    }
}

fn next_nonce(counter: &AtomicU64) -> [u8; freeq_crypto::bulk::NONCE_LEN] {
    let value = counter.fetch_add(1, Ordering::Relaxed);
    let mut nonce = [0u8; freeq_crypto::bulk::NONCE_LEN];
    nonce[freeq_crypto::bulk::NONCE_LEN - NONCE_COUNTER_LEN..]
        .copy_from_slice(&value.to_be_bytes());
    nonce
}

fn destination_ip(packet: &[u8]) -> Result<IpAddr> {
    let version = packet
        .first()
        .map(|byte| byte >> 4)
        .ok_or_else(|| TunnelError::InvalidPacket("empty IP packet".into()))?;

    match version {
        4 => parse_ipv4_destination(packet),
        6 => parse_ipv6_destination(packet),
        _ => Err(TunnelError::InvalidPacket(format!(
            "unsupported IP version nibble: {version}"
        ))),
    }
}

fn parse_ipv4_destination(packet: &[u8]) -> Result<IpAddr> {
    if packet.len() < 20 {
        return Err(TunnelError::InvalidPacket(
            "IPv4 packet shorter than minimum header".into(),
        ));
    }

    let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok(IpAddr::V4(dest))
}

fn parse_ipv6_destination(packet: &[u8]) -> Result<IpAddr> {
    if packet.len() < 40 {
        return Err(TunnelError::InvalidPacket(
            "IPv6 packet shorter than minimum header".into(),
        ));
    }

    let dest: [u8; 16] = packet[24..40]
        .try_into()
        .map_err(|_| TunnelError::InvalidPacket("invalid IPv6 destination".into()))?;
    Ok(IpAddr::V6(Ipv6Addr::from(dest)))
}

#[cfg(test)]
mod tests {
    use super::TunnelEngine;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn sample_ipv4_packet(dest: Ipv4Addr) -> Bytes {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&dest.octets());
        Bytes::copy_from_slice(&packet)
    }

    fn sample_session_keys() -> freeq_auth::handshake::SessionKeys {
        freeq_auth::handshake::SessionKeys {
            outbound: [0x11; 32],
            inbound: [0x22; 32],
        }
    }

    #[tokio::test]
    async fn forwarding_engine_encrypts_routes_and_decrypts_packets() {
        let server = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        let server_fingerprint = server.certificate_fingerprint();
        let client = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind client");

        let server_conn_task = {
            let server = server.clone();
            tokio::spawn(async move { Arc::new(server.accept().await.expect("accept")) })
        };
        let client_conn = Arc::new(
            client
                .connect(&server_fingerprint, server_addr)
                .await
                .expect("connect"),
        );
        let server_conn = server_conn_task.await.expect("server task");

        let mut client_router = crate::router::Router::new();
        client_router.insert("10.0.0.0/24".parse().expect("prefix"), "peer-a".into());
        let client_engine = TunnelEngine::new(
            freeq_crypto::agility::BulkAlgorithm::ChaCha20Poly1305,
            client_router,
        );
        let _client_generation =
            client_engine.add_peer("peer-a".into(), client_conn.clone(), &sample_session_keys());

        let server_engine = TunnelEngine::new(
            freeq_crypto::agility::BulkAlgorithm::ChaCha20Poly1305,
            crate::router::Router::new(),
        );
        let reverse_keys = freeq_auth::handshake::SessionKeys {
            outbound: [0x22; 32],
            inbound: [0x11; 32],
        };
        let server_generation =
            server_engine.add_peer("peer-a".into(), server_conn.clone(), &reverse_keys);

        let payload = sample_ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        let routed_peer = client_engine
            .forward_packet(payload.clone())
            .await
            .expect("forward");
        let received = server_engine
            .receive_packet("peer-a", server_generation)
            .await
            .expect("receive");

        assert_eq!(routed_peer, "peer-a");
        assert_eq!(received, payload);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn forwarding_engine_rejects_unrouted_packets() {
        let engine = TunnelEngine::new(
            freeq_crypto::agility::BulkAlgorithm::Aes256Gcm,
            crate::router::Router::new(),
        );
        let err = engine
            .forward_packet(sample_ipv4_packet(Ipv4Addr::new(10, 0, 0, 42)))
            .await
            .expect_err("missing route should fail");

        assert!(matches!(err, crate::TunnelError::NoRoute { .. }));
    }

    #[tokio::test]
    async fn receive_packet_rejects_stale_session_generation() {
        let server = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        let server_fingerprint = server.certificate_fingerprint();
        let client = freeq_transport::endpoint::Endpoint::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("bind client");

        let server_conn_task = {
            let server = server.clone();
            tokio::spawn(async move { Arc::new(server.accept().await.expect("accept")) })
        };
        let client_conn = Arc::new(
            client
                .connect(&server_fingerprint, server_addr)
                .await
                .expect("connect"),
        );
        let server_conn = server_conn_task.await.expect("server task");

        let engine = TunnelEngine::new(
            freeq_crypto::agility::BulkAlgorithm::ChaCha20Poly1305,
            crate::router::Router::new(),
        );
        let first_generation =
            engine.add_peer("peer-a".into(), server_conn.clone(), &sample_session_keys());
        let second_generation =
            engine.add_peer("peer-a".into(), client_conn.clone(), &sample_session_keys());

        let err = engine
            .receive_packet("peer-a", first_generation)
            .await
            .expect_err("stale session should fail");

        assert!(matches!(
            err,
            crate::TunnelError::StaleSession(ref peer) if peer == "peer-a"
        ));
        assert!(second_generation > first_generation);

        client.close().await;
        server.close().await;
    }
}
