//! Shared tunnel service for daemon ingress and benchmark harnesses.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use crate::packet::parse_ipv4_header;
use crate::pipeline::PreparedTransportPacket;
use crate::router::Router;
use crate::{Result, TunnelConfig, TunnelError, TunnelInterface};

/// One successful packet ingest through the tunnel service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIngestReport {
    /// Routed peer identifier chosen for the destination IP.
    pub peer_id: String,
    /// Original packet length.
    pub packet_len: usize,
    /// Encrypted packet length.
    pub encrypted_len: usize,
    /// Number of emitted transport frames.
    pub frames_emitted: usize,
}

/// One packet prepared for transport transmission to a routed peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPeerPacket {
    /// Routed peer identifier chosen for the destination IP.
    pub peer_id: String,
    /// Original packet length.
    pub packet_len: usize,
    /// Encrypted packet length.
    pub encrypted_len: usize,
    /// Number of emitted transport frames.
    pub frames_emitted: usize,
    /// QUIC datagram frames ready to send.
    pub frames: Vec<Bytes>,
}

/// Snapshot of tunnel service counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelServiceStats {
    /// Successfully ingested packet count.
    pub packets_ingested: u64,
    /// Encrypted bytes emitted by the tunnel pipeline.
    pub bytes_encrypted: u64,
    /// QUIC-sized frames emitted by transport framing.
    pub frames_emitted: u64,
    /// Route misses rejected before encryption.
    pub route_misses: u64,
    /// Packets rejected as structurally malformed.
    pub malformed_packet_errors: u64,
    /// Packets rejected during crypto processing.
    pub crypto_errors: u64,
    /// Packets rejected during transport framing or sending.
    pub transport_errors: u64,
}

/// Reusable service wrapper over packet routing and tunnel processing.
pub struct TunnelService {
    tunnel: TunnelInterface,
    router: Router,
    route_misses: AtomicU64,
    malformed_packet_errors: AtomicU64,
    crypto_errors: AtomicU64,
    transport_errors: AtomicU64,
}

impl TunnelService {
    /// Create a service from a tunnel pipeline and router.
    pub fn new(tunnel: TunnelInterface, router: Router) -> Self {
        Self {
            tunnel,
            router,
            route_misses: AtomicU64::new(0),
            malformed_packet_errors: AtomicU64::new(0),
            crypto_errors: AtomicU64::new(0),
            transport_errors: AtomicU64::new(0),
        }
    }

    /// Ingest a packet and route it through the tunnel pipeline.
    pub async fn ingest_packet(&self, packet: Bytes) -> Result<ServiceIngestReport> {
        let prepared = self.prepare_peer_packet(packet)?;
        consume_prepared_frames(&prepared.frames).await?;

        Ok(ServiceIngestReport {
            peer_id: prepared.peer_id,
            packet_len: prepared.packet_len,
            encrypted_len: prepared.encrypted_len,
            frames_emitted: prepared.frames_emitted,
        })
    }

    /// Prepare a packet for transport transmission to the routed peer.
    pub fn prepare_peer_packet(&self, packet: Bytes) -> Result<PreparedPeerPacket> {
        let session_key = self.tunnel.test_session_key();
        let packet_id = self.tunnel.next_packet_id();
        self.prepare_peer_packet_with_session(packet, &session_key, packet_id)
    }

    /// Prepare a packet for transport transmission to the routed peer using an explicit session key.
    pub fn prepare_peer_packet_with_session(
        &self,
        packet: Bytes,
        session_key: &[u8; 32],
        packet_id: u64,
    ) -> Result<PreparedPeerPacket> {
        let header = parse_ipv4_header(packet.as_ref())?;
        let destination = IpAddr::V4(header.destination);
        let Some(peer_id) = self.router.lookup(destination) else {
            self.route_misses.fetch_add(1, Ordering::Relaxed);
            return Err(TunnelError::NoRoute { dest: destination });
        };

        let PreparedTransportPacket {
            packet_len,
            encrypted_len,
            frames,
            ..
        } = match self.tunnel.prepare_transport_packet_with_session(
            packet.as_ref(),
            session_key,
            packet_id,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                match &err {
                    TunnelError::BufferUnderflow | TunnelError::MalformedPacket(_) => {
                        self.malformed_packet_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    TunnelError::Crypto(_) => {
                        self.crypto_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    TunnelError::Transport(_) => {
                        self.transport_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    TunnelError::Interface(_)
                    | TunnelError::Io(_)
                    | TunnelError::NoRoute { .. } => {}
                }
                return Err(err);
            }
        };

        Ok(PreparedPeerPacket {
            peer_id: peer_id.to_string(),
            packet_len,
            encrypted_len,
            frames_emitted: frames.len(),
            frames,
        })
    }

    /// Decrypt one reassembled transport payload back into an L3 packet.
    pub fn receive_transport_packet(&self, packet: Bytes) -> Result<Bytes> {
        let session_key = self.tunnel.test_session_key();
        self.receive_transport_packet_with_session(packet, &session_key)
    }

    /// Decrypt one reassembled transport payload back into an L3 packet using an explicit session key.
    pub fn receive_transport_packet_with_session(
        &self,
        packet: Bytes,
        session_key: &[u8; 32],
    ) -> Result<Bytes> {
        match self
            .tunnel
            .receive_transport_packet_with_session(packet.as_ref(), session_key)
        {
            Ok(plaintext) => Ok(plaintext),
            Err(err) => {
                match &err {
                    TunnelError::BufferUnderflow | TunnelError::MalformedPacket(_) => {
                        self.malformed_packet_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    TunnelError::Crypto(_) => {
                        self.crypto_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    TunnelError::Transport(_) => {
                        self.transport_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    TunnelError::Interface(_)
                    | TunnelError::Io(_)
                    | TunnelError::NoRoute { .. } => {}
                }
                Err(err)
            }
        }
    }

    /// Return a snapshot of accumulated service counters.
    pub fn stats(&self) -> TunnelServiceStats {
        TunnelServiceStats {
            packets_ingested: self.tunnel.packets_processed(),
            bytes_encrypted: self.tunnel.bytes_processed(),
            frames_emitted: self.tunnel.transport_frames(),
            route_misses: self.route_misses.load(Ordering::Relaxed),
            malformed_packet_errors: self.malformed_packet_errors.load(Ordering::Relaxed),
            crypto_errors: self.crypto_errors.load(Ordering::Relaxed),
            transport_errors: self.transport_errors.load(Ordering::Relaxed),
        }
    }

    /// Access the configured interface metadata.
    pub fn interface_config(&self) -> &TunnelConfig {
        self.tunnel.config()
    }

    /// Resolve a destination IP to a configured peer identifier.
    pub fn resolve_peer(&self, destination: IpAddr) -> Option<&str> {
        self.router.lookup(destination)
    }
}

async fn consume_prepared_frames(frames: &[Bytes]) -> Result<()> {
    for frame in frames {
        if frame.is_empty() {
            return Err(TunnelError::MalformedPacket("empty transport frame".into()));
        }
        tokio::task::yield_now().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::TunnelService;
    use crate::router::Router;
    use crate::{TunnelConfig, TunnelError, TunnelInterface};
    use bytes::Bytes;
    use freeq_crypto::FreeQKeyPair;

    #[tokio::test]
    async fn ingest_packet_routes_to_peer_and_reports_stats() {
        let service = build_service();
        let packet = Bytes::from(test_ipv4_packet(1180, [10, 0, 0, 9]));

        let report = service.ingest_packet(packet).await.expect("ingest packet");

        assert_eq!(report.peer_id, "peer-a");
        assert_eq!(report.packet_len, 1180);
        assert!(report.frames_emitted >= 2);
        assert_eq!(service.stats().packets_ingested, 1);
    }

    #[tokio::test]
    async fn ingest_packet_rejects_route_miss() {
        let service = build_service();
        let packet = Bytes::from(test_ipv4_packet(1180, [10, 1, 0, 9]));

        let err = service
            .ingest_packet(packet)
            .await
            .expect_err("route miss should fail");

        assert!(matches!(err, TunnelError::NoRoute { .. }));
        assert_eq!(service.stats().route_misses, 1);
    }

    #[tokio::test]
    async fn ingest_packet_rejects_over_mtu() {
        let service = build_service();
        let packet = Bytes::from(test_ipv4_packet(1300, [10, 0, 0, 9]));

        let err = service
            .ingest_packet(packet)
            .await
            .expect_err("over mtu should fail");

        assert!(matches!(err, TunnelError::MalformedPacket(_)));
    }

    fn build_service() -> TunnelService {
        let keys = FreeQKeyPair::generate_ephemeral_test_pair().expect("keys");
        let tunnel = TunnelInterface::new(
            TunnelConfig {
                interface_name: "freeqsvc0".into(),
                mtu: 1200,
            },
            keys,
        )
        .expect("tunnel");
        let mut router = Router::new();
        router.insert("10.0.0.0/24".parse().expect("prefix"), "peer-a".into());

        TunnelService::new(tunnel, router)
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
}
