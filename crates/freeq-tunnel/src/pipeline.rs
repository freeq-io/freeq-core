//! High-level packet processing pipeline for benchmarks and future TUN integration.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use freeq_crypto::agility::AlgorithmSuite;
use freeq_crypto::{bulk, combine_secrets, FreeQKeyPair};

use crate::packet::parse_ipv4_header;
use crate::{Result, TunnelError};

const TRANSPORT_AAD_CONTEXT: &[u8] = b"freeq-tunnel/v1";

/// Operational tunnel processing configuration.
pub struct TunnelConfig {
    /// Interface name used in associated-data binding and diagnostics.
    pub interface_name: String,
    /// Maximum raw L3 packet size accepted by this interface.
    pub mtu: usize,
}

/// High-level FreeQ tunnel pipeline.
pub struct TunnelInterface {
    config: TunnelConfig,
    suite: AlgorithmSuite,
    session_key: [u8; 32],
    packet_counter: AtomicU64,
    packets_processed: AtomicU64,
    bytes_processed: AtomicU64,
    transport_frames: AtomicU64,
}

/// Report describing one successfully processed packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelWriteReport {
    /// Original L3 packet size in bytes.
    pub packet_len: usize,
    /// Encrypted packet size after AEAD processing.
    pub encrypted_len: usize,
    /// Number of QUIC-sized transport frames emitted.
    pub frames_emitted: usize,
}

/// Fully prepared encrypted transport packet with QUIC datagram frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTransportPacket {
    /// Monotonic packet identifier used for nonce derivation and reassembly.
    pub packet_id: u64,
    /// Original L3 packet size in bytes.
    pub packet_len: usize,
    /// Encrypted payload size after AEAD processing.
    pub encrypted_len: usize,
    /// QUIC-sized transport frames ready to send.
    pub frames: Vec<Bytes>,
}

impl TunnelInterface {
    /// Construct a tunnel pipeline from config and ephemeral benchmark keys.
    pub fn new(config: TunnelConfig, keys: FreeQKeyPair) -> Result<Self> {
        if config.mtu == 0 {
            return Err(TunnelError::MalformedPacket("MTU must be non-zero".into()));
        }

        let mlkem_shared = keys.mlkem_private[..32]
            .try_into()
            .map_err(|_| TunnelError::MalformedPacket("invalid ML-KEM test material".into()))?;
        let session_key = combine_secrets(
            &keys.x25519_private,
            mlkem_shared,
            &keys.x25519_public,
            &keys.x25519_public,
        );

        Ok(Self {
            config,
            suite: AlgorithmSuite::default(),
            session_key,
            packet_counter: AtomicU64::new(0),
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            transport_frames: AtomicU64::new(0),
        })
    }

    /// Process one raw L3 packet through validation, encryption, and QUIC frame chunking.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let _ = self.write_packet_report(packet).await?;
        Ok(())
    }

    /// Process one raw L3 packet and return the resulting pipeline report.
    pub async fn write_packet_report(&self, packet: &[u8]) -> Result<TunnelWriteReport> {
        let prepared = self.prepare_transport_packet(packet)?;
        let frames_emitted = prepared.frames.len();
        let encrypted_len = prepared.encrypted_len;
        let packet_len = prepared.packet_len;
        consume_transport_frames(prepared.frames).await?;

        Ok(TunnelWriteReport {
            packet_len,
            encrypted_len,
            frames_emitted,
        })
    }

    /// Prepare one raw L3 packet for transport transmission.
    pub fn prepare_transport_packet(&self, packet: &[u8]) -> Result<PreparedTransportPacket> {
        let packet_id = self.packet_counter.fetch_add(1, Ordering::Relaxed);
        self.prepare_transport_packet_with_session(packet, &self.session_key, packet_id)
    }

    /// Prepare one raw L3 packet for transport transmission using an explicit session key.
    pub fn prepare_transport_packet_with_session(
        &self,
        packet: &[u8],
        session_key: &[u8; 32],
        packet_id: u64,
    ) -> Result<PreparedTransportPacket> {
        if packet.len() > self.config.mtu {
            return Err(TunnelError::MalformedPacket(format!(
                "packet length {} exceeds MTU {}",
                packet.len(),
                self.config.mtu
            )));
        }

        let header = parse_ipv4_header(packet)?;
        if usize::from(header.total_length) != packet.len() {
            return Err(TunnelError::MalformedPacket(format!(
                "IPv4 total length {} does not match packet length {}",
                header.total_length,
                packet.len()
            )));
        }

        let nonce = nonce_from_counter(packet_id);
        let aad = aad_for_packet(header.total_length);
        let ciphertext = bulk::encrypt(&self.suite.bulk, session_key, &nonce, &aad, packet)?;
        let envelope = build_transport_envelope(packet_id, header.total_length, &ciphertext);
        let frames = freeq_transport::frame::chunk_packet_with_id(
            packet_id,
            &envelope,
            freeq_transport::frame::SECURE_QUIC_MTU,
        )?;

        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed
            .fetch_add(ciphertext.len() as u64, Ordering::Relaxed);
        self.transport_frames
            .fetch_add(frames.len() as u64, Ordering::Relaxed);

        Ok(PreparedTransportPacket {
            packet_id,
            packet_len: packet.len(),
            encrypted_len: ciphertext.len(),
            frames,
        })
    }

    /// Decrypt and validate one reassembled transport payload back into an L3 packet.
    pub fn receive_transport_packet(&self, packet: &[u8]) -> Result<Bytes> {
        self.receive_transport_packet_with_session(packet, &self.session_key)
    }

    /// Decrypt and validate one reassembled transport payload using an explicit session key.
    pub fn receive_transport_packet_with_session(
        &self,
        packet: &[u8],
        session_key: &[u8; 32],
    ) -> Result<Bytes> {
        let (packet_id, total_length, ciphertext) = parse_transport_envelope(packet)?;
        let nonce = nonce_from_counter(packet_id);
        let aad = aad_for_packet(total_length);
        let plaintext = bulk::decrypt(&self.suite.bulk, session_key, &nonce, &aad, ciphertext)?;

        if plaintext.len() != usize::from(total_length) {
            return Err(TunnelError::MalformedPacket(format!(
                "decrypted packet length {} does not match envelope length {}",
                plaintext.len(),
                total_length
            )));
        }

        let header = parse_ipv4_header(&plaintext)?;
        if header.total_length != total_length {
            return Err(TunnelError::MalformedPacket(format!(
                "IPv4 total length {} does not match envelope length {}",
                header.total_length, total_length
            )));
        }

        Ok(Bytes::from(plaintext))
    }

    /// Return the number of successfully processed packets.
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    /// Return the number of encrypted bytes emitted by the pipeline.
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    /// Return the number of QUIC-sized transport frames emitted by the pipeline.
    pub fn transport_frames(&self) -> u64 {
        self.transport_frames.load(Ordering::Relaxed)
    }

    /// Return the tunnel configuration for this interface.
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    pub(crate) fn next_packet_id(&self) -> u64 {
        self.packet_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn test_session_key(&self) -> [u8; 32] {
        self.session_key
    }
}

fn nonce_from_counter(counter: u64) -> [u8; bulk::NONCE_LEN] {
    let mut nonce = [0u8; bulk::NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn build_transport_envelope(packet_id: u64, total_length: u16, ciphertext: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(10 + ciphertext.len());
    envelope.extend_from_slice(&packet_id.to_be_bytes());
    envelope.extend_from_slice(&total_length.to_be_bytes());
    envelope.extend_from_slice(ciphertext);
    envelope
}

fn parse_transport_envelope(packet: &[u8]) -> Result<(u64, u16, &[u8])> {
    if packet.len() < 10 {
        return Err(TunnelError::MalformedPacket(
            "transport envelope shorter than header".into(),
        ));
    }

    let packet_id = u64::from_be_bytes(packet[0..8].try_into().map_err(|_| {
        TunnelError::MalformedPacket("failed to decode packet id from transport envelope".into())
    })?);
    let total_length = u16::from_be_bytes(packet[8..10].try_into().map_err(|_| {
        TunnelError::MalformedPacket("failed to decode total length from transport envelope".into())
    })?);

    Ok((packet_id, total_length, &packet[10..]))
}

fn aad_for_packet(total_length: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TRANSPORT_AAD_CONTEXT.len() + 2);
    aad.extend_from_slice(TRANSPORT_AAD_CONTEXT);
    aad.extend_from_slice(&total_length.to_be_bytes());
    aad
}

async fn consume_transport_frames(frames: Vec<Bytes>) -> Result<()> {
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
    use super::{PreparedTransportPacket, TunnelConfig, TunnelInterface};
    use freeq_crypto::FreeQKeyPair;

    #[tokio::test]
    async fn write_packet_exercises_real_path() {
        let keys = FreeQKeyPair::generate_ephemeral_test_pair().expect("keys");
        let tunnel = TunnelInterface::new(
            TunnelConfig {
                interface_name: "freeqtest0".into(),
                mtu: 1200,
            },
            keys,
        )
        .expect("tunnel");
        let packet = test_ipv4_packet(1180);

        let report = tunnel
            .write_packet_report(&packet)
            .await
            .expect("write packet");

        assert_eq!(tunnel.packets_processed(), 1);
        assert!(tunnel.bytes_processed() > packet.len() as u64);
        assert!(tunnel.transport_frames() >= 1);
        assert_eq!(report.packet_len, packet.len());
        assert!(report.encrypted_len > report.packet_len);
        assert!(report.frames_emitted >= 2);
    }

    #[test]
    fn prepared_packet_round_trips_back_to_plaintext() {
        let keys = FreeQKeyPair::generate_ephemeral_test_pair().expect("keys");
        let tunnel = TunnelInterface::new(
            TunnelConfig {
                interface_name: "freeqtest0".into(),
                mtu: 1200,
            },
            keys,
        )
        .expect("tunnel");
        let packet = test_ipv4_packet(1180);

        let PreparedTransportPacket { frames, .. } = tunnel
            .prepare_transport_packet(&packet)
            .expect("prepare packet");
        let mut reassembler = freeq_transport::frame::FrameReassembler::default();
        let mut rebuilt = None;
        for frame in frames {
            rebuilt = reassembler.push_frame(&frame).expect("push frame");
        }
        let plaintext = tunnel
            .receive_transport_packet(rebuilt.expect("rebuilt packet").as_ref())
            .expect("receive packet");

        assert_eq!(plaintext.as_ref(), packet.as_slice());
    }

    fn test_ipv4_packet(len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet
    }
}
