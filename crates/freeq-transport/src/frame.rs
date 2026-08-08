//! Transport frame construction and reassembly helpers.

use std::collections::HashMap;

use crate::{Result, TransportError};
use bytes::Bytes;

/// Conservative QUIC datagram payload size used for public-path FreeQ frames.
///
/// This stays below a 1200-byte path MTU so QUIC DATAGRAM framing overhead does
/// not push an application datagram over the transport's minimum safe size.
pub const SECURE_QUIC_MTU: usize = 1024;
const FRAME_HEADER_LEN: usize = 12;

/// One decoded QUIC datagram frame carrying a slice of a larger packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// Monotonic sender-selected packet identifier.
    pub packet_id: u64,
    /// Zero-based chunk index for this frame.
    pub chunk_index: u16,
    /// Total number of chunks required for this packet.
    pub chunk_count: u16,
    /// Raw frame payload bytes.
    pub payload: Bytes,
}

/// Stateful packet reassembler for received QUIC datagram frames.
#[derive(Default)]
pub struct FrameReassembler {
    packets: HashMap<u64, PartialPacket>,
}

#[derive(Debug)]
struct PartialPacket {
    expected_chunks: u16,
    received_chunks: u16,
    chunks: Vec<Option<Bytes>>,
}

impl FrameReassembler {
    /// Ingest one received frame and return a reassembled packet when complete.
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<Option<Bytes>> {
        let decoded = decode_frame(frame)?;
        let chunk_slot = usize::from(decoded.chunk_index);
        let chunk_count = usize::from(decoded.chunk_count);
        let packet_id = decoded.packet_id;

        let partial = self
            .packets
            .entry(packet_id)
            .or_insert_with(|| PartialPacket {
                expected_chunks: decoded.chunk_count,
                received_chunks: 0,
                chunks: vec![None; chunk_count],
            });

        if partial.expected_chunks != decoded.chunk_count || partial.chunks.len() != chunk_count {
            self.packets.remove(&packet_id);
            return Err(TransportError::Frame(format!(
                "inconsistent chunk count for packet {packet_id}"
            )));
        }

        if chunk_slot >= partial.chunks.len() {
            self.packets.remove(&packet_id);
            return Err(TransportError::Frame(format!(
                "chunk index {} out of range for packet {packet_id}",
                decoded.chunk_index
            )));
        }

        if partial.chunks[chunk_slot].is_none() {
            partial.received_chunks += 1;
            partial.chunks[chunk_slot] = Some(decoded.payload);
        }

        if partial.received_chunks != partial.expected_chunks {
            return Ok(None);
        }

        let Some(partial) = self.packets.remove(&packet_id) else {
            return Err(TransportError::Frame(format!(
                "packet {packet_id} disappeared before final assembly"
            )));
        };
        let total_len = partial
            .chunks
            .iter()
            .map(|chunk| chunk.as_ref().map_or(0, Bytes::len))
            .sum();
        let mut packet = Vec::with_capacity(total_len);
        for chunk in partial.chunks {
            let chunk = chunk.ok_or_else(|| {
                TransportError::Frame(format!("missing chunk while finalizing packet {packet_id}"))
            })?;
            packet.extend_from_slice(&chunk);
        }

        Ok(Some(Bytes::from(packet)))
    }
}

/// Split an encrypted packet into QUIC-sized frames using packet id `0`.
pub fn chunk_packet_for_quic(packet: &[u8]) -> Result<Vec<Bytes>> {
    chunk_packet_with_id(0, packet, SECURE_QUIC_MTU)
}

/// Split a packet into frames no larger than `mtu` using packet id `0`.
pub fn chunk_packet(packet: &[u8], mtu: usize) -> Result<Vec<Bytes>> {
    chunk_packet_with_id(0, packet, mtu)
}

/// Split a packet into frames tagged with `packet_id`.
pub fn chunk_packet_with_id(packet_id: u64, packet: &[u8], mtu: usize) -> Result<Vec<Bytes>> {
    if mtu <= FRAME_HEADER_LEN {
        return Err(TransportError::Frame(format!(
            "MTU must be greater than frame header length {FRAME_HEADER_LEN}"
        )));
    }

    let payload_mtu = mtu - FRAME_HEADER_LEN;
    if packet.is_empty() {
        return Ok(vec![encode_frame(packet_id, 0, 1, &[])]);
    }

    let chunk_count = packet.len().div_ceil(payload_mtu);
    let chunk_count_u16 = u16::try_from(chunk_count).map_err(|_| {
        TransportError::Frame(format!(
            "packet requires {chunk_count} chunks which exceeds u16 frame count"
        ))
    })?;

    packet
        .chunks(payload_mtu)
        .enumerate()
        .map(|(index, chunk)| {
            let chunk_index = u16::try_from(index).map_err(|_| {
                TransportError::Frame(format!(
                    "chunk index {index} exceeds u16 for packet {packet_id}"
                ))
            })?;
            Ok(encode_frame(packet_id, chunk_index, chunk_count_u16, chunk))
        })
        .collect::<Result<Vec<_>>>()
}

/// Decode one transport frame into its metadata and payload.
pub fn decode_frame(frame: &[u8]) -> Result<DecodedFrame> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(TransportError::Frame("frame shorter than header".into()));
    }

    let packet_id = u64::from_be_bytes(frame[0..8].try_into().map_err(|_| {
        TransportError::Frame("failed to decode packet id from frame header".into())
    })?);
    let chunk_index = u16::from_be_bytes(frame[8..10].try_into().map_err(|_| {
        TransportError::Frame("failed to decode chunk index from frame header".into())
    })?);
    let chunk_count = u16::from_be_bytes(frame[10..12].try_into().map_err(|_| {
        TransportError::Frame("failed to decode chunk count from frame header".into())
    })?);

    if chunk_count == 0 {
        return Err(TransportError::Frame("chunk count must be non-zero".into()));
    }

    if chunk_index >= chunk_count {
        return Err(TransportError::Frame(format!(
            "chunk index {chunk_index} out of range for count {chunk_count}"
        )));
    }

    Ok(DecodedFrame {
        packet_id,
        chunk_index,
        chunk_count,
        payload: Bytes::copy_from_slice(&frame[FRAME_HEADER_LEN..]),
    })
}

fn encode_frame(packet_id: u64, chunk_index: u16, chunk_count: u16, payload: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&packet_id.to_be_bytes());
    frame.extend_from_slice(&chunk_index.to_be_bytes());
    frame.extend_from_slice(&chunk_count.to_be_bytes());
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

#[cfg(test)]
mod tests {
    use super::{
        chunk_packet, chunk_packet_with_id, decode_frame, FrameReassembler, SECURE_QUIC_MTU,
    };
    use bytes::Bytes;

    #[test]
    fn chunking_clamps_to_secure_mtu() {
        let frames =
            chunk_packet(&vec![0u8; SECURE_QUIC_MTU + 7], SECURE_QUIC_MTU).expect("chunk packet");

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].len(), SECURE_QUIC_MTU);
        assert_eq!(frames[1].len(), 31);
    }

    #[test]
    fn decode_frame_round_trips_metadata() {
        let frame = chunk_packet_with_id(41, b"freeq", 1200)
            .expect("frame")
            .pop()
            .expect("single frame");
        let decoded = decode_frame(&frame).expect("decode frame");

        assert_eq!(decoded.packet_id, 41);
        assert_eq!(decoded.chunk_index, 0);
        assert_eq!(decoded.chunk_count, 1);
        assert_eq!(decoded.payload.as_ref(), b"freeq");
    }

    #[test]
    fn reassembler_rebuilds_multi_frame_packet() {
        let payload = vec![7u8; SECURE_QUIC_MTU * 2];
        let frames = chunk_packet_with_id(9, &payload, SECURE_QUIC_MTU).expect("chunk packet");
        let mut reassembler = FrameReassembler::default();
        let mut rebuilt = None;

        for frame in frames {
            rebuilt = reassembler.push_frame(&frame).expect("push frame");
        }

        assert_eq!(rebuilt.expect("rebuilt packet"), Bytes::from(payload));
    }
}
