//! Packet parsing helpers for TUN frame ingress.

use crate::{Result, TunnelError};
use std::net::Ipv4Addr;

/// Minimal IPv4 header fields needed for routing and validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Header {
    /// Version and internet header length packed into the first octet.
    pub version_ihl: u8,
    /// Differentiated services field.
    pub dscp_ecn: u8,
    /// Total packet length in bytes.
    pub total_length: u16,
    /// Packet identification field.
    pub identification: u16,
    /// Source IPv4 address.
    pub source: Ipv4Addr,
    /// Destination IPv4 address.
    pub destination: Ipv4Addr,
}

impl Ipv4Header {
    /// Return the decoded IP version.
    pub fn version(self) -> u8 {
        self.version_ihl >> 4
    }

    /// Return the decoded header length in bytes.
    pub fn header_len(self) -> usize {
        usize::from(self.version_ihl & 0x0f) * 4
    }
}

/// Parse an IPv4 header without taking references to potentially unaligned data.
pub fn parse_ipv4_header(buffer: &[u8]) -> Result<Ipv4Header> {
    if buffer.len() < 20 {
        return Err(TunnelError::BufferUnderflow);
    }

    let header = Ipv4Header {
        version_ihl: buffer[0],
        dscp_ecn: buffer[1],
        total_length: u16::from_be_bytes([buffer[2], buffer[3]]),
        identification: u16::from_be_bytes([buffer[4], buffer[5]]),
        source: Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]),
        destination: Ipv4Addr::new(buffer[16], buffer[17], buffer[18], buffer[19]),
    };

    if header.version() != 4 || header.header_len() < 20 || buffer.len() < header.header_len() {
        return Err(TunnelError::MalformedPacket("invalid IPv4 header".into()));
    }

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::parse_ipv4_header;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_ipv4_header_from_unaligned_subslice() {
        let frame = [
            0xff, 0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0,
            1, 10, 0, 0, 2, 0x00,
        ];

        let header = parse_ipv4_header(&frame[1..]).expect("valid header");

        assert_eq!(header.version(), 4);
        assert_eq!(header.header_len(), 20);
        assert_eq!(header.total_length, 40);
        assert_eq!(header.identification, 0xabcd);
        assert_eq!(header.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(header.destination, Ipv4Addr::new(10, 0, 0, 2));
    }
}
