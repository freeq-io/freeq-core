//! Virtual network interface management (TUN/TAP).

use crate::Result;

/// A handle to the OS virtual network interface.
pub struct TunInterface {
    // TODO(v0.1): platform-specific handle
    //   Linux:   File handle to /dev/net/tun (via nix or tun-tap crate)
    //   macOS:   kern control socket for utun
    //   Windows: WinTUN adapter handle (v0.3)
    _private: (),
}

impl TunInterface {
    /// Open the TUN interface.
    ///
    /// `name` is an optional interface name hint (e.g. `"freeq0"`).
    /// The OS may assign a different name; check [`TunInterface::name`].
    pub async fn open(_name: Option<&str>, _addr: std::net::IpAddr) -> Result<Self> {
        todo!("open TUN interface")
    }

    /// The actual OS interface name (e.g. `"freeq0"` or `"utun3"`).
    pub fn name(&self) -> &str {
        todo!("TUN interface name")
    }

    /// Read one IP packet from the TUN interface.
    pub async fn read_packet(&self) -> Result<bytes::Bytes> {
        todo!("TUN read packet")
    }

    /// Write one IP packet to the TUN interface.
    pub async fn write_packet(&self, _pkt: bytes::Bytes) -> Result<()> {
        todo!("TUN write packet")
    }
}
