//! # freeq-tunnel
//!
//! TUN/TAP L3 overlay — the packet routing core of the FreeQ daemon.
//!
//! Responsibilities:
//! - Open and manage the OS virtual network interface (TUN)
//!   - Linux: `/dev/net/tun`
//!   - macOS: `utun` via kern control sockets
//!   - Windows: WinTUN driver (v0.3)
//! - Read IP packets from the TUN interface, encrypt via `freeq-crypto`,
//!   forward via `freeq-transport`
//! - Receive encrypted packets from `freeq-transport`, decrypt, write to TUN
//! - io_uring zero-copy I/O on Linux 5.19+ (v0.2)

#![deny(missing_docs, clippy::unwrap_used)]

pub mod error;
pub mod iface;
pub mod router;

pub use error::TunnelError;

/// Library-wide result type.
pub type Result<T> = std::result::Result<T, TunnelError>;
