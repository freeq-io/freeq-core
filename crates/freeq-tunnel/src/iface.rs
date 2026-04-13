//! Virtual network interface management (TUN/TAP).

use crate::Result;
use bytes::Bytes;

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::raw::{c_char, c_int, c_uint};
    use tokio::io::unix::AsyncFd;

    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
    const UTUN_OPT_IFNAME: c_int = 2;
    const MAX_PACKET_SIZE: usize = 65_535;
    const UTUN_HEADER_LEN: usize = 4;

    const PF_SYSTEM_VALUE: c_int = 32;
    const AF_SYS_CONTROL_VALUE: u8 = 2;
    const SYSPROTO_CONTROL_VALUE: c_int = 2;
    const AF_INET_VALUE: u8 = libc::AF_INET as u8;
    const AF_INET6_VALUE: u8 = libc::AF_INET6 as u8;
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;

    #[repr(C)]
    struct CtlInfo {
        ctl_id: c_uint,
        ctl_name: [c_char; 96],
    }

    #[repr(C)]
    struct SockAddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: c_uint,
        sc_unit: c_uint,
        sc_reserved: [c_uint; 5],
    }

    const AF_SYS_CONTROL: u16 = 2;

    pub struct PlatformTun {
        fd: AsyncFd<OwnedFd>,
        name: String,
    }

    impl PlatformTun {
        pub async fn open(name: Option<&str>, addr: std::net::IpAddr) -> Result<Self> {
            if let Some(name) = name {
                validate_name(name)?;
            }

            let fd = open_utun(name)?;
            configure_interface(&fd, addr).await?;
            let interface_name = interface_name(&fd)?;

            Ok(Self {
                fd: AsyncFd::new(fd).map_err(|e| crate::TunnelError::Interface(e.to_string()))?,
                name: interface_name,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&self) -> Result<Bytes> {
            let mut frame = vec![0u8; MAX_PACKET_SIZE + UTUN_HEADER_LEN];

            loop {
                let mut guard = self
                    .fd
                    .readable()
                    .await
                    .map_err(|e| crate::TunnelError::Interface(e.to_string()))?;

                match guard.try_io(|inner| read_fd(inner.get_ref(), &mut frame)) {
                    Ok(result) => {
                        return parse_frame(&frame[..result.map_err(crate::TunnelError::Io)?])
                    }
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn write_packet(&self, pkt: Bytes) -> Result<()> {
            let frame = encode_frame(&pkt)?;

            loop {
                let mut guard = self
                    .fd
                    .writable()
                    .await
                    .map_err(|e| crate::TunnelError::Interface(e.to_string()))?;

                match guard.try_io(|inner| write_fd(inner.get_ref(), &frame)) {
                    Ok(result) => return result.map_err(crate::TunnelError::Io),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    fn validate_name(name: &str) -> Result<()> {
        if !name.starts_with("utun") {
            return Err(crate::TunnelError::Interface(
                "macOS TUN interface hints must start with 'utun'".into(),
            ));
        }

        if name.len() > 4 {
            name[4..].parse::<u32>().map_err(|_| {
                crate::TunnelError::Interface(
                    "macOS utun hints must be in the form 'utun' or 'utunN'".into(),
                )
            })?;
        }

        Ok(())
    }

    fn open_utun(name: Option<&str>) -> Result<OwnedFd> {
        let fd = unsafe { libc::socket(PF_SYSTEM_VALUE, libc::SOCK_DGRAM, SYSPROTO_CONTROL_VALUE) };
        if fd < 0 {
            return Err(crate::TunnelError::Io(std::io::Error::last_os_error()));
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let control_id = lookup_utun_control_id(&owned_fd)?;
        let unit = requested_unit(name)?;
        connect_utun(&owned_fd, control_id, unit)?;
        set_nonblocking(&owned_fd)?;

        Ok(owned_fd)
    }

    fn lookup_utun_control_id(fd: &OwnedFd) -> Result<c_uint> {
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        for (dest, src) in info
            .ctl_name
            .iter_mut()
            .zip(UTUN_CONTROL_NAME.iter().copied())
        {
            *dest = src as c_char;
        }

        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) };
        if rc < 0 {
            return Err(crate::TunnelError::Io(std::io::Error::last_os_error()));
        }

        Ok(info.ctl_id)
    }

    fn requested_unit(name: Option<&str>) -> Result<c_uint> {
        match name {
            None => Ok(0),
            Some("utun") => Ok(0),
            Some(interface) => {
                let unit = interface[4..].parse::<u32>().map_err(|_| {
                    crate::TunnelError::Interface(
                        "macOS utun hints must be in the form 'utun' or 'utunN'".into(),
                    )
                })?;
                Ok(unit.saturating_add(1))
            }
        }
    }

    fn connect_utun(fd: &OwnedFd, control_id: c_uint, unit: c_uint) -> Result<()> {
        let addr = SockAddrCtl {
            sc_len: std::mem::size_of::<SockAddrCtl>() as u8,
            sc_family: AF_SYS_CONTROL_VALUE,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: control_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&addr as *const SockAddrCtl).cast(),
                std::mem::size_of::<SockAddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(crate::TunnelError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(crate::TunnelError::Io(std::io::Error::last_os_error()));
        }

        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(crate::TunnelError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    async fn configure_interface(fd: &OwnedFd, addr: std::net::IpAddr) -> Result<()> {
        let name = interface_name(fd)?;
        let mask = match addr {
            std::net::IpAddr::V4(_) => "255.255.255.255",
            std::net::IpAddr::V6(_) => "128",
        };

        let status = tokio::process::Command::new("ifconfig")
            .arg(&name)
            .arg(addr.to_string())
            .arg(match addr {
                std::net::IpAddr::V4(_) => addr.to_string(),
                std::net::IpAddr::V6(_) => "prefixlen".into(),
            })
            .args(match addr {
                std::net::IpAddr::V4(_) => vec![mask.to_string(), "up".to_string()],
                std::net::IpAddr::V6(_) => vec![mask.to_string(), "up".to_string()],
            })
            .status()
            .await
            .map_err(crate::TunnelError::Io)?;

        if !status.success() {
            return Err(crate::TunnelError::Interface(format!(
                "ifconfig failed to configure {name} with address {addr}"
            )));
        }

        Ok(())
    }

    fn interface_name(fd: &OwnedFd) -> Result<String> {
        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SYSPROTO_CONTROL_VALUE,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc < 0 {
            return Err(crate::TunnelError::Io(std::io::Error::last_os_error()));
        }

        let cstr = CStr::from_bytes_until_nul(&name)
            .map_err(|_| crate::TunnelError::Interface("invalid utun interface name".into()))?;
        Ok(cstr.to_string_lossy().into_owned())
    }

    fn read_fd(fd: &OwnedFd, buffer: &mut [u8]) -> std::io::Result<usize> {
        let rc = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(rc as usize)
    }

    fn write_fd(fd: &OwnedFd, buffer: &[u8]) -> std::io::Result<()> {
        let written = unsafe { libc::write(fd.as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) };
        if written < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if written as usize != buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short write to utun interface",
            ));
        }

        Ok(())
    }

    fn encode_frame(packet: &[u8]) -> Result<Vec<u8>> {
        let family = packet_family(packet)?;
        let mut frame = Vec::with_capacity(UTUN_HEADER_LEN + packet.len());
        frame.extend_from_slice(&u32::from(family).to_be_bytes());
        frame.extend_from_slice(packet);
        Ok(frame)
    }

    fn parse_frame(frame: &[u8]) -> Result<Bytes> {
        if frame.len() <= UTUN_HEADER_LEN {
            return Err(crate::TunnelError::InvalidPacket(
                "utun frame shorter than header".into(),
            ));
        }

        let family = u32::from_be_bytes(
            frame[..UTUN_HEADER_LEN]
                .try_into()
                .map_err(|_| crate::TunnelError::InvalidPacket("invalid utun header".into()))?,
        );
        if family != u32::from(AF_INET_VALUE) && family != u32::from(AF_INET6_VALUE) {
            return Err(crate::TunnelError::InvalidPacket(format!(
                "unsupported utun address family {family}"
            )));
        }

        Ok(Bytes::copy_from_slice(&frame[UTUN_HEADER_LEN..]))
    }

    fn packet_family(packet: &[u8]) -> Result<u8> {
        let version = packet
            .first()
            .map(|byte| byte >> 4)
            .ok_or_else(|| crate::TunnelError::InvalidPacket("empty IP packet".into()))?;

        match version {
            4 => Ok(AF_INET_VALUE),
            6 => Ok(AF_INET6_VALUE),
            _ => Err(crate::TunnelError::InvalidPacket(format!(
                "unsupported IP version nibble: {version}"
            ))),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{encode_frame, parse_frame};

        #[test]
        fn utun_frame_round_trips_ipv4_packet() {
            let packet = bytes::Bytes::from_static(&[
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            ]);
            let frame = encode_frame(&packet).expect("encode");
            let decoded = parse_frame(&frame).expect("decode");

            assert_eq!(decoded, packet);
        }

        #[test]
        fn utun_frame_rejects_unknown_family() {
            let err = parse_frame(&[0, 0, 0, 99, 1, 2, 3]).expect_err("invalid family");

            assert!(matches!(err, crate::TunnelError::InvalidPacket(_)));
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    pub struct PlatformTun {
        name: String,
    }

    impl PlatformTun {
        pub async fn open(name: Option<&str>, _addr: std::net::IpAddr) -> Result<Self> {
            Err(crate::TunnelError::Interface(format!(
                "TUN interface support is not implemented for {}{}",
                std::env::consts::OS,
                name.map(|hint| format!(" (requested interface hint: {hint})"))
                    .unwrap_or_default()
            )))
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&self) -> Result<Bytes> {
            Err(crate::TunnelError::Interface(format!(
                "TUN packet reads are not implemented for {}",
                std::env::consts::OS
            )))
        }

        pub async fn write_packet(&self, _pkt: Bytes) -> Result<()> {
            Err(crate::TunnelError::Interface(format!(
                "TUN packet writes are not implemented for {}",
                std::env::consts::OS
            )))
        }
    }
}

/// A handle to the OS virtual network interface.
pub struct TunInterface {
    inner: platform::PlatformTun,
}

impl TunInterface {
    /// Open the TUN interface.
    ///
    /// `name` is an optional interface name hint (e.g. `"freeq0"`).
    /// The OS may assign a different name; check [`TunInterface::name`].
    pub async fn open(name: Option<&str>, addr: std::net::IpAddr) -> Result<Self> {
        Ok(Self {
            inner: platform::PlatformTun::open(name, addr).await?,
        })
    }

    /// The actual OS interface name (e.g. `"freeq0"` or `"utun3"`).
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Read one IP packet from the TUN interface.
    pub async fn read_packet(&self) -> Result<Bytes> {
        self.inner.read_packet().await
    }

    /// Write one IP packet to the TUN interface.
    pub async fn write_packet(&self, pkt: Bytes) -> Result<()> {
        self.inner.write_packet(pkt).await
    }
}
