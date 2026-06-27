//! Virtual network interface management (TUN/TAP).

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::{Result, TunnelError};

#[cfg(unix)]
const MAX_PACKET_SIZE: usize = 65_535;
#[cfg(target_os = "macos")]
const UTUN_HEADER_LEN: usize = 4;

/// A handle to the OS virtual network interface.
pub struct TunInterface {
    name: String,
    #[cfg(unix)]
    fd: tokio::io::unix::AsyncFd<OwnedFd>,
}

impl TunInterface {
    /// Open the TUN interface.
    ///
    /// `name` is an optional interface name hint (e.g. `"utun7"` on macOS or
    /// `"tun0"` on Linux). The OS may assign a different name; check
    /// [`TunInterface::name`].
    pub async fn open(name: Option<&str>, addr: std::net::IpAddr) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let interface = open_macos_utun(name)?;
            tracing::info!(
                interface = %interface.name,
                address = %addr,
                "opened macOS utun interface; address configuration remains external"
            );
            Ok(interface)
        }

        #[cfg(target_os = "linux")]
        {
            let interface = open_linux_tun(name)?;
            tracing::info!(
                interface = %interface.name,
                address = %addr,
                "opened Linux TUN interface; address configuration remains external"
            );
            Ok(interface)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (name, addr);
            Err(TunnelError::Interface(
                "OS TUN adapter is implemented only for macOS and Linux in this revision".into(),
            ))
        }
    }

    /// The actual OS interface name (e.g. `"utun3"` or `"tun0"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one IP packet from the TUN interface.
    pub async fn read_packet(&self) -> Result<bytes::Bytes> {
        #[cfg(not(unix))]
        {
            Err(TunnelError::Interface(
                "OS TUN packet reads are implemented only for macOS and Linux in this revision"
                    .into(),
            ))
        }

        #[cfg(unix)]
        {
            let mut buffer = vec![0u8; max_read_buffer_len()];
            loop {
                let mut readiness = self
                    .fd
                    .readable()
                    .await
                    .map_err(|err| TunnelError::Interface(err.to_string()))?;
                let result = readiness.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    let read_len = unsafe {
                        libc::read(fd, buffer.as_mut_ptr().cast::<libc::c_void>(), buffer.len())
                    };
                    if read_len < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(read_len as usize)
                });

                match result {
                    Ok(Ok(read_len)) => return decode_read_packet(&buffer[..read_len]),
                    Ok(Err(err)) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Ok(Err(err)) => return Err(TunnelError::Io(err)),
                    Err(_) => continue,
                }
            }
        }
    }

    /// Write one IP packet to the TUN interface.
    pub async fn write_packet(&self, pkt: bytes::Bytes) -> Result<()> {
        #[cfg(not(unix))]
        {
            let _ = pkt;
            Err(TunnelError::Interface(
                "OS TUN packet writes are implemented only for macOS and Linux in this revision"
                    .into(),
            ))
        }

        #[cfg(unix)]
        {
            let frame = encode_write_packet(pkt)?;
            let mut written = 0usize;
            while written < frame.len() {
                let mut readiness = self
                    .fd
                    .writable()
                    .await
                    .map_err(|err| TunnelError::Interface(err.to_string()))?;
                let result = readiness.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    let write_len = unsafe {
                        libc::write(
                            fd,
                            frame[written..].as_ptr().cast::<libc::c_void>(),
                            frame.len() - written,
                        )
                    };
                    if write_len < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(write_len as usize)
                });

                match result {
                    Ok(Ok(write_len)) => written += write_len,
                    Ok(Err(err)) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Ok(Err(err)) => return Err(TunnelError::Io(err)),
                    Err(_) => continue,
                }
            }

            Ok(())
        }
    }
}

#[cfg(unix)]
fn max_read_buffer_len() -> usize {
    #[cfg(target_os = "macos")]
    {
        MAX_PACKET_SIZE + UTUN_HEADER_LEN
    }

    #[cfg(not(target_os = "macos"))]
    {
        MAX_PACKET_SIZE
    }
}

#[cfg(target_os = "linux")]
fn open_linux_tun(name_hint: Option<&str>) -> Result<TunInterface> {
    const DEV_NET_TUN: &[u8] = b"/dev/net/tun\0";

    let fd = unsafe {
        libc::open(
            DEV_NET_TUN.as_ptr().cast::<libc::c_char>(),
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_nonblocking(fd.as_raw_fd())?;

    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    if let Some(name_hint) = name_hint {
        copy_interface_name(name_hint, &mut ifreq.ifr_name)?;
    }
    unsafe {
        ifreq.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    }

    let ioctl_result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, &ifreq) };
    if ioctl_result < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let name = parse_interface_name(&ifreq.ifr_name)?;

    Ok(TunInterface {
        name,
        fd: tokio::io::unix::AsyncFd::new(fd)
            .map_err(|err| TunnelError::Interface(err.to_string()))?,
    })
}

#[cfg(target_os = "macos")]
fn open_macos_utun(name_hint: Option<&str>) -> Result<TunInterface> {
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
    const MAX_IF_NAME: usize = 64;

    let socket_fd =
        unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if socket_fd < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let fd = unsafe { OwnedFd::from_raw_fd(socket_fd) };
    set_nonblocking(fd.as_raw_fd())?;

    let mut ctl_info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    for (dst, src) in ctl_info
        .ctl_name
        .iter_mut()
        .zip(UTUN_CONTROL_NAME.iter().copied())
    {
        *dst = src as libc::c_char;
    }

    let ioctl_result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut ctl_info) };
    if ioctl_result < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let addr = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: ctl_info.ctl_id,
        sc_unit: requested_utun_unit(name_hint)?,
        sc_reserved: [0; 5],
    };

    let connect_result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ctl).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if connect_result < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let mut if_name = [0u8; MAX_IF_NAME];
    let mut if_name_len = if_name.len() as libc::socklen_t;
    let getsockopt_result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            if_name.as_mut_ptr().cast::<libc::c_void>(),
            &mut if_name_len,
        )
    };
    if getsockopt_result < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let name_len = if_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(if_name_len as usize)
        .min(if_name_len as usize);
    let name = std::str::from_utf8(&if_name[..name_len])
        .map_err(|err| TunnelError::Interface(err.to_string()))?
        .to_string();

    Ok(TunInterface {
        name,
        fd: tokio::io::unix::AsyncFd::new(fd)
            .map_err(|err| TunnelError::Interface(err.to_string()))?,
    })
}

#[cfg(target_os = "linux")]
fn copy_interface_name(name: &str, dst: &mut [libc::c_char]) -> Result<()> {
    if name.is_empty() {
        return Err(TunnelError::Interface(
            "Linux TUN name hint must not be empty".into(),
        ));
    }
    if name.len() >= dst.len() {
        return Err(TunnelError::Interface(format!(
            "Linux TUN name hint '{name}' exceeds IFNAMSIZ {}",
            dst.len()
        )));
    }

    for (slot, byte) in dst.iter_mut().zip(name.as_bytes().iter().copied()) {
        *slot = byte as libc::c_char;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_interface_name(name: &[libc::c_char]) -> Result<String> {
    let len = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let bytes = name[..len]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    std::str::from_utf8(&bytes)
        .map(|name| name.to_string())
        .map_err(|err| TunnelError::Interface(err.to_string()))
}

#[cfg(target_os = "macos")]
fn requested_utun_unit(name_hint: Option<&str>) -> Result<u32> {
    match name_hint {
        None => Ok(0),
        Some(name) => {
            let unit = parse_utun_name(name)?;
            Ok(unit + 1)
        }
    }
}

#[cfg(target_os = "macos")]
fn parse_utun_name(name: &str) -> Result<u32> {
    let suffix = name.strip_prefix("utun").ok_or_else(|| {
        TunnelError::Interface(format!(
            "macOS TUN name hint must look like 'utunN'; got '{name}'"
        ))
    })?;
    suffix
        .parse::<u32>()
        .map_err(|err| TunnelError::Interface(format!("invalid utun unit in '{name}': {err}")))
}

#[cfg(unix)]
fn set_nonblocking(fd: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    let set_result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if set_result < 0 {
        return Err(TunnelError::Io(std::io::Error::last_os_error()));
    }

    Ok(())
}

#[cfg(unix)]
fn decode_read_packet(buffer: &[u8]) -> Result<bytes::Bytes> {
    #[cfg(target_os = "linux")]
    {
        return Ok(bytes::Bytes::copy_from_slice(buffer));
    }

    #[cfg(target_os = "macos")]
    {
        if buffer.len() < UTUN_HEADER_LEN {
            return Err(TunnelError::BufferUnderflow);
        }
        return Ok(bytes::Bytes::copy_from_slice(&buffer[UTUN_HEADER_LEN..]));
    }

    #[allow(unreachable_code)]
    Err(TunnelError::Interface(
        "OS TUN packet reads are implemented only for macOS and Linux in this revision".into(),
    ))
}

#[cfg(unix)]
fn encode_write_packet(pkt: bytes::Bytes) -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        return Ok(pkt.to_vec());
    }

    #[cfg(target_os = "macos")]
    {
        let family = packet_family(pkt.as_ref())?;
        let mut frame = Vec::with_capacity(UTUN_HEADER_LEN + pkt.len());
        frame.extend_from_slice(&family.to_be_bytes());
        frame.extend_from_slice(&pkt);
        return Ok(frame);
    }

    #[allow(unreachable_code)]
    Err(TunnelError::Interface(
        "OS TUN packet writes are implemented only for macOS and Linux in this revision".into(),
    ))
}

fn packet_family(packet: &[u8]) -> Result<u32> {
    let version = packet
        .first()
        .ok_or_else(|| TunnelError::MalformedPacket("empty TUN packet".into()))?
        >> 4;
    match version {
        4 => Ok(libc::AF_INET as u32),
        6 => Ok(libc::AF_INET6 as u32),
        _ => Err(TunnelError::MalformedPacket(format!(
            "unsupported IP version nibble {version}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::packet_family;

    #[test]
    fn packet_family_detects_ipv4_and_ipv6() {
        assert_eq!(packet_family(&[0x45]).expect("ipv4"), libc::AF_INET as u32);
        assert_eq!(packet_family(&[0x60]).expect("ipv6"), libc::AF_INET6 as u32);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_utun_name_accepts_expected_shape() {
        assert_eq!(super::parse_utun_name("utun7").expect("utun7"), 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_linux_interface_name_rejects_empty_hint() {
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        let err = super::copy_interface_name("", &mut name).expect_err("empty name");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_linux_interface_name_round_trips() {
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        super::copy_interface_name("tun7", &mut name).expect("copy name");
        assert_eq!(
            super::parse_interface_name(&name).expect("parse name"),
            "tun7"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "opens a real host utun interface"]
    async fn open_utun_assigns_interface_name() {
        let tun = super::TunInterface::open(
            None,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        )
        .await
        .expect("open utun");

        assert!(tun.name().starts_with("utun"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "opens a real host /dev/net/tun interface"]
    async fn open_linux_tun_assigns_interface_name() {
        let tun = super::TunInterface::open(
            Some("tun-test"),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        )
        .await
        .expect("open tun");

        assert!(!tun.name().is_empty());
    }
}
