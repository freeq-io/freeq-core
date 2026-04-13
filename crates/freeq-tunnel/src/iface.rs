//! Virtual network interface management (TUN/TAP).

use crate::Result;
use bytes::Bytes;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use tun::AbstractDevice as _;

    const MAX_PACKET_SIZE: usize = 65_535;

    pub struct PlatformTun {
        device: Arc<Mutex<tun::Device>>,
        name: String,
    }

    impl PlatformTun {
        pub async fn open(name: Option<&str>, addr: IpAddr) -> Result<Self> {
            let device = create_device(name, addr)?;
            let interface_name = device
                .tun_name()
                .map_err(|e| crate::TunnelError::Interface(e.to_string()))?;

            Ok(Self {
                device: Arc::new(Mutex::new(device)),
                name: interface_name,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&self) -> Result<Bytes> {
            let device = self.device.clone();

            tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; MAX_PACKET_SIZE];
                let amount = device
                    .lock()
                    .map_err(|_| {
                        crate::TunnelError::Interface(
                            "TUN device mutex poisoned during read".into(),
                        )
                    })?
                    .recv(&mut buf)
                    .map_err(|e| crate::TunnelError::Interface(e.to_string()))?;
                buf.truncate(amount);
                Ok(Bytes::from(buf))
            })
            .await
            .map_err(|e| crate::TunnelError::Interface(e.to_string()))?
        }

        pub async fn write_packet(&self, pkt: Bytes) -> Result<()> {
            let device = self.device.clone();
            let packet = pkt.to_vec();

            tokio::task::spawn_blocking(move || {
                let written = device
                    .lock()
                    .map_err(|_| {
                        crate::TunnelError::Interface(
                            "TUN device mutex poisoned during write".into(),
                        )
                    })?
                    .send(&packet)
                    .map_err(|e| crate::TunnelError::Interface(e.to_string()))?;

                if written != packet.len() {
                    return Err(crate::TunnelError::Interface(
                        "short write to TUN interface".into(),
                    ));
                }

                Ok(())
            })
            .await
            .map_err(|e| crate::TunnelError::Interface(e.to_string()))?
        }
    }

    fn create_device(name: Option<&str>, addr: IpAddr) -> Result<tun::Device> {
        let ipv4_addr = match addr {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(crate::TunnelError::Interface(
                    "tun-backed interface setup currently supports IPv4 addresses only".into(),
                ));
            }
        };

        let mut config = tun::Configuration::default();
        config
            .layer(tun::Layer::L3)
            .address(ipv4_addr)
            .netmask(Ipv4Addr::new(255, 255, 255, 255))
            .destination(ipv4_addr)
            .up();

        if let Some(name) = name {
            config.tun_name(name);
        }

        #[cfg(target_os = "linux")]
        config.platform_config(|platform| {
            platform.ensure_root_privileges(true);
        });

        tun::create(&config).map_err(|e| crate::TunnelError::Interface(e.to_string()))
    }

    #[cfg(test)]
    mod tests {
        use super::create_device;
        use std::net::Ipv6Addr;

        #[test]
        fn tun_backend_rejects_ipv6_until_dual_stack_setup_exists() {
            let err = match create_device(None, std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)) {
                Ok(_) => panic!("IPv6 should be rejected for now"),
                Err(err) => err,
            };

            assert!(matches!(err, crate::TunnelError::Interface(_)));
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
