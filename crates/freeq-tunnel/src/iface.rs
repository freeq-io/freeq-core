//! Virtual network interface management (TUN/TAP).

use crate::Result;
use bytes::Bytes;
use ipnetwork::IpNetwork;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tun::AbstractDevice as _;

    const MAX_PACKET_SIZE: usize = 65_535;

    pub struct PlatformTun {
        device: Arc<Mutex<tun::Device>>,
        name: String,
    }

    impl PlatformTun {
        pub async fn open(name: Option<&str>, network: IpNetwork) -> Result<Self> {
            let device = create_device(name, network)?;
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

    fn create_device(name: Option<&str>, network: IpNetwork) -> Result<tun::Device> {
        let mut config = tun::Configuration::default();
        config.layer(tun::Layer::L3).up();

        match network {
            IpNetwork::V4(network) => {
                config
                    .address(network.ip())
                    .netmask(prefix_to_ipv4_netmask(network.prefix()))
                    .destination(network.ip());
            }
            IpNetwork::V6(network) => {
                #[cfg(target_os = "macos")]
                {
                    let _ = network;
                    return Err(crate::TunnelError::Interface(
                        "the tun crate macOS backend does not yet support IPv6 interface setup"
                            .into(),
                    ));
                }

                #[cfg(target_os = "linux")]
                {
                    config
                        .address(network.ip())
                        .netmask(prefix_to_ipv6_netmask(network.prefix()))
                        .destination(network.ip());
                }
            }
        }

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
        use crate::iface::{prefix_to_ipv4_netmask, prefix_to_ipv6_netmask};
        use std::net::Ipv4Addr;

        #[test]
        fn ipv4_netmask_conversion_matches_prefix_length() {
            assert_eq!(prefix_to_ipv4_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(
                prefix_to_ipv4_netmask(32),
                Ipv4Addr::new(255, 255, 255, 255)
            );
        }

        #[test]
        fn ipv6_netmask_conversion_matches_prefix_length() {
            assert_eq!(
                prefix_to_ipv6_netmask(64),
                "ffff:ffff:ffff:ffff::"
                    .parse::<std::net::Ipv6Addr>()
                    .expect("mask"),
            );
            assert_eq!(
                prefix_to_ipv6_netmask(128),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                    .parse::<std::net::Ipv6Addr>()
                    .expect("mask"),
            );
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
        pub async fn open(name: Option<&str>, _network: IpNetwork) -> Result<Self> {
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
    pub async fn open(name: Option<&str>, network: IpNetwork) -> Result<Self> {
        Ok(Self {
            inner: platform::PlatformTun::open(name, network).await?,
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prefix_to_ipv4_netmask(prefix: u8) -> std::net::Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    std::net::Ipv4Addr::from(mask)
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prefix_to_ipv6_netmask(prefix: u8) -> std::net::Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    std::net::Ipv6Addr::from(mask)
}
