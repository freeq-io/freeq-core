//! QUIC endpoint — the local UDP socket that accepts incoming connections.

use crate::{connection, Result, TransportError};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::sync::Arc;

/// SHA-256 fingerprint of the leaf QUIC certificate.
pub type CertificateFingerprint = [u8; 32];

/// The local QUIC endpoint, bound to a UDP port.
///
/// Accepts incoming peer connections and initiates outgoing ones.
#[derive(Debug, Clone)]
pub struct Endpoint {
    endpoint: quinn::Endpoint,
    certificate_fingerprint: CertificateFingerprint,
}

impl Endpoint {
    /// Bind a new QUIC endpoint to `addr`.
    ///
    /// `addr` is typically `0.0.0.0:51820` (user-configurable).
    pub async fn bind(addr: std::net::SocketAddr) -> Result<Self> {
        let (server_config, certificate_fingerprint) = configure_server()?;
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        Ok(Self {
            endpoint,
            certificate_fingerprint,
        })
    }

    /// Accept the next incoming peer connection.
    pub async fn accept(&self) -> Result<crate::connection::PeerConnection> {
        let incoming = self.endpoint.accept().await.ok_or_else(|| {
            TransportError::ConnectionLost(
                "endpoint closed while waiting for incoming connection".into(),
            )
        })?;
        let connection = incoming.await.map_err(|e| TransportError::Connect {
            peer: "incoming".into(),
            reason: e.to_string(),
        })?;

        Ok(crate::connection::PeerConnection::new(connection))
    }

    /// Connect to a remote peer at `addr`.
    pub async fn connect(
        &self,
        expected_certificate_fingerprint: &CertificateFingerprint,
        addr: std::net::SocketAddr,
    ) -> Result<crate::connection::PeerConnection> {
        let client_config = configure_client(*expected_certificate_fingerprint)?;
        let connecting = self
            .endpoint
            .connect_with(client_config, addr, "localhost")
            .map_err(|e| TransportError::Connect {
                peer: addr.to_string(),
                reason: e.to_string(),
            })?;
        let connection = connecting.await.map_err(|e| TransportError::Connect {
            peer: addr.to_string(),
            reason: e.to_string(),
        })?;

        Ok(crate::connection::PeerConnection::new(connection))
    }

    /// Return the local socket address of the endpoint.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.endpoint.local_addr().map_err(TransportError::Io)
    }

    /// Return the SHA-256 fingerprint of this endpoint's leaf certificate.
    pub fn certificate_fingerprint(&self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }

    /// Close the endpoint and all active connections.
    pub async fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
    }
}

fn configure_server() -> Result<(quinn::ServerConfig, CertificateFingerprint)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert);
    let certificate_fingerprint = certificate_fingerprint(cert_der.as_ref());
    let private_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_config =
        quinn::ServerConfig::with_single_cert(vec![cert_der], private_key.into())
            .map_err(|e| TransportError::Tls(e.to_string()))?;
    server_config.transport = Arc::new(transport_config());
    Ok((server_config, certificate_fingerprint))
}

fn configure_client(
    expected_certificate_fingerprint: CertificateFingerprint,
) -> Result<quinn::ClientConfig> {
    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerCertificateVerifier::new(
            expected_certificate_fingerprint,
        ))
        .with_no_client_auth();
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(rustls_config)
            .map_err(|e| TransportError::Tls(e.to_string()))?,
    ));
    client_config.transport_config(Arc::new(transport_config()));
    Ok(client_config)
}

fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.keep_alive_interval(Some(connection::QUIC_KEEPALIVE_INTERVAL));
    config.max_idle_timeout(Some(
        connection::QUIC_IDLE_TIMEOUT
            .try_into()
            .expect("default idle timeout should fit"),
    ));
    config
}

fn certificate_fingerprint(certificate: &[u8]) -> CertificateFingerprint {
    use sha2::Digest as _;

    sha2::Sha256::digest(certificate).into()
}

#[derive(Debug)]
struct PinnedServerCertificateVerifier {
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    expected_fingerprint: CertificateFingerprint,
}

impl PinnedServerCertificateVerifier {
    fn new(expected_fingerprint: CertificateFingerprint) -> Arc<Self> {
        Arc::new(Self {
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            expected_fingerprint,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if certificate_fingerprint(end_entity.as_ref()) != self.expected_fingerprint {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoint;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn endpoint_connects_and_exchanges_datagrams() {
        let server = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        let server_fingerprint = server.certificate_fingerprint();
        let client = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client");

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let conn = server.accept().await.expect("accept");
                let payload = conn.recv().await.expect("recv");
                assert_eq!(payload, Bytes::from_static(b"ping"));
                conn.send(Bytes::from_static(b"pong")).await.expect("send");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            })
        };

        let client_conn = client
            .connect(&server_fingerprint, server_addr)
            .await
            .expect("connect");
        client_conn
            .send(Bytes::from_static(b"ping"))
            .await
            .expect("send ping");
        let reply = client_conn.recv().await.expect("recv pong");
        assert_eq!(reply, Bytes::from_static(b"pong"));

        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn endpoint_rejects_unpinned_server_certificate() {
        let server = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        let client = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client");

        let err = client
            .connect(&[0xAA; 32], server_addr)
            .await
            .expect_err("mismatched fingerprint should fail");

        assert!(matches!(err, crate::TransportError::Connect { .. }));

        client.close().await;
        server.close().await;
    }
}
