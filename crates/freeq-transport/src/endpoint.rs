//! QUIC endpoint — the local UDP socket that accepts incoming connections.

use crate::{connection, Result, TransportError};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::sync::Arc;

/// The local QUIC endpoint, bound to a UDP port.
///
/// Accepts incoming peer connections and initiates outgoing ones.
#[derive(Debug, Clone)]
pub struct Endpoint {
    endpoint: quinn::Endpoint,
}

impl Endpoint {
    /// Bind a new QUIC endpoint to `addr`.
    ///
    /// `addr` is typically `0.0.0.0:51820` (user-configurable).
    pub async fn bind(addr: std::net::SocketAddr) -> Result<Self> {
        let server_config = configure_server()?;
        let mut endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        endpoint.set_default_client_config(configure_client()?);

        Ok(Self { endpoint })
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
        addr: std::net::SocketAddr,
    ) -> Result<crate::connection::PeerConnection> {
        let connecting =
            self.endpoint
                .connect(addr, "localhost")
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

    /// Close the endpoint and all active connections.
    pub async fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
    }
}

fn configure_server() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert);
    let private_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_config =
        quinn::ServerConfig::with_single_cert(vec![cert_der], private_key.into())
            .map_err(|e| TransportError::Tls(e.to_string()))?;
    server_config.transport = Arc::new(transport_config());
    Ok(server_config)
}

fn configure_client() -> Result<quinn::ClientConfig> {
    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
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

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
            &self.0.signature_verification_algorithms,
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
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
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

        let client_conn = client.connect(server_addr).await.expect("connect");
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
}
