//! QUIC endpoint — the local UDP socket that accepts incoming connections.

use crate::{connection::PeerConnection, Result, TransportError};
use quinn::{ClientConfig, Endpoint as QuinnEndpoint, ServerConfig, VarInt};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Endpoint {
    endpoint: QuinnEndpoint,
}

impl Endpoint {
    /// Bind a new QUIC endpoint to `addr` (typically 0.0.0.0:51820).
    pub async fn bind(addr: std::net::SocketAddr) -> Result<Self> {
        let server_config = Self::configure_server()?;
        let mut endpoint = QuinnEndpoint::server(server_config, addr)
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        endpoint.set_default_client_config(Self::configure_client()?);
        Ok(Self { endpoint })
    }

    pub async fn accept(&self) -> Result<PeerConnection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::ConnectionLost(
                "endpoint closed while waiting for incoming connection".into(),
            ))?;
        let connection = incoming.await.map_err(|e| TransportError::Connect {
            peer: "incoming".into(),
            reason: e.to_string(),
        })?;
        Ok(PeerConnection::new(connection))
    }

    pub async fn connect(&self, addr: std::net::SocketAddr) -> Result<PeerConnection> {
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
        Ok(PeerConnection::new(connection))
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.endpoint.local_addr().map_err(TransportError::Io)
    }

    pub async fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        self.endpoint.wait_idle().await;
    }

    fn configure_server() -> Result<ServerConfig> {
        let cert_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        let cert_der = CertificateDer::from(cert_key.cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der());

        let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key_der.into())
            .map_err(|e| TransportError::Tls(e.to_string()))?;

        server_config.transport = Arc::new(Self::transport_config());
        Ok(server_config)
    }

    fn configure_client() -> Result<ClientConfig> {
        let rustls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| TransportError::Tls(e.to_string()))?,
        ));

        client_config.transport_config(Arc::new(Self::transport_config()));
        Ok(client_config)
    }

    fn transport_config() -> quinn::TransportConfig {
        let mut config = quinn::TransportConfig::default();
        config.keep_alive_interval(Some(crate::connection::QUIC_KEEPALIVE_INTERVAL));
        config.max_idle_timeout(Some(
            crate::connection::QUIC_IDLE_TIMEOUT
                .try_into()
                .expect("timeout fits"),
        ));
        config
    }
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
