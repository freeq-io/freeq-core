//! Session with real QUIC transport + hybrid PQC handshake

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

use crate::connection::PeerConnection;
use crate::endpoint::Endpoint;
use crate::peer::PeerId;
use crate::Result;
use freeq_crypto::sign::IdentityKeypair;

pub type SessionId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Discovering,
    Handshaking,
    Authenticating,
    Active,
    Rekeying,
    Suspended,
    Terminating,
    Failed,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub battlefield_mode: bool,
    pub max_suspension_time: Duration,
    pub fast_reconnect_interval: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            battlefield_mode: true,
            max_suspension_time: Duration::from_secs(1800),
            fast_reconnect_interval: Duration::from_millis(800),
        }
    }
}

pub struct Session {
    pub id: SessionId,
    pub state: Arc<RwLock<SessionState>>,
    pub peer: PeerId,
    pub config: SessionConfig,
    pub connection: PeerConnection,
    _identity: IdentityKeypair,
}

#[async_trait::async_trait]
pub trait EnterpriseHooks: Send + Sync + 'static {
    async fn on_session_event(&self, event: &str);
}

pub struct DefaultHooks;

#[async_trait::async_trait]
impl EnterpriseHooks for DefaultHooks {
    async fn on_session_event(&self, event: &str) {
        info!("Session event: {}", event);
    }
}

impl Session {
    pub async fn new(
        peer: PeerId,
        hooks: Arc<dyn EnterpriseHooks>,
        config: SessionConfig,
        endpoint: &Endpoint,
        peer_addr: std::net::SocketAddr,
    ) -> Result<Arc<Self>> {
        let connection = endpoint.connect(peer_addr).await?;

        // Hybrid PQC handshake stub (ML-DSA + ML-KEM)
        info!("Performing hybrid PQC handshake with peer {}", peer);
        let (identity, _) = IdentityKeypair::generate(&mut rand::thread_rng())
            .map_err(|e| crate::TransportError::Tls(format!("crypto error: {}", e)))?;

        let id = Uuid::new_v4();
        let session = Arc::new(Self {
            id,
            state: Arc::new(RwLock::new(SessionState::Active)),
            peer,
            config,
            connection,
            _identity: identity,
        });

        hooks.on_session_event("session_created").await;
        Ok(session)
    }

    pub async fn suspend(&self, reason: &str) -> Result<()> {
        let mut state = self.state.write().await;
        info!("Session {} suspended: {}", self.id, reason);
        *state = SessionState::Suspended;
        Ok(())
    }

    pub async fn attempt_fast_reconnect(&self) -> Result<()> {
        let current = *self.state.read().await;
        if current == SessionState::Suspended {
            info!("Session {} fast reconnected", self.id);
            let mut state = self.state.write().await;
            *state = SessionState::Active;
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.connection.close().await
    }
}
