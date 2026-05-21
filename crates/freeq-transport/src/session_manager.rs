//! SessionManager — creates real QUIC sessions with hybrid PQC handshake

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn};

use crate::endpoint::Endpoint;
use crate::peer::PeerId;
use crate::session::{EnterpriseHooks, Session, SessionConfig, SessionId, SessionState};

use crate::Result;

pub struct SessionManager {
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    hooks: Arc<dyn EnterpriseHooks>,
    config: SessionConfig,
    endpoint: Endpoint,
}

impl SessionManager {
    pub fn new(hooks: Arc<dyn EnterpriseHooks>, config: SessionConfig, endpoint: Endpoint) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            hooks,
            config,
            endpoint,
        }
    }

    pub async fn create_session(
        &self,
        peer: PeerId,
        peer_addr: std::net::SocketAddr,
    ) -> Result<Arc<Session>> {
        let session = Session::new(
            peer.clone(),
            self.hooks.clone(),
            self.config.clone(),
            &self.endpoint,
            peer_addr,
        )
        .await?;

        self.sessions
            .write()
            .await
            .insert(session.id, session.clone());

        if self.config.battlefield_mode {
            tokio::spawn(Self::resilience_task(session.clone()));
        }

        info!(session_id = %session.id, peer = %peer, "New session created with real QUIC + PQC handshake");
        Ok(session)
    }

    async fn resilience_task(session: Arc<Session>) {
        let mut interval = time::interval(session.config.fast_reconnect_interval);
        loop {
            interval.tick().await;
            let state = *session.state.read().await;
            if state == SessionState::Suspended {
                if let Err(e) = session.attempt_fast_reconnect().await {
                    warn!(session_id = %session.id, "Fast reconnect failed: {}", e);
                }
            }
        }
    }

    pub async fn get_session(&self, session_id: SessionId) -> Option<Arc<Session>> {
        self.sessions.read().await.get(&session_id).cloned()
    }
}
