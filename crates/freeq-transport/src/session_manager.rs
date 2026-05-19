// crates/freeq-transport/src/session_manager.rs

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn};

use crate::session::{Session, SessionId, SessionConfig, EnterpriseHooks, SessionState, Platform};
use crate::peer::PeerId;

pub struct SessionManager {
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    hooks: Arc<dyn EnterpriseHooks>,
    config: SessionConfig,
}

impl SessionManager {
    pub fn new(hooks: Arc<dyn EnterpriseHooks>, config: SessionConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            hooks,
            config,
        }
    }

    pub async fn create_session(&self, peer: PeerId) -> crate::session::Result<Arc<Session>> {
        let session = Arc::new(Session::new(peer, self.hooks.clone(), self.config.clone()));
        
        session.transition_to(SessionState::Discovering, "New session created").await?;
        
        self.sessions.write().await.insert(session.id, session.clone());
        
        if self.config.battlefield_mode {
            tokio::spawn(Self::resilience_task(session.clone()));
        }
        
        info!(session_id = %session.id, peer = %peer, "New session created");
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

    pub async fn get_session_by_peer(&self, peer: &PeerId) -> Option<Arc<Session>> {
        self.sessions.read().await.values()
            .find(|s| s.peer == *peer)
            .cloned()
    }
}