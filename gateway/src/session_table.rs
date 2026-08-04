//! In-memory gateway session table.
//!
//! # Outbound-only invariant
//!
//! The FreeQ gateway **never initiates a connection to a leaf**. Sessions
//! appear in this table only after a leaf completes an authenticated inbound
//! handshake. The table is keyed by authenticated node identity (peer name),
//! not by public IP.
//!
//! If a destination leaf has no active inbound session, the forward path must
//! drop the packet and report `"remote leaf offline"` — never dial the leaf's
//! public endpoint.
//!
//! # Concurrency
//!
//! Uses [`tokio::sync::RwLock`] so the hot forward path can look up sessions
//! with shared reads. Inserts/removes take a write lock briefly.
//!
//! # Session generation
//!
//! Each session has a monotonic generation. Watchers must remove only their
//! own generation so a reconnect cannot be wiped by a stale close handler.

use freeq_transport::connection::PeerConnection;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use zeroize::Zeroize;

/// Authenticated node identity used as the session-table key.
///
/// Today this is the configured peer name established during the ML-DSA
/// handshake. It must not be a public IP or dialable transport endpoint.
pub type NodeId = String;

/// Monotonic session generation counter (process-local).
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

/// One active inbound leaf session held by the gateway.
pub struct ActiveSession {
    /// Authenticated node identity for this leaf.
    #[allow(dead_code)] // surfaced via SessionInfo / future forward diagnostics
    pub node_id: NodeId,
    /// Process-local generation used to avoid stale remove races.
    pub generation: u64,
    /// Live QUIC connection that the leaf opened to the gateway.
    pub connection: PeerConnection,
    /// Leaf→gateway hop bulk keys from the hybrid handshake (not E2E).
    ///
    /// Zeroized on drop. Never logged.
    pub outbound_key: [u8; 32],
    /// Gateway→leaf hop bulk keys from the hybrid handshake (not E2E).
    ///
    /// Zeroized on drop. Never logged.
    pub inbound_key: [u8; 32],
    /// When the authenticated session was established.
    pub established_at: Instant,
    /// Milliseconds since `established_at` of last observed activity.
    last_activity_ms: AtomicU64,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.outbound_key.zeroize();
        self.inbound_key.zeroize();
    }
}

impl ActiveSession {
    /// Build a session from an authenticated inbound connection.
    pub fn new(
        node_id: NodeId,
        connection: PeerConnection,
        outbound_key: [u8; 32],
        inbound_key: [u8; 32],
    ) -> Self {
        Self {
            node_id,
            generation: SESSION_GENERATION.fetch_add(1, Ordering::Relaxed),
            connection,
            outbound_key,
            inbound_key,
            established_at: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    /// Mark the session as recently active (lock-free).
    pub fn touch(&self) {
        let ms = self.established_at.elapsed().as_millis() as u64;
        self.last_activity_ms.store(ms, Ordering::Relaxed);
    }

    /// Age of last activity relative to establishment.
    pub fn last_seen_age(&self) -> std::time::Duration {
        let activity_ms = self.last_activity_ms.load(Ordering::Relaxed);
        let since_start = self.established_at.elapsed();
        since_start.saturating_sub(std::time::Duration::from_millis(activity_ms))
    }

    /// Whether the underlying QUIC connection is still open.
    pub fn is_alive(&self) -> bool {
        self.connection.is_alive()
    }
}

/// Compact session view for status/diagnostics (no keys, no sockets).
#[derive(Debug, Clone)]
#[allow(dead_code)] // reserved for richer /status session detail
pub struct SessionInfo {
    /// Authenticated node id.
    pub node_id: NodeId,
    /// Session generation.
    pub generation: u64,
    /// Seconds since session establishment.
    pub age_secs: u64,
    /// Seconds since last activity.
    pub idle_secs: u64,
    /// Whether QUIC reports the connection alive.
    pub alive: bool,
}

/// Thread-safe session table keyed by authenticated node identity.
#[derive(Clone, Default)]
pub struct SessionTable {
    inner: Arc<RwLock<HashMap<NodeId, Arc<ActiveSession>>>>,
}

impl SessionTable {
    /// Create an empty session table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the active session for `node_id`.
    ///
    /// Returns the previous session if one existed (caller may close it).
    pub async fn insert(
        &self,
        node_id: NodeId,
        session: ActiveSession,
    ) -> Option<Arc<ActiveSession>> {
        let session = Arc::new(session);
        self.inner.write().await.insert(node_id, session)
    }

    /// Remove the session for `node_id` if present (unconditional).
    #[allow(dead_code)] // tests + emergency admin path
    pub async fn remove(&self, node_id: &str) -> Option<Arc<ActiveSession>> {
        self.inner.write().await.remove(node_id)
    }

    /// Remove only if the stored generation matches (stale-watcher safe).
    pub async fn remove_if_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> Option<Arc<ActiveSession>> {
        let mut guard = self.inner.write().await;
        match guard.get(node_id) {
            Some(session) if session.generation == generation => guard.remove(node_id),
            _ => None,
        }
    }

    /// Look up an active session by authenticated node identity.
    ///
    /// Returns `None` when the remote leaf is offline (no inbound session).
    pub async fn get(&self, node_id: &str) -> Option<Arc<ActiveSession>> {
        self.inner.read().await.get(node_id).cloned()
    }

    /// Number of currently registered leaf sessions.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Whether the table has no active sessions.
    #[allow(dead_code)] // tests + status helpers
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    /// Snapshot of currently online node IDs (sorted for stable status).
    pub async fn online_nodes(&self) -> Vec<NodeId> {
        let mut nodes: Vec<NodeId> = self.inner.read().await.keys().cloned().collect();
        nodes.sort();
        nodes
    }

    /// Diagnostic view of all sessions (no secrets).
    #[allow(dead_code)] // reserved for richer /status session detail
    pub async fn session_infos(&self) -> Vec<SessionInfo> {
        let guard = self.inner.read().await;
        let mut infos: Vec<SessionInfo> = guard
            .values()
            .map(|session| SessionInfo {
                node_id: session.node_id.clone(),
                generation: session.generation,
                age_secs: session.established_at.elapsed().as_secs(),
                idle_secs: session.last_seen_age().as_secs(),
                alive: session.is_alive(),
            })
            .collect();
        infos.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        infos
    }

    /// Remove sessions whose QUIC connection is no longer alive.
    ///
    /// Returns the node IDs that were pruned.
    pub async fn reap_dead(&self) -> Vec<(NodeId, u64)> {
        let mut guard = self.inner.write().await;
        let dead: Vec<(NodeId, u64)> = guard
            .iter()
            .filter(|(_, session)| !session.is_alive())
            .map(|(id, session)| (id.clone(), session.generation))
            .collect();
        for (id, generation) in &dead {
            if let Some(session) = guard.get(id) {
                if session.generation == *generation {
                    guard.remove(id);
                }
            }
        }
        dead
    }
}

#[cfg(test)]
mod tests {
    use super::{ActiveSession, SessionTable};
    use freeq_transport::endpoint::Endpoint;
    use std::net::{Ipv4Addr, SocketAddr};

    async fn local_connection() -> freeq_transport::connection::PeerConnection {
        let endpoint = Endpoint::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let client = Endpoint::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind client");
        let server_addr = endpoint.local_addr().expect("server addr");
        let accept = tokio::spawn(async move { endpoint.accept().await });
        let connection = client.connect(server_addr).await.expect("connect");
        let _accepted = accept.await.expect("join").expect("accept");
        connection
    }

    #[tokio::test]
    async fn table_insert_get_remove_by_node_id() {
        let connection = local_connection().await;
        let table = SessionTable::new();
        assert!(table.is_empty().await);

        let session = ActiveSession::new("leaf-a".into(), connection, [1u8; 32], [2u8; 32]);
        table.insert("leaf-a".into(), session).await;
        assert_eq!(table.len().await, 1);
        assert!(table.get("leaf-a").await.is_some());
        assert!(table.get("leaf-b").await.is_none());

        table.remove("leaf-a").await;
        assert!(table.is_empty().await);
    }

    #[tokio::test]
    async fn remove_if_generation_ignores_stale_watcher() {
        let table = SessionTable::new();
        let first = ActiveSession::new(
            "leaf-a".into(),
            local_connection().await,
            [1u8; 32],
            [2u8; 32],
        );
        let gen1 = first.generation;
        table.insert("leaf-a".into(), first).await;

        let second = ActiveSession::new(
            "leaf-a".into(),
            local_connection().await,
            [3u8; 32],
            [4u8; 32],
        );
        let gen2 = second.generation;
        let _old = table.insert("leaf-a".into(), second).await;
        assert_ne!(gen1, gen2);

        // Stale watcher for gen1 must not remove gen2.
        assert!(table.remove_if_generation("leaf-a", gen1).await.is_none());
        assert!(table.get("leaf-a").await.is_some());
        assert_eq!(table.get("leaf-a").await.expect("present").generation, gen2);

        assert!(table.remove_if_generation("leaf-a", gen2).await.is_some());
        assert!(table.get("leaf-a").await.is_none());
    }

    #[tokio::test]
    async fn touch_is_lock_free_via_atomics() {
        let session = ActiveSession::new(
            "leaf-a".into(),
            local_connection().await,
            [1u8; 32],
            [2u8; 32],
        );
        session.touch();
        // Immediately after touch, idle age should be small.
        assert!(session.last_seen_age().as_secs() < 2);
    }
}
