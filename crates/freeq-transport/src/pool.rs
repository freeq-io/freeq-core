//! Connection pool — reuse live QUIC connections to known peers.

use crate::{connection::PeerConnection, endpoint::Endpoint, Result, TransportError};
use std::collections::HashMap;
use std::sync::Arc;

/// Manages live connections to all known peers.
///
/// On cache miss, opens a new QUIC connection and inserts it into the pool.
pub struct ConnectionPool {
    endpoint: Endpoint,
    max_size: usize,
    connections: HashMap<String, Arc<PeerConnection>>,
}

impl ConnectionPool {
    /// Create an empty connection pool backed by `endpoint`.
    pub fn new(endpoint: Endpoint) -> Self {
        Self::with_max_size(endpoint, 1024)
    }

    /// Create an empty connection pool with a fixed capacity.
    pub fn with_max_size(endpoint: Endpoint, max_size: usize) -> Self {
        Self {
            endpoint,
            max_size,
            connections: HashMap::new(),
        }
    }

    /// Get or create a connection to `peer_id`.
    pub async fn get_or_connect(
        &mut self,
        peer_id: &str,
        addr: std::net::SocketAddr,
    ) -> Result<Arc<PeerConnection>> {
        if let Some(connection) = self.connections.get(peer_id) {
            if connection.is_alive() {
                return Ok(connection.clone());
            }
        }

        self.connections
            .retain(|_, connection| connection.is_alive());
        if !self.connections.contains_key(peer_id) && self.connections.len() >= self.max_size {
            return Err(TransportError::PoolFull);
        }

        let connection = Arc::new(self.endpoint.connect(addr).await?);
        self.connections
            .insert(peer_id.to_string(), connection.clone());
        Ok(connection)
    }

    /// Remove a connection from the pool (e.g. after detecting it is dead).
    pub fn evict(&mut self, peer_id: &str) {
        self.connections.remove(peer_id);
    }

    /// Current number of pooled peer connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns `true` if there are no pooled peer connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionPool;
    use crate::endpoint::Endpoint;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    #[tokio::test]
    async fn pool_reuses_live_connection() {
        let server = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        let client_endpoint = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client");

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _conn = server.accept().await.expect("accept");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            })
        };

        let mut pool = ConnectionPool::with_max_size(client_endpoint.clone(), 4);
        let first = pool
            .get_or_connect("peer-a", server_addr)
            .await
            .expect("first connect");
        let second = pool
            .get_or_connect("peer-a", server_addr)
            .await
            .expect("reused connect");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(pool.len(), 1);

        server_task.await.expect("server task");
        client_endpoint.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn pool_enforces_capacity() {
        let client_endpoint = Endpoint::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client");
        let mut pool = ConnectionPool::with_max_size(client_endpoint.clone(), 0);

        let err = pool
            .get_or_connect(
                "peer-a",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            )
            .await
            .expect_err("capacity error");

        assert!(matches!(err, crate::TransportError::PoolFull));
        client_endpoint.close().await;
    }
}
