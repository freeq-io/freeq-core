//! API server startup.

use crate::Result;

/// The local REST API server.
pub struct ApiServer {
    addr: std::net::SocketAddr,
    state: crate::state::SharedApiState,
}

impl ApiServer {
    /// Create a new API server bound to `addr`.
    pub fn new(addr: std::net::SocketAddr, state: crate::state::SharedApiState) -> Self {
        Self { addr, state }
    }

    /// Start serving requests.
    pub async fn serve(self) -> Result<()> {
        let router = crate::router::build_router(self.state);
        let listener = tokio::net::TcpListener::bind(self.addr)
            .await
            .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

        tracing::info!("FreeQ API listening on {}", self.addr);

        axum::serve(listener, router)
            .await
            .map_err(|e| crate::ApiError::Internal(e.to_string()))
    }
}
