//! API server startup.

use crate::Result;

/// The local REST API server.
pub struct ApiServer {
    addr: std::net::SocketAddr,
    state: crate::state::SharedApiState,
    auth_token: Option<String>,
}

impl ApiServer {
    /// Create a new API server bound to `addr`.
    pub fn new(
        addr: std::net::SocketAddr,
        state: crate::state::SharedApiState,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            addr,
            state,
            auth_token,
        }
    }

    /// Start serving requests.
    pub async fn serve(self) -> Result<()> {
        let router = crate::router::build_router(self.state, self.auth_token);
        let listener = tokio::net::TcpListener::bind(self.addr)
            .await
            .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

        tracing::info!("FreeQ API listening on {}", self.addr);

        axum::serve(listener, router)
            .await
            .map_err(|e| crate::ApiError::Internal(e.to_string()))
    }
}
