//! GET /v1/tunnels handler.

use crate::{models::TunnelStats, ApiError, Result};
use axum::Json;

/// List all active tunnels with per-tunnel traffic statistics.
pub async fn list_tunnels() -> Result<Json<Vec<TunnelStats>>> {
    Err(ApiError::NotImplemented(
        "tunnel listing is not implemented yet".into(),
    ))
}
