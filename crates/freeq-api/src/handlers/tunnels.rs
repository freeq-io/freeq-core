//! GET /v1/tunnels handler.

use axum::Json;
use crate::{models::TunnelStats, Result};

/// List all active tunnels with per-tunnel traffic statistics.
pub async fn list_tunnels() -> Result<Json<Vec<TunnelStats>>> {
    todo!("GET /v1/tunnels")
}
