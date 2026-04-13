//! GET /v1/tunnels handler.

use crate::{models::TunnelStats, Result};
use axum::{extract::State, Json};

/// List all active tunnels with per-tunnel traffic statistics.
pub async fn list_tunnels(
    State(state): State<crate::state::SharedApiState>,
) -> Result<Json<Vec<TunnelStats>>> {
    Ok(Json(state.tunnel_stats()))
}
