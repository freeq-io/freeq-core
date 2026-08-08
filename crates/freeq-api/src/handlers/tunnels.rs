//! GET /v1/tunnels handler.

use crate::{models::TunnelStats, ApiState, Result};
use axum::{extract::State, Json};

/// List all active tunnels with per-tunnel traffic statistics.
pub async fn list_tunnels(State(state): State<ApiState>) -> Result<Json<Vec<TunnelStats>>> {
    let snapshot = state.snapshot().await;
    if snapshot.tunnel.packets_ingested == 0 {
        return Ok(Json(Vec::new()));
    }

    Ok(Json(vec![TunnelStats {
        peer: snapshot
            .tunnel
            .interface_name
            .unwrap_or_else(|| "aggregate".into()),
        bytes_sent: snapshot.tunnel.encrypted_bytes,
        bytes_received: 0,
        latency_ms: None,
        packet_loss_pct: None,
    }]))
}
