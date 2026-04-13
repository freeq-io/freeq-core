//! GET /v1/status handler.

use crate::{models::StatusResponse, Result};
use axum::{extract::State, Json};

/// Return the node's current status, uptime, and active algorithm configuration.
pub async fn get_status(
    State(state): State<crate::state::SharedApiState>,
) -> Result<Json<StatusResponse>> {
    let state = state.read().await;
    Ok(Json(state.status_response()))
}
