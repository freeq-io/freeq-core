//! GET/POST /v1/algorithm — read or hot-swap active crypto algorithms.

use crate::{models::AlgorithmSwitchRequest, ApiError, Result};
use axum::{extract::State, Json};

/// Return the node's current active algorithm set.
pub async fn get_algorithm(
    State(state): State<crate::state::SharedApiState>,
) -> Json<crate::models::AlgorithmResponse> {
    Json(state.read().await.algorithm_response())
}

/// Hot-swap the active KEM or signature algorithm without interrupting sessions.
pub async fn switch_algorithm(Json(_req): Json<AlgorithmSwitchRequest>) -> Result<()> {
    Err(ApiError::NotImplemented(
        "algorithm switching is not implemented yet".into(),
    ))
}
