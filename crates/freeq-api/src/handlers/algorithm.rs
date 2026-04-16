//! GET/POST /v1/algorithm — read or hot-swap active crypto algorithms.

use crate::{models::AlgorithmSwitchRequest, ApiError, Result};
use axum::{extract::State, Json};

/// Return the node's current active algorithm set.
pub async fn get_algorithm(
    State(state): State<crate::state::SharedApiState>,
) -> Json<crate::models::AlgorithmResponse> {
    Json(state.algorithm_response())
}

/// Hot-swap the active KEM or signature algorithm without interrupting sessions.
pub async fn switch_algorithm(
    State(state): State<crate::state::SharedApiState>,
    Json(req): Json<AlgorithmSwitchRequest>,
) -> Result<Json<crate::models::AlgorithmResponse>> {
    req.validate()?;
    let current = state.algorithm_response();
    let requested_kem = req
        .kem
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.kem_algorithm);
    let requested_sign = req
        .sign
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.sign_algorithm);

    if requested_kem == current.kem_algorithm && requested_sign == current.sign_algorithm {
        return Ok(Json(current));
    }

    Err(ApiError::BadRequest(format!(
        "live algorithm switching is not supported yet; active suite remains kem={} sign={} bulk={}",
        current.kem_algorithm, current.sign_algorithm, current.bulk_algorithm
    )))
}
