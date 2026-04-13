//! POST /v1/algorithm — hot-swap the active crypto algorithm.

use crate::{models::AlgorithmSwitchRequest, ApiError, Result};
use axum::Json;

/// Hot-swap the active KEM or signature algorithm without interrupting sessions.
pub async fn switch_algorithm(Json(_req): Json<AlgorithmSwitchRequest>) -> Result<()> {
    Err(ApiError::NotImplemented(
        "algorithm switching is not implemented yet".into(),
    ))
}
