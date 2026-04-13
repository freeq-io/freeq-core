//! GET /v1/status handler.

use crate::{models::StatusResponse, ApiError, Result};
use axum::Json;

/// Return the node's current status, uptime, and active algorithm configuration.
pub async fn get_status() -> Result<Json<StatusResponse>> {
    Err(ApiError::NotImplemented(
        "status reporting is not implemented yet".into(),
    ))
}
