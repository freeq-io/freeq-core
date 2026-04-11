//! GET /v1/status handler.

use axum::Json;
use crate::{models::StatusResponse, Result};

pub async fn get_status() -> Result<Json<StatusResponse>> {
    // TODO(v0.1): read live state from shared daemon state
    todo!("GET /v1/status")
}
