//! POST /v1/algorithm — hot-swap the active crypto algorithm.

use axum::Json;
use crate::{models::AlgorithmSwitchRequest, Result};

pub async fn switch_algorithm(Json(_req): Json<AlgorithmSwitchRequest>) -> Result<()> {
    // TODO(v0.1): validate new algorithm, hot-swap without session interruption
    todo!("POST /v1/algorithm")
}
